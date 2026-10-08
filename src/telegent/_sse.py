"""SSE parsing and complete-response delta-size extraction."""

import json
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass

from ._capture import Packet, http2_data_fragments, http2_frames, split_values
from ._transaction import TransactionBuilder
from .models import SseEventSize

StreamingEventClassifier = Callable[[bytes], bool]


@dataclass(frozen=True)
class SseEvent:
    """One dispatched SSE event and its original encoded block."""

    raw: bytes
    data: bytes
    event_type: str | None


class SseParser:
    """Incrementally parse an SSE byte stream while preserving raw event bytes."""

    def __init__(self) -> None:
        self._buffer = bytearray()
        self._raw = bytearray()
        self._data_lines: list[bytes] = []
        self._at_start = True

    def feed(self, fragment: bytes) -> list[SseEvent]:
        self._buffer.extend(fragment)
        if self._at_start:
            if len(self._buffer) < 3:
                return []
            self._consume_bom()

        return self._drain(allow_terminal_cr=False)

    def finish(self) -> list[SseEvent]:
        """Finish parsing line endings that end with a bare carriage return."""

        if self._at_start:
            self._consume_bom()
        return self._drain(allow_terminal_cr=True)

    def _consume_bom(self) -> None:
        if self._buffer.startswith(b"\xef\xbb\xbf"):
            del self._buffer[:3]
        self._at_start = False

    def _drain(self, *, allow_terminal_cr: bool) -> list[SseEvent]:
        events = []
        while (line := self._next_line(allow_terminal_cr)) is not None:
            value, ending = line
            self._raw.extend(value)
            self._raw.extend(ending)
            if value:
                self._apply_field(value)
                continue

            if self._data_lines:
                data = b"\n".join(self._data_lines)
                if data:
                    events.append(
                        SseEvent(bytes(self._raw), data, _json_event_type(data))
                    )
            self._raw.clear()
            self._data_lines.clear()
        return events

    @property
    def is_clean(self) -> bool:
        """Return whether no unterminated SSE block remains."""

        return not self._buffer and not self._raw and not self._data_lines

    def _next_line(self, allow_terminal_cr: bool) -> tuple[bytes, bytes] | None:
        for index, byte in enumerate(self._buffer):
            if byte == 0x0A:
                value = bytes(self._buffer[:index])
                del self._buffer[: index + 1]
                return value, b"\n"
            if byte != 0x0D:
                continue
            if index + 1 == len(self._buffer):
                if not allow_terminal_cr:
                    return None
                value = bytes(self._buffer[:index])
                del self._buffer[: index + 1]
                return value, b"\r"
            ending_length = 2 if self._buffer[index + 1] == 0x0A else 1
            value = bytes(self._buffer[:index])
            ending = bytes(self._buffer[index : index + ending_length])
            del self._buffer[: index + ending_length]
            return value, ending
        return None

    def _apply_field(self, line: bytes) -> None:
        if line.startswith(b":"):
            return
        field, separator, value = line.partition(b":")
        if separator and value.startswith(b" "):
            value = value[1:]
        if field == b"data":
            self._data_lines.append(value)


def extract_http2_delta_sizes(
    packets: Iterable[Packet],
    end_packets: Sequence[Packet],
    builders: Sequence[TransactionBuilder],
    event_classifier: StreamingEventClassifier,
) -> list[SseEventSize]:
    """Return delta sizes from complete HTTP/2 SSE responses."""

    eligible = {
        (builder.tcp_stream, builder.http2_stream_id): builder
        for builder in builders
        if builder.http2_stream_id is not None and _eligible(builder)
    }
    parsers = {key: SseParser() for key in eligible}
    staged: dict[tuple[int, int | None], list[SseEvent]] = {
        key: [] for key in eligible
    }
    application_complete: set[tuple[int, int | None]] = set()

    for packet in packets:
        for stream_id, payload in http2_data_fragments(packet):
            key = (packet.tcp_stream, stream_id)
            builder = eligible.get(key)
            if builder is None or packet.endpoint == builder.request_endpoint:
                continue
            for event in parsers[key].feed(payload):
                if _terminal(event):
                    application_complete.add(key)
                if event_classifier(event.raw):
                    staged[key].append(event)

    for key, parser in parsers.items():
        for event in parser.finish():
            if _terminal(event):
                application_complete.add(key)
            if event_classifier(event.raw):
                staged[key].append(event)

    clean_ends = _http2_clean_ends(end_packets, eligible)
    result = []
    for key, builder in eligible.items():
        if key not in application_complete and not (
            key in clean_ends and parsers[key].is_clean
        ):
            continue
        result.extend(_measurements(builder, staged[key]))
    return result


def extract_http1_delta_sizes(
    packets: Sequence[Packet],
    builders: Sequence[TransactionBuilder],
    event_classifier: StreamingEventClassifier,
) -> list[SseEventSize]:
    """Return delta sizes from fully reassembled HTTP/1.1 SSE responses."""

    result = []
    for builder in builders:
        if not _eligible(builder):
            continue
        packet = _http1_body_packet(builder, builders, packets)
        if packet is None:
            continue
        bodies = _decode_hex_values(packet.values.get("http.file_data", ""))
        if not bodies:
            continue
        body = max(bodies, key=len)
        parser = SseParser()
        events = parser.feed(body)
        events.extend(parser.finish())
        application_complete = any(_terminal(event) for event in events)
        clean_http_end = _http1_clean_end(packet, len(body))
        if not application_complete and not (clean_http_end and parser.is_clean):
            continue
        deltas = [event for event in events if event_classifier(event.raw)]
        result.extend(_measurements(builder, deltas))
    return result


def _eligible(builder: TransactionBuilder) -> bool:
    content_type = (builder.response_content_type or "").lower()
    content_encoding = (builder.response_content_encoding or "identity").lower()
    return (
        builder.response_status == 200
        and content_type.split(";", 1)[0].strip() == "text/event-stream"
        and content_encoding in ("", "identity")
    )


def _terminal(event: SseEvent) -> bool:
    return event.data.strip() == b"[DONE]" or event.event_type == "response.completed"


def _json_event_type(data: bytes) -> str | None:
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    event_type = value.get("type") if isinstance(value, dict) else None
    return event_type if isinstance(event_type, str) else None


def _measurements(
    builder: TransactionBuilder, events: Sequence[SseEvent]
) -> list[SseEventSize]:
    return [
        SseEventSize(
            capture_path=builder.capture_path,
            sni=builder.sni,
            http_version=builder.http_version,
            tcp_stream=builder.tcp_stream,
            http2_stream_id=builder.http2_stream_id,
            request=builder.request,
            response_status=builder.response_status or 200,
            delta_index=index,
            event_type=event.event_type,
            event_size_bytes=len(event.raw),
        )
        for index, event in enumerate(events)
    ]


def _http2_clean_ends(
    packets: Sequence[Packet],
    builders: dict[tuple[int, int | None], TransactionBuilder],
) -> set[tuple[int, int | None]]:
    result = set()
    for packet in packets:
        for frame in http2_frames(packet):
            key = (packet.tcp_stream, frame.stream_id)
            builder = builders.get(key)
            if (
                builder is not None
                and packet.endpoint != builder.request_endpoint
                and frame.frame_type in (0, 1)
                and frame.flags & 0x01
            ):
                result.add(key)
    return result


def _http1_body_packet(
    builder: TransactionBuilder,
    builders: Sequence[TransactionBuilder],
    packets: Sequence[Packet],
) -> Packet | None:
    if builder.response_headers is None:
        return None
    next_response = min(
        (
            other.response_headers.timestamp_epoch
            for other in builders
            if other is not builder
            and other.tcp_stream == builder.tcp_stream
            and other.response_headers is not None
            and other.response_headers.timestamp_epoch
            > builder.response_headers.timestamp_epoch
        ),
        default=None,
    )
    for packet in packets:
        if packet.tcp_stream != builder.tcp_stream:
            continue
        if packet.endpoint == builder.request_endpoint:
            continue
        if packet.frame.timestamp_epoch < builder.response_headers.timestamp_epoch:
            continue
        if next_response is not None and packet.frame.timestamp_epoch >= next_response:
            break
        if packet.values.get("http.file_data", ""):
            return packet
    return None


def _http1_clean_end(packet: Packet, body_size: int) -> bool:
    chunk_sizes = split_values(packet.values.get("http.chunk_size", ""))
    if chunk_sizes:
        try:
            return int(chunk_sizes[-1]) == 0
        except ValueError:
            return False
    content_length = packet.values.get("http.content_length", "").split(",", 1)[0]
    if content_length:
        try:
            return int(content_length) == body_size
        except ValueError:
            return False
    # A response without chunked framing or Content-Length is complete when
    # the server closes its side of the connection after the reassembled body.
    return packet.values.get("tcp.flags.fin", "") in ("1", "True", "true")


def _decode_hex_values(value: str) -> list[bytes]:
    result = []
    for item in split_values(value):
        try:
            result.append(bytes.fromhex(item))
        except ValueError:
            continue
    return result
