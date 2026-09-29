"""HTTP/2 transaction correlation."""

import re
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path

from ._capture import (
    Http2Frame,
    Packet,
    http2_data_fragments,
    http2_frames,
    split_values,
)
from ._transaction import TransactionBuilder
from .models import HttpRequest

RequestClassifier = Callable[[HttpRequest], bool]
StreamingEventClassifier = Callable[[bytes], bool]

_SSE_EVENT_END = re.compile(rb"\r?\n\r?\n")


def build_http2_transactions(
    pcap: Path,
    packets: Sequence[Packet],
    sni_by_stream: dict[int, str],
    request_classifier: RequestClassifier,
) -> list[TransactionBuilder]:
    """Correlate classified HTTP/2 requests with response frames."""

    builders = _find_requests(pcap, packets, sni_by_stream, request_classifier)
    _find_response_points(packets, builders)
    return list(builders.values())


def find_first_streaming_tokens(
    packets: Iterable[Packet],
    builders: Sequence[TransactionBuilder],
    event_classifier: StreamingEventClassifier,
) -> None:
    """Attach the first matching complete SSE event to HTTP/2 transactions."""

    builders_by_stream = {
        (builder.tcp_stream, builder.http2_stream_id): builder
        for builder in builders
        if builder.http2_stream_id is not None
    }
    buffers: dict[tuple[int, int], bytearray] = {}
    for packet in packets:
        for stream_id, payload in http2_data_fragments(packet):
            key = (packet.tcp_stream, stream_id)
            builder = builders_by_stream.get(key)
            if (
                builder is None
                or builder.response_status != 200
                or builder.response_headers is None
                or builder.first_streaming_token is not None
                or packet.endpoint == builder.request_endpoint
            ):
                continue
            buffer = buffers.setdefault(key, bytearray())
            buffer.extend(payload)
            while match := _SSE_EVENT_END.search(buffer):
                event = bytes(buffer[: match.start()])
                del buffer[: match.end()]
                if event_classifier(event):
                    builder.first_streaming_token = packet.frame
                    buffers.pop(key, None)
                    break


def _find_requests(
    pcap: Path,
    packets: Sequence[Packet],
    sni_by_stream: dict[int, str],
    request_classifier: RequestClassifier,
) -> dict[tuple[int, int], TransactionBuilder]:
    builders = {}
    for packet in packets:
        method = packet.values.get("http2.headers.method", "")
        path = packet.values.get("http2.headers.path", "")
        if not method or not path:
            continue
        request = HttpRequest(method.split(",", 1)[0], path.split(",", 1)[0])
        if not request_classifier(request):
            continue
        stream_ids = {
            frame.stream_id
            for frame in http2_frames(packet)
            if frame.frame_type == 1 and frame.stream_id != 0
        }
        if len(stream_ids) != 1:
            continue
        stream_id = stream_ids.pop()
        builders[(packet.tcp_stream, stream_id)] = TransactionBuilder(
            capture_path=pcap,
            sni=sni_by_stream.get(packet.tcp_stream),
            http_version="2",
            tcp_stream=packet.tcp_stream,
            http2_stream_id=stream_id,
            request=request,
            request_endpoint=packet.endpoint,
        )
    return builders


def _find_response_points(
    packets: Sequence[Packet],
    builders: dict[tuple[int, int], TransactionBuilder],
) -> None:
    for packet in packets:
        frames = http2_frames(packet)
        _apply_stream_frames(packet, frames, builders)
        _apply_response_headers(packet, frames, builders)


def _apply_stream_frames(
    packet: Packet,
    frames: Sequence[Http2Frame],
    builders: dict[tuple[int, int], TransactionBuilder],
) -> None:
    for frame in frames:
        builder = builders.get((packet.tcp_stream, frame.stream_id))
        if builder is None:
            continue
        from_client = packet.endpoint == builder.request_endpoint
        if from_client and frame.frame_type in (0, 1) and frame.flags & 0x01:
            builder.request_end = packet.frame
        if (
            not from_client
            and frame.frame_type == 0
            and builder.response_headers is not None
            and builder.first_response_data is None
        ):
            builder.first_response_data = packet.frame


def _apply_response_headers(
    packet: Packet,
    frames: Sequence[Http2Frame],
    builders: dict[tuple[int, int], TransactionBuilder],
) -> None:
    statuses = split_values(packet.values.get("http2.headers.status", ""))
    if not statuses:
        return
    header_streams = {
        frame.stream_id
        for frame in frames
        if frame.frame_type == 1 and frame.stream_id != 0
    }
    if len(header_streams) != 1:
        return
    builder = builders.get((packet.tcp_stream, next(iter(header_streams))))
    if builder is None or packet.endpoint == builder.request_endpoint:
        return
    final_statuses = [int(status) for status in statuses if int(status) >= 200]
    if not final_statuses or builder.response_headers is not None:
        return
    builder.response_status = final_statuses[0]
    builder.response_headers = packet.frame
    if any(
        frame.frame_type == 0 and frame.stream_id == builder.http2_stream_id
        for frame in frames
    ):
        builder.first_response_data = packet.frame
