"""HTTP/1.1 transaction correlation."""

from collections import defaultdict
from collections.abc import Callable, Sequence
from decimal import Decimal
from pathlib import Path

from ._capture import Packet, optional_int
from ._transaction import TransactionBuilder
from .models import HttpRequest

RequestClassifier = Callable[[HttpRequest], bool]


def find_first_streaming_tokens(*_: object) -> None:
    """Reserve the HTTP/1.1 token-event extraction interface."""

    # TODO: Implement HTTP/1.1 response-body SSE extraction and correlation.
    raise NotImplementedError("HTTP/1.1 streaming token extraction is not implemented")


def build_http1_transactions(
    pcap: Path,
    reassembled_packets: Sequence[Packet],
    header_packets: Sequence[Packet],
    sni_by_stream: dict[int, str],
    request_classifier: RequestClassifier,
) -> list[TransactionBuilder]:
    """Correlate classified HTTP/1.1 requests with response packets."""

    request_ends = _collect_request_ends(reassembled_packets, request_classifier)
    builders, builders_by_start = _find_request_starts(
        pcap,
        header_packets,
        request_ends,
        sni_by_stream,
        request_classifier,
    )
    _find_response_headers(header_packets, builders, builders_by_start)
    _find_response_data(header_packets, builders)
    return builders


def _collect_request_ends(
    packets: Sequence[Packet],
    request_classifier: RequestClassifier,
) -> dict[int, list[Packet]]:
    request_ends = defaultdict(list)
    for packet in packets:
        method = packet.values.get("http.request.method", "")
        path = packet.values.get("http.request.uri", "")
        if method and path and request_classifier(HttpRequest(method, path)):
            request_ends[packet.tcp_stream].append(packet)
    return request_ends


def _find_request_starts(
    pcap: Path,
    packets: Sequence[Packet],
    request_ends: dict[int, list[Packet]],
    sni_by_stream: dict[int, str],
    request_classifier: RequestClassifier,
) -> tuple[list[TransactionBuilder], dict[int, TransactionBuilder]]:
    builders = []
    builders_by_start = {}
    starts_seen = defaultdict(int)
    for packet in packets:
        method = packet.values.get("http.request.method", "")
        path = packet.values.get("http.request.uri", "")
        request = HttpRequest(method, path)
        if not method or not path or not request_classifier(request):
            continue
        index = starts_seen[packet.tcp_stream]
        starts_seen[packet.tcp_stream] += 1
        ends = request_ends.get(packet.tcp_stream, ())
        request_end = ends[index].frame if index < len(ends) else None
        builder = TransactionBuilder(
            capture_path=pcap,
            sni=sni_by_stream.get(packet.tcp_stream),
            http_version="1.1",
            tcp_stream=packet.tcp_stream,
            http2_stream_id=None,
            request=request,
            request_endpoint=packet.endpoint,
            request_end=request_end,
        )
        builders.append(builder)
        builders_by_start[packet.frame.frame_number] = builder
    return builders, builders_by_start


def _find_response_headers(
    packets: Sequence[Packet],
    builders: Sequence[TransactionBuilder],
    builders_by_start: dict[int, TransactionBuilder],
) -> None:
    by_stream = defaultdict(list)
    for builder in builders:
        by_stream[builder.tcp_stream].append(builder)

    for packet in packets:
        status_text = packet.values.get("http.response.code", "")
        if not status_text:
            continue
        request_in = optional_int(packet.values.get("http.request_in", ""))
        builder = builders_by_start.get(request_in or -1)
        if builder is None:
            builder = next(
                (
                    candidate
                    for candidate in by_stream.get(packet.tcp_stream, ())
                    if candidate.response_headers is None
                    and candidate.request_endpoint != packet.endpoint
                ),
                None,
            )
        if builder is None:
            continue
        builder.response_status = int(status_text.split(",", 1)[0])
        builder.response_headers = packet.frame
        builder.response_content_type = (
            packet.values.get("http.content_type", "").split(",", 1)[0] or None
        )
        builder.response_content_encoding = (
            packet.values.get("http.content_encoding", "").split(",", 1)[0]
            or None
        )
        if packet.values.get("http.file_data", ""):
            builder.first_response_data = packet.frame


def _find_response_data(
    packets: Sequence[Packet],
    builders: Sequence[TransactionBuilder],
) -> None:
    for builder in builders:
        if builder.response_headers is None or builder.first_response_data is not None:
            continue
        next_response_time = _next_response_time(builder, builders)
        for packet in packets:
            if packet.tcp_stream != builder.tcp_stream:
                continue
            if packet.endpoint == builder.request_endpoint:
                continue
            if packet.frame.timestamp_epoch < builder.response_headers.timestamp_epoch:
                continue
            if (
                next_response_time
                and packet.frame.timestamp_epoch >= next_response_time
            ):
                break
            if packet.values.get("http.file_data", ""):
                builder.first_response_data = packet.frame
                break


def _next_response_time(
    builder: TransactionBuilder,
    builders: Sequence[TransactionBuilder],
) -> Decimal | None:
    return min(
        (
            other.response_headers.timestamp_epoch
            for other in builders
            if other.tcp_stream == builder.tcp_stream
            and other.response_headers is not None
            and builder.response_headers is not None
            and other.response_headers.timestamp_epoch
            > builder.response_headers.timestamp_epoch
        ),
        default=None,
    )
