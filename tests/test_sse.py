from pathlib import Path

from telegent import TsharkAnalyzer
from telegent._sse import SseParser


class FakeRunner:
    def __init__(self, *results: list[dict[str, str]]) -> None:
        self.results = list(results)

    def fields(self, *args: object, **kwargs: object) -> list[dict[str, str]]:
        return self.results.pop(0)

    def iter_fields(self, *args: object, **kwargs: object) -> object:
        return iter(self.results.pop(0))


def test_sse_parser_preserves_raw_bytes_and_ignores_comment_blocks() -> None:
    parser = SseParser()
    first = b": keepalive\r\n\r\nevent: response.output_text.delta\r\n"
    second = b'data: {"type":"response.output_text.delta",\r\n'
    third = b'data: "delta":"\xe4\xbd\xa0"}\r\n\r\n'

    assert parser.feed(first) == []
    assert parser.feed(second) == []
    events = parser.feed(third)

    assert len(events) == 1
    assert events[0].data == (
        b'{"type":"response.output_text.delta",\n"delta":"\xe4\xbd\xa0"}'
    )
    assert events[0].event_type == "response.output_text.delta"
    assert len(events[0].raw) == len(first.split(b"\r\n\r\n", 1)[1] + second + third)
    assert parser.is_clean


def test_sse_parser_accepts_bare_carriage_return_delimiters() -> None:
    parser = SseParser()

    events = parser.feed(
        b'data: {"type":"response.output_text.delta"}\r\r'
    )
    events.extend(parser.finish())

    assert len(events) == 1
    assert parser.is_clean


def test_sse_parser_handles_a_fragmented_utf8_bom() -> None:
    parser = SseParser()

    assert parser.feed(b"\xef") == []
    assert parser.feed(b"\xbb") == []
    events = parser.feed(
        b'\xbfdata: {"type":"response.output_text.delta"}\n\n'
    )

    assert len(events) == 1
    assert events[0].raw.startswith(b"data:")


def test_http2_application_completion_does_not_require_end_stream(
    tmp_path: Path,
) -> None:
    delta = b'data: {"type":"response.output_text.delta","delta":"Hi"}\n\n'
    completed = b'data: {"type":"response.completed"}\n\n'
    common = [
        _row(
            frame_number="10",
            timestamp="1.0",
            tcp_stream="3",
            address="client",
            port="50000",
            **{
                "http2.streamid": "1",
                "http2.type": "1",
                "http2.flags": "0x05",
                "http2.headers.method": "POST",
                "http2.headers.path": "/v1/responses",
            },
        ),
        _row(
            frame_number="20",
            timestamp="2.0",
            tcp_stream="3",
            address="server",
            port="443",
            **{
                "http2.streamid": "1",
                "http2.type": "1",
                "http2.flags": "0x04",
                "http2.headers.status": "200",
                "http2.headers.content_type": "text/event-stream",
            },
        ),
    ]
    data = [
        _row(
            frame_number="21",
            timestamp="2.1",
            tcp_stream="3",
            address="server",
            port="443",
            **{
                "@http2.stream": _http2_data_frame(1, delta + completed).hex(),
                "http2.data.data": (delta + completed + delta).hex(),
            },
        )
    ]
    pcap, keylog = _files(tmp_path)
    analyzer = TsharkAnalyzer(  # type: ignore[arg-type]
        _runner=FakeRunner(common, [], data)
    )

    measurements = analyzer.analyze_sse_capture(pcap, keylog)

    assert len(measurements) == 1
    assert measurements[0].event_size_bytes == len(delta)
    assert measurements[0].event_type == "response.output_text.delta"


def test_http2_clean_end_fallback_and_padding(tmp_path: Path) -> None:
    delta = b'data: {"type":"response.output_text.delta"}\n\n'
    common = [
        _row(
            frame_number="10",
            timestamp="1.0",
            tcp_stream="3",
            address="client",
            port="50000",
            **{
                "http2.streamid": "1",
                "http2.type": "1",
                "http2.flags": "0x05",
                "http2.headers.method": "POST",
                "http2.headers.path": "/responses",
            },
        ),
        _row(
            frame_number="20",
            timestamp="2.0",
            tcp_stream="3",
            address="server",
            port="443",
            **{
                "http2.streamid": "1",
                "http2.type": "1",
                "http2.flags": "0x04",
                "http2.headers.status": "200",
                "http2.headers.content_type": "text/event-stream",
            },
        ),
        _row(
            frame_number="21",
            timestamp="2.1",
            tcp_stream="3",
            address="server",
            port="443",
            **{
                "http2.streamid": "1",
                "http2.type": "0",
                "http2.flags": "0x09",
            },
        ),
    ]
    padded_payload = bytes((3,)) + delta + b"\0\0\0"
    data = [
        _row(
            frame_number="21",
            timestamp="2.1",
            tcp_stream="3",
            address="server",
            port="443",
            **{
                "@http2.stream": _http2_data_frame(
                    1, padded_payload, flags=0x09
                ).hex()
            },
        )
    ]
    pcap, keylog = _files(tmp_path)
    analyzer = TsharkAnalyzer(  # type: ignore[arg-type]
        _runner=FakeRunner(common, [], data)
    )

    measurements = analyzer.analyze_sse_capture(pcap, keylog)

    assert len(measurements) == 1
    assert measurements[0].event_size_bytes == len(delta)


def test_http2_incomplete_response_discards_staged_deltas(tmp_path: Path) -> None:
    delta = b'data: {"type":"response.output_text.delta"}\n\n'
    common = [
        _row(
            frame_number="10",
            timestamp="1.0",
            tcp_stream="3",
            address="client",
            port="50000",
            **{
                "http2.streamid": "1",
                "http2.type": "1",
                "http2.flags": "0x05",
                "http2.headers.method": "POST",
                "http2.headers.path": "/responses",
            },
        ),
        _row(
            frame_number="20",
            timestamp="2.0",
            tcp_stream="3",
            address="server",
            port="443",
            **{
                "http2.streamid": "1",
                "http2.type": "1",
                "http2.flags": "0x04",
                "http2.headers.status": "200",
                "http2.headers.content_type": "text/event-stream",
            },
        ),
    ]
    data = [
        _row(
            frame_number="21",
            timestamp="2.1",
            tcp_stream="3",
            address="server",
            port="443",
            **{"@http2.stream": _http2_data_frame(1, delta).hex()},
        )
    ]
    pcap, keylog = _files(tmp_path)
    analyzer = TsharkAnalyzer(  # type: ignore[arg-type]
        _runner=FakeRunner(common, [], data)
    )

    assert analyzer.analyze_sse_capture(pcap, keylog) == []


def test_http1_uses_complete_dechunked_body(tmp_path: Path) -> None:
    delta = b'data: {"type":"response.output_text.delta"}\r\n\r\n'
    completed = b'data: {"type":"response.completed"}\r\n\r\n'
    common = [
        _row(
            frame_number="12",
            timestamp="1.2",
            tcp_stream="5",
            address="client",
            port="50000",
            **{
                "http.request.method": "POST",
                "http.request.uri": "/v1/responses",
            },
        )
    ]
    headers = [
        _row(
            frame_number="10",
            timestamp="1.0",
            tcp_stream="5",
            address="client",
            port="50000",
            **{
                "http.request.method": "POST",
                "http.request.uri": "/v1/responses",
            },
        ),
        _row(
            frame_number="20",
            timestamp="2.0",
            tcp_stream="5",
            address="server",
            port="443",
            **{
                "http.response.code": "200",
                "http.request_in": "10",
                "http.content_type": "text/event-stream; charset=utf-8",
            },
        ),
    ]
    body = [
        _row(
            frame_number="30",
            timestamp="3.0",
            tcp_stream="5",
            address="server",
            port="443",
            **{
                "http.response.code": "200",
                "http.file_data": (delta + completed).hex(),
                "http.chunk_size": f"{len(delta)},{len(completed)},0",
            },
        )
    ]
    pcap, keylog = _files(tmp_path)
    analyzer = TsharkAnalyzer(  # type: ignore[arg-type]
        _runner=FakeRunner(common, headers, body)
    )

    measurements = analyzer.analyze_sse_capture(pcap, keylog)

    assert len(measurements) == 1
    assert measurements[0].http_version == "1.1"
    assert measurements[0].event_size_bytes == len(delta)


def _row(
    *,
    frame_number: str,
    timestamp: str,
    tcp_stream: str,
    address: str,
    port: str,
    **values: str,
) -> dict[str, str]:
    row = {
        "frame.number": frame_number,
        "frame.time_epoch": timestamp,
        "tcp.stream": tcp_stream,
        "ip.src": address,
        "ipv6.src": "",
        "tcp.srcport": port,
    }
    row.update(values)
    return row


def _http2_data_frame(stream_id: int, payload: bytes, flags: int = 0) -> bytes:
    return (
        len(payload).to_bytes(3, "big")
        + bytes((0, flags))
        + stream_id.to_bytes(4, "big")
        + payload
    )


def _files(tmp_path: Path) -> tuple[Path, Path]:
    pcap = tmp_path / "capture.pcap"
    keylog = tmp_path / "sslkeys.key"
    pcap.touch()
    keylog.touch()
    return pcap, keylog
