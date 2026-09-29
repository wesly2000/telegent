from pathlib import Path

import pytest

from telegent import HttpRequest, TelegentError, TsharkAnalyzer


class FakeRunner:
    def __init__(
        self,
        common_rows: list[dict[str, str]],
        http1_rows: list[dict[str, str]],
        http2_data_rows: list[dict[str, str]] | None = None,
    ):
        self._results = [common_rows, http1_rows]
        if http2_data_rows is not None:
            self._results.append(http2_data_rows)

    def fields(self, *args: object, **kwargs: object) -> list[dict[str, str]]:
        return self._results.pop(0)

    def iter_fields(self, *args: object, **kwargs: object) -> object:
        return iter(self._results.pop(0) if self._results else [])


def row(**values: str) -> dict[str, str]:
    defaults = {
        "frame.number": "",
        "frame.time_epoch": "",
        "tcp.stream": "",
        "ip.src": "",
        "ipv6.src": "",
        "tcp.srcport": "",
        "tls.handshake.extensions_server_name": "",
        "http2.streamid": "",
        "http2.type": "",
        "http2.length": "",
        "http2.flags": "",
        "http2.data.data": "",
        "http2.headers.method": "",
        "http2.headers.path": "",
        "http2.headers.status": "",
        "http.request.method": "",
        "http.request.uri": "",
        "http.response.code": "",
        "http.request_in": "",
        "http.response_in": "",
        "http.file_data": "",
    }
    defaults.update(values)
    return defaults


def test_http2_correlation_and_sni(tmp_path: Path) -> None:
    common = [
        row(
            **{
                "frame.number": "1",
                "frame.time_epoch": "1.0",
                "tcp.stream": "3",
                "ip.src": "client",
                "tcp.srcport": "50000",
                "tls.handshake.extensions_server_name": "api.example.test",
            }
        ),
        row(
            **{
                "frame.number": "10",
                "frame.time_epoch": "2.0",
                "tcp.stream": "3",
                "ip.src": "client",
                "tcp.srcport": "50000",
                "http2.streamid": "0,1",
                "http2.type": "8,1",
                "http2.flags": "0x00,0x04",
                "http2.headers.method": "POST",
                "http2.headers.path": "/v1/responses",
            }
        ),
        row(
            **{
                "frame.number": "12",
                "frame.time_epoch": "2.1",
                "tcp.stream": "3",
                "ip.src": "client",
                "tcp.srcport": "50000",
                "http2.streamid": "1",
                "http2.type": "0",
                "http2.flags": "0x01",
            }
        ),
        row(
            **{
                "frame.number": "20",
                "frame.time_epoch": "2.6",
                "tcp.stream": "3",
                "ip.src": "server",
                "tcp.srcport": "443",
                "http2.streamid": "1,1",
                "http2.type": "1,0",
                "http2.flags": "0x04,0x00",
                "http2.headers.status": "200",
            }
        ),
    ]
    token_event = b'data: {"type":"response.output_text.delta"}\n\n'
    http2_data = [
        row(
            **{
                "frame.number": "25",
                "frame.time_epoch": "2.7",
                "tcp.stream": "3",
                "ip.src": "server",
                "tcp.srcport": "443",
                "http2.streamid": "1",
                "http2.type": "0",
                "http2.length": str(len(token_event)),
                "http2.flags": "0x00",
                "http2.data.data": token_event.hex(),
            }
        )
    ]
    pcap, keylog = _files(tmp_path)
    analyzer = TsharkAnalyzer(  # type: ignore[arg-type]
        _runner=FakeRunner(common, [], http2_data)
    )

    transactions = analyzer.analyze_capture(pcap, keylog)

    assert len(transactions) == 1
    transaction = transactions[0]
    assert transaction.sni == "api.example.test"
    assert transaction.http2_stream_id == 1
    assert transaction.request_to_response_headers_ms() == 500.0
    assert transaction.response_headers_to_first_response_data_ms() == 0.0
    assert transaction.first_streaming_token is not None
    assert transaction.first_streaming_token.frame_number == 25
    assert transaction.first_response_data_to_first_streaming_token_ms() == 100.0
    assert transaction.diagnostics == ()


def test_http2_reassembles_split_sse_event_and_ignores_reassembled_duplicate(
    tmp_path: Path,
) -> None:
    common = [
        row(
            **{
                "frame.number": "10",
                "frame.time_epoch": "2.0",
                "tcp.stream": "3",
                "ip.src": "client",
                "tcp.srcport": "50000",
                "http2.streamid": "1",
                "http2.type": "1",
                "http2.flags": "0x05",
                "http2.headers.method": "POST",
                "http2.headers.path": "/responses",
            }
        ),
        row(
            **{
                "frame.number": "20",
                "frame.time_epoch": "2.5",
                "tcp.stream": "3",
                "ip.src": "server",
                "tcp.srcport": "443",
                "http2.streamid": "1,1",
                "http2.type": "1,0",
                "http2.length": "20,7",
                "http2.flags": "0x04,0x00",
                "http2.headers.status": "200",
            }
        ),
    ]
    first_fragment = b'data: {"type":"response.output_'
    second_fragment = b'text.delta","delta":"Hi"}\n\n'
    trailing_event = b'data: {"type":"response.completed"}\n\n'
    full_body = first_fragment + second_fragment + trailing_event
    http2_data = [
        row(
            **{
                "frame.number": "25",
                "frame.time_epoch": "2.6",
                "tcp.stream": "3",
                "ip.src": "server",
                "tcp.srcport": "443",
                "http2.streamid": "1",
                "http2.type": "0",
                "http2.length": str(len(first_fragment)),
                "http2.flags": "0x00",
                "http2.data.data": first_fragment.hex(),
            }
        ),
        row(
            **{
                "frame.number": "26",
                "frame.time_epoch": "2.7",
                "tcp.stream": "3",
                "ip.src": "server",
                "tcp.srcport": "443",
                "http2.streamid": "1,1,1",
                "http2.type": "0,0,0",
                "http2.length": f"{len(second_fragment)},{len(trailing_event)},0",
                "http2.flags": "0x00,0x00,0x01",
                "http2.data.data": ",".join(
                    (
                        second_fragment.hex(),
                        trailing_event.hex(),
                        full_body.hex(),
                    )
                ),
            }
        ),
    ]
    pcap, keylog = _files(tmp_path)
    analyzer = TsharkAnalyzer(  # type: ignore[arg-type]
        _runner=FakeRunner(common, [], http2_data)
    )

    transaction = analyzer.analyze_capture(pcap, keylog)[0]

    assert transaction.first_streaming_token is not None
    assert transaction.first_streaming_token.frame_number == 26
    assert transaction.first_response_data_to_first_streaming_token_ms() == 200.0


def test_http1_uses_reassembled_request_end_and_status_packet(tmp_path: Path) -> None:
    common = [
        row(
            **{
                "frame.number": "34",
                "frame.time_epoch": "10.2",
                "tcp.stream": "5",
                "ip.src": "client",
                "tcp.srcport": "50000",
                "http.request.method": "POST",
                "http.request.uri": "/v1/responses",
            }
        )
    ]
    http1 = [
        row(
            **{
                "frame.number": "30",
                "frame.time_epoch": "10.0",
                "tcp.stream": "5",
                "ip.src": "client",
                "tcp.srcport": "50000",
                "http.request.method": "POST",
                "http.request.uri": "/v1/responses",
            }
        ),
        row(
            **{
                "frame.number": "40",
                "frame.time_epoch": "11.4",
                "tcp.stream": "5",
                "ip.src": "server",
                "tcp.srcport": "443",
                "http.response.code": "200",
                "http.request_in": "30",
            }
        ),
        row(
            **{
                "frame.number": "41",
                "frame.time_epoch": "11.5",
                "tcp.stream": "5",
                "ip.src": "server",
                "tcp.srcport": "443",
                "http.file_data": "data",
            }
        ),
    ]
    pcap, keylog = _files(tmp_path)
    analyzer = TsharkAnalyzer(_runner=FakeRunner(common, http1))  # type: ignore[arg-type]

    transactions = analyzer.analyze_capture(pcap, keylog)

    assert len(transactions) == 1
    transaction = transactions[0]
    assert transaction.http_version == "1.1"
    assert transaction.request_end is not None
    assert transaction.request_end.frame_number == 34
    assert transaction.response_headers is not None
    assert transaction.response_headers.frame_number == 40
    assert transaction.first_response_data is not None
    assert transaction.first_response_data.frame_number == 41
    assert transaction.request_to_response_headers_ms() == 1200.0
    assert transaction.request_to_first_response_data_ms() == 1300.0


def test_injected_classifier_controls_selection(tmp_path: Path) -> None:
    common = [
        row(
            **{
                "frame.number": "10",
                "frame.time_epoch": "2.0",
                "tcp.stream": "3",
                "ip.src": "client",
                "tcp.srcport": "50000",
                "http2.streamid": "1",
                "http2.type": "1",
                "http2.flags": "0x05",
                "http2.headers.method": "POST",
                "http2.headers.path": "/custom-inference",
            }
        )
    ]
    pcap, keylog = _files(tmp_path)

    def classifier(request: HttpRequest) -> bool:
        return request == HttpRequest("POST", "/custom-inference")

    analyzer = TsharkAnalyzer(  # type: ignore[arg-type]
        classifier,
        _runner=FakeRunner(common, []),
    )

    transactions = analyzer.analyze_capture(pcap, keylog)

    assert len(transactions) == 1


def test_non_200_response_is_reported_without_success_latency(tmp_path: Path) -> None:
    common = [
        row(
            **{
                "frame.number": "10",
                "frame.time_epoch": "2.0",
                "tcp.stream": "3",
                "ip.src": "client",
                "tcp.srcport": "50000",
                "http2.streamid": "1",
                "http2.type": "1",
                "http2.flags": "0x05",
                "http2.headers.method": "POST",
                "http2.headers.path": "/responses",
            }
        ),
        row(
            **{
                "frame.number": "20",
                "frame.time_epoch": "2.5",
                "tcp.stream": "3",
                "ip.src": "server",
                "tcp.srcport": "443",
                "http2.streamid": "1",
                "http2.type": "1",
                "http2.flags": "0x05",
                "http2.headers.status": "429",
            }
        ),
    ]
    pcap, keylog = _files(tmp_path)
    analyzer = TsharkAnalyzer(_runner=FakeRunner(common, []))  # type: ignore[arg-type]

    transactions = analyzer.analyze_capture(pcap, keylog)

    assert len(transactions) == 1
    transaction = transactions[0]
    assert transaction.sni is None
    assert transaction.response_status == 429
    assert transaction.request_to_response_headers_ms() is None
    assert transaction.diagnostics == ("http_status_429",)


def test_missing_files_are_rejected_before_tshark_runs(tmp_path: Path) -> None:
    analyzer = TsharkAnalyzer(_runner=FakeRunner([], []))  # type: ignore[arg-type]

    with pytest.raises(TelegentError, match="capture does not exist"):
        analyzer.analyze_capture(tmp_path / "missing.pcap", tmp_path / "missing.log")


def _files(tmp_path: Path) -> tuple[Path, Path]:
    pcap = tmp_path / "capture.pcap"
    keylog = tmp_path / "keys.log"
    pcap.touch()
    keylog.touch()
    return pcap, keylog
