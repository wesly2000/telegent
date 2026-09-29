from decimal import Decimal
from pathlib import Path

from telegent import FramePoint, HttpRequest, HttpTransaction


def _transaction(status: int = 200) -> HttpTransaction:
    return HttpTransaction(
        capture_path=Path("capture.pcap"),
        sni="api.example.test",
        http_version="2",
        tcp_stream=3,
        http2_stream_id=1,
        request=HttpRequest("POST", "/v1/responses"),
        request_end=FramePoint(10, Decimal("1.000")),
        response_status=status,
        response_headers=FramePoint(20, Decimal("1.250")),
        first_response_data=FramePoint(20, Decimal("1.250")),
        first_streaming_token=FramePoint(24, Decimal("1.375")),
    )


def test_measurements_are_independent_and_allow_same_packet() -> None:
    transaction = _transaction()

    assert transaction.request_to_response_headers_ms() == 250.0
    assert transaction.request_to_first_response_data_ms() == 250.0
    assert transaction.response_headers_to_first_response_data_ms() == 0.0
    assert transaction.first_response_data_to_first_streaming_token_ms() == 125.0


def test_non_200_response_has_no_success_measurements() -> None:
    transaction = _transaction(status=429)

    assert transaction.request_to_response_headers_ms() is None
    assert transaction.request_to_first_response_data_ms() is None
    assert transaction.response_headers_to_first_response_data_ms() is None
    assert transaction.first_response_data_to_first_streaming_token_ms() is None
