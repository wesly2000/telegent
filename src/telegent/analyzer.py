"""Public tshark-backed capture analyzer."""

from collections.abc import Callable
from decimal import Decimal
from pathlib import Path

from ._capture import (
    COMMON_FIELDS,
    HTTP1_BODY_FIELDS,
    HTTP1_FIELDS,
    HTTP2_DATA_FIELDS,
    TsharkRunner,
    collect_sni,
    packets,
)
from ._http1 import build_http1_transactions
from ._http2 import build_http2_transactions, find_first_streaming_tokens
from ._sse import extract_http1_delta_sizes, extract_http2_delta_sizes
from .classifier import is_llm_request, is_streaming_token_event
from .errors import TelegentError
from .models import HttpRequest, HttpTransaction, SseEventSize

RequestClassifier = Callable[[HttpRequest], bool]
StreamingEventClassifier = Callable[[bytes], bool]


class TsharkAnalyzer:
    """Extract LLM HTTP transactions from a TLS-decryptable packet capture."""

    def __init__(
        self,
        request_classifier: RequestClassifier = is_llm_request,
        *,
        streaming_event_classifier: StreamingEventClassifier = is_streaming_token_event,
        tshark_executable: str | None = None,
        _runner: TsharkRunner | None = None,
    ) -> None:
        self._request_classifier = request_classifier
        self._streaming_event_classifier = streaming_event_classifier
        self._runner = _runner or TsharkRunner(tshark_executable)

    def analyze_capture(
        self,
        pcap_path: Path | str,
        keylog_path: Path | str,
    ) -> list[HttpTransaction]:
        """Analyze every classified LLM request in one packet capture."""

        pcap = Path(pcap_path)
        keylog = Path(keylog_path)
        _validate_inputs(pcap, keylog)

        common_rows = self._runner.fields(
            pcap,
            keylog,
            COMMON_FIELDS,
            "tls.handshake.extensions_server_name || http2 || http.request.method",
        )
        # This keeps response metadata on the status-line packet instead of the
        # final chunked-body packet while still allowing split header reassembly.
        http1_rows = self._runner.fields(
            pcap,
            keylog,
            HTTP1_FIELDS,
            "http.request.method || http.response.code || http.file_data",
            ("http.desegment_headers:TRUE", "http.desegment_body:FALSE"),
        )

        common_packets = list(packets(common_rows))
        http1_packets = list(packets(http1_rows))
        sni_by_stream = collect_sni(common_packets)
        http2_builders = build_http2_transactions(
            pcap,
            common_packets,
            sni_by_stream,
            self._request_classifier,
        )
        if http2_builders:
            http2_data_rows = self._runner.iter_fields(
                pcap,
                keylog,
                HTTP2_DATA_FIELDS,
                "http2.data.data && http2.length > 0",
            )
            find_first_streaming_tokens(
                packets(http2_data_rows),
                http2_builders,
                self._streaming_event_classifier,
            )
        builders = list(http2_builders)
        builders.extend(
            build_http1_transactions(
                pcap,
                common_packets,
                http1_packets,
                sni_by_stream,
                self._request_classifier,
            )
        )
        transactions = [builder.finish() for builder in builders]
        return sorted(transactions, key=_transaction_order)

    def analyze_sse_capture(
        self,
        pcap_path: Path | str,
        keylog_path: Path | str,
    ) -> list[SseEventSize]:
        """Measure delta-event sizes in complete LLM SSE responses."""

        pcap = Path(pcap_path)
        keylog = Path(keylog_path)
        _validate_inputs(pcap, keylog)

        common_rows = self._runner.fields(
            pcap,
            keylog,
            COMMON_FIELDS,
            "tls.handshake.extensions_server_name || http2 || http.request.method",
        )
        http1_header_rows = self._runner.fields(
            pcap,
            keylog,
            HTTP1_FIELDS,
            "http.request.method || http.response.code || http.file_data",
            ("http.desegment_headers:TRUE", "http.desegment_body:FALSE"),
        )
        common_packets = list(packets(common_rows))
        http1_header_packets = list(packets(http1_header_rows))
        sni_by_stream = collect_sni(common_packets)

        http2_builders = build_http2_transactions(
            pcap,
            common_packets,
            sni_by_stream,
            self._request_classifier,
        )
        measurements: list[SseEventSize] = []
        if http2_builders:
            http2_rows = self._runner.iter_fields(
                pcap,
                keylog,
                HTTP2_DATA_FIELDS,
                "http2.type == 0 && http2.length > 0",
            )
            measurements.extend(
                extract_http2_delta_sizes(
                    packets(http2_rows),
                    common_packets,
                    http2_builders,
                    self._streaming_event_classifier,
                )
            )

        http1_builders = build_http1_transactions(
            pcap,
            common_packets,
            http1_header_packets,
            sni_by_stream,
            self._request_classifier,
        )
        if http1_builders:
            http1_body_rows = self._runner.iter_fields(
                pcap,
                keylog,
                HTTP1_BODY_FIELDS,
                "http.response.code || http.file_data",
            )
            measurements.extend(
                extract_http1_delta_sizes(
                    list(packets(http1_body_rows)),
                    http1_builders,
                    self._streaming_event_classifier,
                )
            )
        return sorted(measurements, key=_sse_measurement_order)


def _validate_inputs(pcap: Path, keylog: Path) -> None:
    if not pcap.is_file():
        raise TelegentError(f"capture does not exist: {pcap}")
    if not keylog.is_file():
        raise TelegentError(f"TLS key log does not exist: {keylog}")


def _transaction_order(transaction: HttpTransaction) -> tuple[Decimal, int, int]:
    timestamp = (
        transaction.request_end.timestamp_epoch
        if transaction.request_end
        else Decimal("Infinity")
    )
    return timestamp, transaction.tcp_stream, transaction.http2_stream_id or 0


def _sse_measurement_order(measurement: SseEventSize) -> tuple[int, int, int]:
    return (
        measurement.tcp_stream,
        measurement.http2_stream_id or 0,
        measurement.delta_index,
    )
