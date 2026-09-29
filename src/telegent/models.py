"""Public data models for Telegent measurements."""

from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Literal


@dataclass(frozen=True)
class HttpRequest:
    """HTTP request attributes used by the LLM request classifier."""

    method: str
    path: str


@dataclass(frozen=True)
class FramePoint:
    """A timestamped endpoint in a packet capture."""

    frame_number: int
    timestamp_epoch: Decimal


@dataclass(frozen=True)
class HttpTransaction:
    """A classified LLM HTTP transaction and its observable timing endpoints."""

    capture_path: Path
    sni: str | None
    http_version: Literal["1.1", "2"]
    tcp_stream: int
    http2_stream_id: int | None
    request: HttpRequest
    request_end: FramePoint | None
    response_status: int | None
    response_headers: FramePoint | None
    first_response_data: FramePoint | None
    diagnostics: tuple[str, ...] = ()
    first_streaming_token: FramePoint | None = None

    def request_to_response_headers_ms(self) -> float | None:
        """Return milliseconds from request completion to HTTP 200 headers."""

        return self._successful_elapsed_ms(self.request_end, self.response_headers)

    def request_to_first_response_data_ms(self) -> float | None:
        """Return milliseconds from request completion to first response data."""

        return self._successful_elapsed_ms(self.request_end, self.first_response_data)

    def response_headers_to_first_response_data_ms(self) -> float | None:
        """Return milliseconds from HTTP 200 headers to first response data."""

        return self._successful_elapsed_ms(
            self.response_headers,
            self.first_response_data,
        )

    def first_response_data_to_first_streaming_token_ms(self) -> float | None:
        """Return milliseconds from first response data to the first token event."""

        return self._successful_elapsed_ms(
            self.first_response_data,
            self.first_streaming_token,
        )

    def _successful_elapsed_ms(
        self,
        start: FramePoint | None,
        end: FramePoint | None,
    ) -> float | None:
        if self.response_status != 200 or start is None or end is None:
            return None
        duration = end.timestamp_epoch - start.timestamp_epoch
        if duration < 0:
            return None
        return float(duration * Decimal(1000))
