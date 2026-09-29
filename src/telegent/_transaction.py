"""Internal transaction construction."""

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .models import FramePoint, HttpRequest, HttpTransaction


@dataclass
class TransactionBuilder:
    capture_path: Path
    sni: str | None
    http_version: Literal["1.1", "2"]
    tcp_stream: int
    http2_stream_id: int | None
    request: HttpRequest
    request_endpoint: tuple[str, str]
    request_end: FramePoint | None = None
    response_status: int | None = None
    response_headers: FramePoint | None = None
    first_response_data: FramePoint | None = None
    first_streaming_token: FramePoint | None = None

    def finish(self) -> HttpTransaction:
        """Create an immutable transaction and derive completeness diagnostics."""

        diagnostics = []
        if self.request_end is None:
            diagnostics.append("missing_request_end")
        if self.response_headers is None:
            diagnostics.append("missing_response_headers")
        elif self.response_status != 200:
            diagnostics.append(f"http_status_{self.response_status}")
        elif self.first_response_data is None:
            diagnostics.append("missing_response_data")
        elif self.http_version == "2" and self.first_streaming_token is None:
            diagnostics.append("missing_streaming_token")

        points = (
            self.request_end,
            self.response_headers,
            self.first_response_data,
            self.first_streaming_token,
        )
        timestamps = [point.timestamp_epoch for point in points if point is not None]
        if timestamps != sorted(timestamps):
            diagnostics.append("negative_timestamp_order")

        return HttpTransaction(
            capture_path=self.capture_path,
            sni=self.sni,
            http_version=self.http_version,
            tcp_stream=self.tcp_stream,
            http2_stream_id=self.http2_stream_id,
            request=self.request,
            request_end=self.request_end,
            response_status=self.response_status,
            response_headers=self.response_headers,
            first_response_data=self.first_response_data,
            diagnostics=tuple(dict.fromkeys(diagnostics)),
            first_streaming_token=self.first_streaming_token,
        )
