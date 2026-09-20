"""Send one bounded, credential-safe Responses API request."""

import json
import re
from http.client import HTTPException
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .config import ProbeTarget

_MAX_RESPONSE_BYTES = 256 * 1024  # 256 KiB as the max size of response data (the real response should be far more smaller)
_DIAGNOSTIC_ATOM = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}\Z")
_RESPONSE_STATUSES = {"completed", "incomplete", "failed", "in_progress", "queued", "cancelled"}

# If the direct HTTP request encounters 3xx redirect, mark it as a failure.
class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(
        self,
        request: Request,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> None:
        return None


def probe_endpoint(target: ProbeTarget, timeout_seconds: float) -> tuple[bool, str]:
    """Return success and a safe diagnostic; never expose the API key or body."""

    body = json.dumps(
        {
            "model": target.model_id,
            "input": "Hi",
            "stream": False,
            "store": False,
            "max_output_tokens": 4096,
        }
    ).encode("utf-8")
    request = Request(
        target.url,
        data=body,
        headers={
            "Authorization": f"Bearer {target.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )
    try:
        with build_opener(_NoRedirect()).open(request, timeout=timeout_seconds) as response:
            parsed, read_error = _read_response(response)
    except HTTPError as error:
        try:
            parsed, read_error = _read_response(error)
        finally:
            error.close()
        detail = _response_details(parsed, target.api_key) if parsed is not None else read_error
        return False, f"HTTP {error.code}" + (f"; {detail}" if detail else "")
    except (OSError, URLError, HTTPException) as error:
        return False, f"connection error ({type(error).__name__})"
    if read_error is not None:
        return False, read_error
    assert parsed is not None
    if parsed.get("status") == "completed":
        return True, "completed"
    return False, _response_details(parsed, target.api_key)


def _read_response(response: Any) -> tuple[dict | None, str | None]:
    try:
        # The extra byte detects an oversized body without reading it all.
        payload = response.read(_MAX_RESPONSE_BYTES + 1)
    except (OSError, HTTPException):
        return None, "could not read response body"
    if len(payload) > _MAX_RESPONSE_BYTES:
        return None, "response exceeded size limit"
    try:
        parsed = json.loads(payload)
    except (ValueError, UnicodeDecodeError):
        return None, "response was not JSON"
    if not isinstance(parsed, dict):
        return None, "response JSON was not an object"
    return parsed, None


def _response_details(response: dict, api_key: str) -> str:
    status = response.get("status")
    safe_status = (
        status if isinstance(status, str) and status in _RESPONSE_STATUSES else "missing_or_unknown"
    )
    parts = [f"status={safe_status}"]
    incomplete = response.get("incomplete_details")
    if isinstance(incomplete, dict):
        reason = _safe_atom(incomplete.get("reason"), api_key)
        if reason:
            parts.append(f"incomplete_reason={reason}")
    error = response.get("error")
    if isinstance(error, dict):
        for field in ("code", "type"):
            value = _safe_atom(error.get(field), api_key)
            if value:
                parts.append(f"error_{field}={value}")
    usage = response.get("usage")
    if isinstance(usage, dict):
        output_tokens = _safe_count(usage.get("output_tokens"))
        if output_tokens is not None:
            parts.append(f"output_tokens={output_tokens}")
        output_details = usage.get("output_tokens_details")
        if isinstance(output_details, dict):
            reasoning_tokens = _safe_count(output_details.get("reasoning_tokens"))
            if reasoning_tokens is not None:
                parts.append(f"reasoning_tokens={reasoning_tokens}")
    return "; ".join(parts)


def _safe_atom(value: object, api_key: str) -> str | None:
    if not isinstance(value, str) or not _DIAGNOSTIC_ATOM.fullmatch(value):
        return None
    return None if api_key in value else value


def _safe_count(value: object) -> int | None:
    if type(value) is int and 0 <= value <= 1_000_000_000:
        return value
    return None
