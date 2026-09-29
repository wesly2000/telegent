"""Rules for identifying model inference requests and streaming token events."""

import json
from urllib.parse import urlsplit

from .models import HttpRequest

_LLM_PATH_SUFFIXES = ("/responses", "/chat/completions")


def is_llm_request(request: HttpRequest) -> bool:
    """Return whether a request matches the default empirical LLM endpoint rule."""

    if request.method.upper() != "POST":
        return False

    path = urlsplit(request.path).path.rstrip("/")
    return path.endswith(_LLM_PATH_SUFFIXES)


def is_streaming_token_event(event: bytes) -> bool:
    """Return whether a complete SSE event carries a token delta."""

    try:
        text = event.decode("utf-8")
    except UnicodeDecodeError:
        return False

    data_lines = []
    for line in text.splitlines():
        if not line.startswith("data:"):
            continue
        value = line[5:]
        if value.startswith(" "):
            value = value[1:]
        data_lines.append(value)
    if not data_lines:
        return False

    try:
        payload = json.loads("\n".join(data_lines))
    except (json.JSONDecodeError, TypeError):
        return False
    event_type = payload.get("type") if isinstance(payload, dict) else None
    return isinstance(event_type, str) and "delta" in event_type
