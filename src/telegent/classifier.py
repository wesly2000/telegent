"""Rules for identifying model inference requests."""

from urllib.parse import urlsplit

from .models import HttpRequest

_LLM_PATH_SUFFIXES = ("/responses", "/chat/completions")


def is_llm_request(request: HttpRequest) -> bool:
    """Return whether a request matches the default empirical LLM endpoint rule."""

    if request.method.upper() != "POST":
        return False

    path = urlsplit(request.path).path.rstrip("/")
    return path.endswith(_LLM_PATH_SUFFIXES)
