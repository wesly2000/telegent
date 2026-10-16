"""Telegent exceptions."""

from pathlib import Path


class TelegentError(RuntimeError):
    """Base class for user-facing Telegent failures."""


class ConfigurationError(TelegentError):
    """Raised when Telegent or agent configuration cannot be resolved."""


class CaptureError(TelegentError):
    """Raised when traffic collection fails, optionally with a preserved log."""

    def __init__(
        self,
        message: str,
        failure_log_path: Path | None = None,
        *,
        interrupted: bool = False,
    ) -> None:
        super().__init__(message)
        self.failure_log_path = failure_log_path
        self.interrupted = interrupted
