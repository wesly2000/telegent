"""Resolve capture configuration from CLI, the environment, and dotenv files."""

import math
import os
import shutil
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import dotenv_values

from ..errors import CaptureError

_BUNDLED_SEQUENCE_SCRIPT = (
    Path(__file__).resolve().parents[1] / "scripts" / "codex-sequence.sh"
)


@dataclass(frozen=True)
class CaptureSettings:
    """Fully resolved settings used for one or more traffic captures."""

    capture_root: Path
    codex_config_root: Path
    sequence_script: Path
    codex_binary: Path
    capture_interface: str
    capture_filter: str
    tail_seconds: float
    capture_start_timeout_seconds: float
    tshark_binary: Path
    environment: Mapping[str, str] = field(repr=False)
    request_interval_seconds: float = 0
    env_file: Path | None = None

    @classmethod
    def resolve(
        cls,
        overrides: Mapping[str, object] | None = None,
        *,
        environ: Mapping[str, str] | None = None,
        cwd: Path | None = None,
    ) -> "CaptureSettings":
        """Resolve settings with CLI > process environment > dotenv > defaults."""

        overrides = overrides or {}
        process_environment = dict(os.environ if environ is None else environ)
        working_directory = (cwd or Path.cwd()).resolve()
        env_file = _env_file(overrides.get("env_file"), working_directory)
        dotenv_environment = _read_dotenv(
            env_file, explicit=overrides.get("env_file") is not None
        )
        merged_environment = {**dotenv_environment, **process_environment}

        def value(name: str, default: str) -> str:
            override = overrides.get(name)
            if override is not None:
                return str(override)
            return merged_environment.get(_ENV_NAMES[name], default)

        search_path = merged_environment.get("PATH")
        local_codex = working_directory / "codex-rs" / "target" / "debug" / "codex"
        default_codex = str(local_codex)
        if not local_codex.is_file():
            default_codex = shutil.which("codex", path=search_path) or "codex"
        default_tshark = shutil.which("tshark", path=search_path) or "tshark"
        return cls(
            capture_root=_path(value("capture_root", "capture/chat"), working_directory),
            codex_config_root=_path(
                value("codex_config_root", "codex-third-party"), working_directory
            ),
            sequence_script=_path(
                value("sequence_script", str(_BUNDLED_SEQUENCE_SCRIPT)),
                working_directory,
            ),
            codex_binary=_path(value("codex_binary", default_codex), working_directory),
            capture_interface=value("capture_interface", "eth0"),
            capture_filter=value("capture_filter", "port 443"),
            tail_seconds=_duration(value("tail_seconds", "10"), "tail seconds"),
            request_interval_seconds=_duration(
                value("request_interval_seconds", "0"),
                "request interval seconds",
            ),
            capture_start_timeout_seconds=_duration(
                value("capture_start_timeout_seconds", "5"),
                "capture start timeout seconds",
            ),
            tshark_binary=_path(
                value("tshark_binary", default_tshark), working_directory
            ),
            environment=merged_environment,
            env_file=env_file if env_file.exists() else None,
        )


_ENV_NAMES = {
    "capture_root": "TELEGENT_CAPTURE_ROOT",
    "codex_config_root": "TELEGENT_CODEX_CONFIG_ROOT",
    "sequence_script": "TELEGENT_SEQUENCE_SCRIPT",
    "codex_binary": "TELEGENT_CODEX_BINARY",
    "capture_interface": "TELEGENT_CAPTURE_INTERFACE",
    "capture_filter": "TELEGENT_CAPTURE_FILTER",
    "tail_seconds": "TELEGENT_TAIL_SECONDS",
    "request_interval_seconds": "TELEGENT_REQUEST_INTERVAL_SECONDS",
    "capture_start_timeout_seconds": "TELEGENT_CAPTURE_START_TIMEOUT_SECONDS",
    "tshark_binary": "TELEGENT_TSHARK_BINARY",
}


def _env_file(value: object | None, cwd: Path) -> Path:
    if value is None:
        return cwd / ".env"
    return _path(str(value), cwd)


def _read_dotenv(path: Path, *, explicit: bool) -> dict[str, str]:
    if not path.exists():
        if explicit:
            raise CaptureError(f"environment file does not exist: {path}")
        return {}
    try:
        return {key: value for key, value in dotenv_values(path).items() if value is not None}
    except OSError as error:
        raise CaptureError(f"could not read environment file {path}: {error}") from error


def _path(value: str, cwd: Path) -> Path:
    path = Path(value).expanduser()
    return (cwd / path).resolve() if not path.is_absolute() else path.resolve()


def _duration(value: str, label: str) -> float:
    try:
        duration = float(value)
    except ValueError as error:
        raise CaptureError(f"{label} must be a number, got {value!r}") from error
    if not math.isfinite(duration):
        raise CaptureError(f"{label} must be finite")
    if duration < 0:
        raise CaptureError(f"{label} must not be negative")
    return duration
