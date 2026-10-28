"""Resolve shared agent, capture, and probe settings."""

import math
import os
import shutil
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, cast

from dotenv import dotenv_values

from ..errors import ConfigurationError

AgentKind = Literal["codex", "opencode"]
_SCRIPTS_DIRECTORY = Path(__file__).resolve().parents[1] / "scripts"


@dataclass(frozen=True, kw_only=True)
class AgentSettings:
    """Settings shared by capture and probe agent invocations."""

    agent: AgentKind
    agent_config_root: Path
    agent_binary: Path
    working_directory: Path
    environment: Mapping[str, str] = field(repr=False)
    env_file: Path | None = None


@dataclass(frozen=True, kw_only=True)
class CaptureSettings(AgentSettings):
    """Fully resolved settings used for one or more traffic captures."""

    capture_root: Path
    sequence_script: Path
    capture_interface: str
    capture_filter: str
    tail_seconds: float
    capture_start_timeout_seconds: float
    tshark_binary: Path
    request_interval_seconds: float = 0

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
        common = _resolve_agent_settings(overrides, environ=environ, cwd=cwd)

        def value(name: str, default: str) -> str:
            override = overrides.get(name)
            if override is not None:
                return str(override)
            return common.environment.get(_CAPTURE_ENV_NAMES[name], default)

        default_tshark = (
            shutil.which("tshark", path=common.environment.get("PATH")) or "tshark"
        )
        default_script = _SCRIPTS_DIRECTORY / f"{common.agent}-sequence.sh"
        return cls(
            agent=common.agent,
            agent_config_root=common.agent_config_root,
            agent_binary=common.agent_binary,
            working_directory=common.working_directory,
            environment=common.environment,
            env_file=common.env_file,
            capture_root=_path(
                value("capture_root", "capture/chat"), common.working_directory
            ),
            sequence_script=_path(
                value("sequence_script", str(default_script)),
                common.working_directory,
            ),
            capture_interface=value("capture_interface", "eth0"),
            capture_filter=value("capture_filter", "port 443"),
            tail_seconds=_duration(
                value("tail_seconds", "10"), "tail seconds"
            ),
            request_interval_seconds=_duration(
                value("request_interval_seconds", "0"),
                "request interval seconds",
            ),
            capture_start_timeout_seconds=_duration(
                value("capture_start_timeout_seconds", "5"),
                "capture start timeout seconds",
            ),
            tshark_binary=_path(
                value("tshark_binary", default_tshark), common.working_directory
            ),
        )


@dataclass(frozen=True, kw_only=True)
class ProbeSettings(AgentSettings):
    """Settings shared by every provider in one agent test command."""

    timeout_seconds: float

    @classmethod
    def resolve(
        cls,
        overrides: Mapping[str, object] | None = None,
        *,
        environ: Mapping[str, str] | None = None,
        cwd: Path | None = None,
    ) -> "ProbeSettings":
        """Resolve settings with CLI > process environment > dotenv > defaults."""

        overrides = overrides or {}
        common = _resolve_agent_settings(overrides, environ=environ, cwd=cwd)
        timeout = overrides.get("timeout_seconds")
        if timeout is None:
            timeout = common.environment.get("TELEGENT_TEST_TIMEOUT_SECONDS", "60")
        try:
            timeout_seconds = float(timeout)
        except (TypeError, ValueError) as error:
            raise ConfigurationError("test timeout must be a number") from error
        if not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 3600:
            raise ConfigurationError(
                "test timeout must be greater than 0 and at most 3600 seconds"
            )
        return cls(
            agent=common.agent,
            agent_config_root=common.agent_config_root,
            agent_binary=common.agent_binary,
            working_directory=common.working_directory,
            environment=common.environment,
            env_file=common.env_file,
            timeout_seconds=timeout_seconds,
        )


_CAPTURE_ENV_NAMES = {
    "capture_root": "TELEGENT_CAPTURE_ROOT",
    "sequence_script": "TELEGENT_SEQUENCE_SCRIPT",
    "capture_interface": "TELEGENT_CAPTURE_INTERFACE",
    "capture_filter": "TELEGENT_CAPTURE_FILTER",
    "tail_seconds": "TELEGENT_TAIL_SECONDS",
    "request_interval_seconds": "TELEGENT_REQUEST_INTERVAL_SECONDS",
    "capture_start_timeout_seconds": "TELEGENT_CAPTURE_START_TIMEOUT_SECONDS",
    "tshark_binary": "TELEGENT_TSHARK_BINARY",
}


def _resolve_agent_settings(
    overrides: Mapping[str, object],
    *,
    environ: Mapping[str, str] | None,
    cwd: Path | None,
) -> AgentSettings:
    working_directory = (cwd or Path.cwd()).resolve()
    environment, env_file = _resolve_environment(
        overrides.get("env_file"),
        environ=environ,
        cwd=working_directory,
    )
    agent_value = overrides.get("agent", "codex")
    if agent_value not in ("codex", "opencode"):
        raise ConfigurationError("agent must be either 'codex' or 'opencode'")
    agent = cast(AgentKind, agent_value)

    config_root = overrides.get("agent_config_root")
    if config_root is None:
        config_root = environment.get("TELEGENT_AGENT_CONFIG_ROOT")
    binary = overrides.get("agent_binary")
    if binary is None:
        binary = environment.get("TELEGENT_AGENT_BINARY")
    if binary is None:
        binary = shutil.which(agent, path=environment.get("PATH")) or agent
        local_codex = working_directory / "codex-rs" / "target" / "debug" / "codex"
        if agent == "codex" and local_codex.is_file():
            binary = local_codex
    return AgentSettings(
        agent=agent,
        agent_config_root=_path(str(config_root), working_directory),
        agent_binary=_path(str(binary), working_directory),
        working_directory=working_directory,
        environment=environment,
        env_file=env_file,
    )


def _resolve_environment(
    env_file_value: object | None,
    *,
    environ: Mapping[str, str] | None,
    cwd: Path,
) -> tuple[dict[str, str], Path | None]:
    explicit = env_file_value is not None
    env_file = _path(str(env_file_value), cwd) if explicit else cwd / ".env"
    if not env_file.is_file():
        if explicit:
            raise ConfigurationError(f"environment file does not exist: {env_file}")
        dotenv_environment: dict[str, str] = {}
        loaded_env_file = None
    else:
        try:
            dotenv_environment = {
                key: value
                for key, value in dotenv_values(env_file).items()
                if value is not None
            }
        except OSError as error:
            raise ConfigurationError(
                f"could not read environment file {env_file}: {error}"
            ) from error
        loaded_env_file = env_file
    environment = {
        **dotenv_environment,
        **dict(os.environ if environ is None else environ),
    }
    return environment, loaded_env_file


def _path(value: str, cwd: Path) -> Path:
    path = Path(value).expanduser()
    return (cwd / path).resolve() if not path.is_absolute() else path.resolve()


def _duration(value: str, label: str) -> float:
    try:
        duration = float(value)
    except ValueError as error:
        raise ConfigurationError(
            f"{label} must be a number, got {value!r}"
        ) from error
    if not math.isfinite(duration):
        raise ConfigurationError(f"{label} must be finite")
    if duration < 0:
        raise ConfigurationError(f"{label} must not be negative")
    return duration
