"""Resolve endpoint-probe paths and credentials."""

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import dotenv_values

from ..errors import TelegentError


@dataclass(frozen=True)
class ProbeSettings:
    """Settings shared by every provider in one test command."""

    codex_config_root: Path
    timeout_seconds: float
    environment: Mapping[str, str] = field(repr=False)
    env_file: Path | None = None

    @classmethod
    def resolve(
        cls,
        overrides: Mapping[str, object] | None = None,
        *,
        environ: Mapping[str, str] | None = None,
        cwd: Path | None = None,
    ) -> "ProbeSettings":
        """Resolve CLI > process environment > working-directory dotenv > defaults."""

        overrides = overrides or {}
        directory = (cwd or Path.cwd()).resolve()
        env_file_option = overrides.get("env_file")
        env_file = (
            _path(str(env_file_option), directory)
            if env_file_option is not None
            else directory / ".env"
        )
        if not env_file.is_file() and env_file_option is not None:
            raise TelegentError(f"environment file does not exist: {env_file}")
        try:
            dotenv_environment = (
                {key: value for key, value in dotenv_values(env_file).items() if value is not None}
                if env_file.is_file()
                else {}
            )
        except OSError as error:
            raise TelegentError(f"could not read environment file {env_file}: {error}") from error
        environment = {
            **dotenv_environment,
            **dict(os.environ if environ is None else environ),
        }
        config_root = overrides.get("codex_config_root")
        if config_root is None:
            config_root = environment.get("TELEGENT_CODEX_CONFIG_ROOT", "codex-third-party")
        timeout = overrides.get("timeout_seconds")
        if timeout is None:
            timeout = environment.get("TELEGENT_TEST_TIMEOUT_SECONDS", "60")
        try:
            timeout_seconds = float(timeout)
        except (TypeError, ValueError) as error:
            raise TelegentError("test timeout must be a number") from error
        if not 0 < timeout_seconds <= 3600:
            raise TelegentError("test timeout must be greater than 0 and at most 3600 seconds")
        return cls(
            codex_config_root=_path(str(config_root), directory),
            timeout_seconds=timeout_seconds,
            environment=environment,
            env_file=env_file if env_file.is_file() else None,
        )


def _path(value: str, cwd: Path) -> Path:
    path = Path(value).expanduser()
    return (cwd / path).resolve() if not path.is_absolute() else path.resolve()
