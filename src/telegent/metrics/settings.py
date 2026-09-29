"""Resolve metrics paths from the environment and dotenv files."""

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from dotenv import dotenv_values

from ..errors import TelegentError


@dataclass(frozen=True)
class MetricSettings:
    """Resolved locations used while computing and storing metrics."""

    analysis_root: Path
    database_path: Path
    env_file: Path | None = None

    @classmethod
    def resolve(
        cls,
        overrides: Mapping[str, object] | None = None,
        *,
        environ: Mapping[str, str] | None = None,
        cwd: Path | None = None,
    ) -> "MetricSettings":
        """Resolve settings with overrides, environment, then dotenv precedence."""

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
                {
                    key: value
                    for key, value in dotenv_values(env_file).items()
                    if value is not None
                }
                if env_file.is_file()
                else {}
            )
        except OSError as error:
            raise TelegentError(
                f"could not read environment file {env_file}: {error}"
            ) from error
        environment = {
            **dotenv_environment,
            **dict(os.environ if environ is None else environ),
        }

        analysis_root = overrides.get("analysis_root")
        if analysis_root is None:
            analysis_root = environment.get("TELEGENT_ANALYSIS_ROOT")
        database_path = overrides.get("database_path")
        if database_path is None:
            database_path = environment.get("TELEGENT_METRICS_DB")
        if not analysis_root:
            raise TelegentError("TELEGENT_ANALYSIS_ROOT is required")
        if not database_path:
            raise TelegentError("TELEGENT_METRICS_DB is required")

        return cls(
            analysis_root=_path(str(analysis_root), directory),
            database_path=_path(str(database_path), directory),
            env_file=env_file if env_file.is_file() else None,
        )


def _path(value: str, cwd: Path) -> Path:
    path = Path(value).expanduser()
    return (cwd / path).resolve() if not path.is_absolute() else path.resolve()
