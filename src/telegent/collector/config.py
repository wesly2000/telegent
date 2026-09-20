"""Validate Codex model and provider configuration for capture."""

import os
import re
from dataclasses import dataclass
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised on Python 3.10 installs
    import tomli as tomllib

from ..errors import CaptureError
from .settings import CaptureSettings

_COMPONENT = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9])?\Z")


@dataclass(frozen=True)
class CaptureTarget:
    model: str
    provider: str
    codex_home: Path
    base_config: Path
    profile_config: Path
    configured_model: str
    api_key_environment_variable: str


def validate_all_targets(settings: CaptureSettings, model: str) -> list[CaptureTarget]:
    """Validate every configured provider before starting a batch capture."""

    _validate_component(model, "model")
    base_config = settings.codex_config_root / model / "config.toml"
    providers = _load_toml(base_config, "model configuration").get("model_providers")
    if not isinstance(providers, dict) or not providers:
        raise CaptureError(f"no model providers are defined in {base_config}")
    return [validate_target(settings, model, provider) for provider in providers]


def validate_target(
    settings: CaptureSettings, model: str, provider: str
) -> CaptureTarget:
    """Validate paths, TOML configuration, credentials, and executables."""

    _validate_component(model, "model")
    _validate_component(provider, "provider")
    codex_home = settings.codex_config_root / model
    base_config = codex_home / "config.toml"
    profile_config = codex_home / f"{provider}.config.toml"
    base = _load_toml(base_config, "model configuration")
    profile = _load_toml(profile_config, "provider profile")

    providers = base.get("model_providers")
    provider_config = providers.get(provider) if isinstance(providers, dict) else None
    if not isinstance(provider_config, dict):
        raise CaptureError(f"provider {provider!r} is not defined in {base_config}")
    profile_provider = profile.get("model_provider")
    if profile_provider != provider:
        raise CaptureError(
            f"profile {profile_config} selects model_provider {profile_provider!r}, "
            f"expected {provider!r}"
        )
    configured_model = profile.get("model")
    if not isinstance(configured_model, str) or not configured_model.strip():
        raise CaptureError(f"profile {profile_config} must define a nonempty model")
    env_key = provider_config.get("env_key")
    if not isinstance(env_key, str) or not env_key:
        raise CaptureError(
            f"provider {provider!r} in {base_config} must define a nonempty env_key"
        )
    if not settings.environment.get(env_key):
        raise CaptureError(f"required API-key environment variable is not set: {env_key}")

    for label, path in (
        ("tshark binary", settings.tshark_binary),
        ("sequence script", settings.sequence_script),
        ("Codex binary", settings.codex_binary),
    ):
        _validate_executable(path, label)

    return CaptureTarget(
        model=model,
        provider=provider,
        codex_home=codex_home,
        base_config=base_config,
        profile_config=profile_config,
        configured_model=configured_model,
        api_key_environment_variable=env_key,
    )


def _validate_component(value: str, label: str) -> None:
    if not _COMPONENT.fullmatch(value):
        raise CaptureError(f"invalid {label} name {value!r}: expected a safe path component")


def _load_toml(path: Path, label: str) -> dict[str, object]:
    if not path.is_file():
        raise CaptureError(f"{label} does not exist: {path}")
    try:
        with path.open("rb") as file:
            return tomllib.load(file)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise CaptureError(f"could not read {label} {path}: {error}") from error


def _validate_executable(path: Path, label: str) -> None:
    if not path.is_file():
        raise CaptureError(f"{label} does not exist: {path}")
    if not os.access(path, os.X_OK):
        raise CaptureError(f"{label} is not executable: {path}")
