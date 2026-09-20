"""Discover provider endpoints and provider-specific model IDs."""

import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised on Python 3.10 installs
    import tomli as tomllib

from ..errors import TelegentError
from .settings import ProbeSettings

_COMPONENT = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9])?\Z")


class MissingCredential(TelegentError):
    """The configured provider cannot be probed without its API key."""


@dataclass(frozen=True)
class ProbeTarget:
    provider: str
    model_id: str
    url: str
    key_environment_variable: str
    api_key: str = field(repr=False)


def configured_providers(settings: ProbeSettings, model: str) -> dict[str, dict]:
    """Read the model's provider table, without requiring capture executables."""

    _validate_component(model, "model")
    path = settings.codex_config_root / model / "config.toml"
    config = _read_toml(path)
    providers = config.get("model_providers")
    if not isinstance(providers, dict) or not providers:
        raise TelegentError(f"no model providers defined in {path}")
    return providers


def load_target(
    settings: ProbeSettings, model: str, provider: str, provider_config: object
) -> ProbeTarget:
    """Validate one provider and its matching profile."""

    _validate_component(provider, "provider")
    if not isinstance(provider_config, dict):
        raise TelegentError(f"provider {provider!r} must be a table")
    profile_path = settings.codex_config_root / model / f"{provider}.config.toml"
    profile = _read_toml(profile_path)
    if profile.get("model_provider") != provider:
        raise TelegentError(f"profile {profile_path} must select provider {provider!r}")
    model_id = profile.get("model")
    if not isinstance(model_id, str) or not model_id.strip():
        raise TelegentError(f"profile {profile_path} must define a nonempty model")
    if provider_config.get("wire_api") != "responses":
        raise TelegentError(f"provider {provider!r} does not use the responses wire API")
    base_url = provider_config.get("base_url")
    if not isinstance(base_url, str):
        raise TelegentError(f"provider {provider!r} must define a base_url")
    try:
        parsed = urlsplit(base_url)
        hostname = parsed.hostname
        _ = parsed.port
    except ValueError as error:
        raise TelegentError(f"provider {provider!r} has an invalid base_url") from error
    if (
        not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.scheme not in ("http", "https")
        or (parsed.scheme == "http" and hostname not in ("localhost", "127.0.0.1", "::1"))
    ):
        raise TelegentError(f"provider {provider!r} has an invalid or insecure base_url")
    env_key = provider_config.get("env_key")
    if not isinstance(env_key, str) or not env_key:
        raise TelegentError(f"provider {provider!r} must define an env_key")
    url = base_url.rstrip("/") + "/responses"
    api_key = settings.environment.get(env_key)
    if not api_key:
        raise MissingCredential(
            f"{model_id} at {url} (key: {env_key}); API key is not set"
        )
    return ProbeTarget(
        provider=provider,
        model_id=model_id,
        url=url,
        key_environment_variable=env_key,
        api_key=api_key,
    )


def _validate_component(value: str, label: str) -> None:
    if not _COMPONENT.fullmatch(value):
        raise TelegentError(f"invalid {label} name {value!r}: expected a safe path component")


def _read_toml(path: Path) -> dict:
    if not path.is_file():
        raise TelegentError(f"configuration does not exist: {path}")
    try:
        with path.open("rb") as file:
            return tomllib.load(file)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise TelegentError(f"could not read configuration {path}: {error}") from error
