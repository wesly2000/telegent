"""Discover and load Codex and OpenCode provider configurations."""

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import json5

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised on Python 3.10 installs
    import tomli as tomllib

from ..errors import ConfigurationError
from .settings import AgentKind

_COMPONENT = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9])?\Z")
_ENV_REFERENCE = re.compile(r"\{env:([^{}]+)\}")
_FILE_REFERENCE = re.compile(r"\{file:([^{}]+)\}")


@dataclass(frozen=True)
class AgentTarget:
    agent: AgentKind
    model: str
    provider: str
    config_directory: Path
    config_path: Path
    configured_model: str
    credential_environment_variables: tuple[str, ...]
    inline_config: str | None = None
    model_catalog: Path | None = None


def discover_providers(
    agent: AgentKind, config_root: Path, model: str
) -> list[str]:
    """Discover provider names using the selected agent's native format."""

    if agent == "opencode":
        return discover_opencode_providers(config_root, model)
    elif agent == "codex":
        return discover_codex_providers(config_root, model)
    else:
        raise NotImplementedError(
            f"provider discovery is not implemented for agent {agent!r}"
        )


def load_target(
    agent: AgentKind,
    config_root: Path,
    environment: Mapping[str, str],
    model: str,
    provider: str,
) -> AgentTarget:
    """Load one provider target using the selected agent's native format."""

    if agent == "opencode":
        return load_opencode_target(config_root, environment, model, provider)
    elif agent == "codex":
        return load_codex_target(config_root, environment, model, provider)
    else:
        raise NotImplementedError(
            f"target loading is not implemented for agent {agent!r}"
        )


def load_targets(
    agent: AgentKind,
    config_root: Path,
    environment: Mapping[str, str],
    model: str,
) -> list[AgentTarget]:
    """Load every configured provider target for one model."""

    return [
        load_target(agent, config_root, environment, model, provider)
        for provider in discover_providers(agent, config_root, model)
    ]


def discover_codex_providers(config_root: Path, model: str) -> list[str]:
    """Return Codex provider names in TOML declaration order."""

    _validate_component(model, "model")
    base_config = config_root / model / "config.toml"
    configured = _load_toml(base_config, "model configuration").get(
        "model_providers"
    )
    if not isinstance(configured, dict) or not configured:
        raise ConfigurationError(f"no model providers are defined in {base_config}")
    providers = list(configured)
    for provider in providers:
        _validate_component(provider, "provider")
    return providers


def discover_opencode_providers(config_root: Path, model: str) -> list[str]:
    """Return provider names from native OpenCode configs in lexical order."""

    _validate_component(model, "model")
    directory = config_root / model
    if not directory.is_dir():
        raise ConfigurationError(
            f"model configuration directory does not exist: {directory}"
        )
    providers: dict[str, Path] = {}
    for path in sorted(directory.iterdir()):
        suffix = next(
            (
                item
                for item in (".opencode.json", ".opencode.jsonc")
                if path.name.endswith(item)
            ),
            None,
        )
        if suffix is None or not path.is_file():
            continue
        provider = path.name[: -len(suffix)]
        _validate_component(provider, "provider")
        if provider in providers:
            raise ConfigurationError(
                f"both JSON and JSONC OpenCode configs exist for provider {provider!r}: "
                f"{providers[provider]} and {path}"
            )
        providers[provider] = path
    if not providers:
        raise ConfigurationError(
            f"no *.opencode.json or *.opencode.jsonc files found in {directory}"
        )
    return sorted(providers)


def load_opencode_target(
    config_root: Path,
    environment: Mapping[str, str],
    model: str,
    provider: str,
) -> AgentTarget:
    """Load, normalize, and validate one native OpenCode configuration."""

    _validate_component(model, "model")
    _validate_component(provider, "provider")
    directory = config_root / model
    json_path = directory / f"{provider}.opencode.json"
    jsonc_path = directory / f"{provider}.opencode.jsonc"
    existing = [path for path in (json_path, jsonc_path) if path.is_file()]
    if len(existing) > 1:
        raise ConfigurationError(
            f"both JSON and JSONC OpenCode configs exist for provider {provider!r}: "
            f"{json_path} and {jsonc_path}"
        )
    if not existing:
        raise ConfigurationError(
            f"OpenCode configuration does not exist: {jsonc_path} or {json_path}"
        )
    path = existing[0]
    try:
        parsed = json5.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ConfigurationError(
            f"could not read OpenCode configuration {path}: {error}"
        ) from error
    if not isinstance(parsed, dict):
        raise ConfigurationError(
            f"OpenCode configuration {path} must contain a JSON object"
        )
    configured_model = parsed.get("model")
    if not isinstance(configured_model, str) or not configured_model.strip():
        raise ConfigurationError(
            f"OpenCode configuration {path} must define a nonempty model"
        )
    model_parts = configured_model.split("/", 1)
    if len(model_parts) != 2 or not all(part.strip() for part in model_parts):
        raise ConfigurationError(
            f"OpenCode configuration {path} model must use provider/model format"
        )

    normalized = _rewrite_file_references(parsed, path.parent)
    normalized = _rewrite_plugin_references(normalized, path.parent)
    references = tuple(sorted(_environment_references(normalized)))
    missing = [name for name in references if not environment.get(name)]
    if missing:
        names = ", ".join(missing)
        raise ConfigurationError(
            f"required OpenCode environment variable(s) not set: {names}"
        )
    return AgentTarget(
        agent="opencode",
        model=model,
        provider=provider,
        config_directory=directory,
        config_path=path,
        configured_model=configured_model,
        credential_environment_variables=references,
        inline_config=json.dumps(
            normalized, separators=(",", ":"), ensure_ascii=False
        ),
    )


def load_codex_target(
    config_root: Path,
    environment: Mapping[str, str],
    model: str,
    provider: str,
) -> AgentTarget:
    """Load and validate one Codex provider configuration and profile."""

    _validate_component(model, "model")
    _validate_component(provider, "provider")
    config_directory = config_root / model
    base_config = config_directory / "config.toml"
    profile_config = config_directory / f"{provider}.config.toml"
    base = _load_toml(base_config, "model configuration")
    profile = _load_toml(profile_config, "provider profile")

    providers = base.get("model_providers")
    provider_config = providers.get(provider) if isinstance(providers, dict) else None
    if not isinstance(provider_config, dict):
        raise ConfigurationError(
            f"provider {provider!r} is not defined in {base_config}"
        )
    profile_provider = profile.get("model_provider")
    if profile_provider != provider:
        raise ConfigurationError(
            f"profile {profile_config} selects model_provider {profile_provider!r}, "
            f"expected {provider!r}"
        )
    configured_model = profile.get("model")
    if not isinstance(configured_model, str) or not configured_model.strip():
        raise ConfigurationError(
            f"profile {profile_config} must define a nonempty model"
        )
    env_key = provider_config.get("env_key")
    if not isinstance(env_key, str) or not env_key:
        raise ConfigurationError(
            f"provider {provider!r} in {base_config} must define a nonempty env_key"
        )
    if not environment.get(env_key):
        raise ConfigurationError(
            f"required API-key environment variable is not set: {env_key}"
        )
    catalog = config_directory / "models.json"
    return AgentTarget(
        agent="codex",
        model=model,
        provider=provider,
        config_directory=config_directory,
        config_path=profile_config,
        configured_model=configured_model,
        credential_environment_variables=(env_key,),
        model_catalog=catalog if catalog.is_file() else None,
    )


def _rewrite_file_references(value: Any, base: Path) -> Any:
    if isinstance(value, dict):
        return {key: _rewrite_file_references(item, base) for key, item in value.items()}
    if isinstance(value, list):
        return [_rewrite_file_references(item, base) for item in value]
    if not isinstance(value, str):
        return value

    def replace(match: re.Match[str]) -> str:
        referenced = Path(match.group(1)).expanduser()
        referenced = (
            referenced.resolve()
            if referenced.is_absolute()
            else (base / referenced).resolve()
        )
        return f"{{file:{referenced}}}"

    return _FILE_REFERENCE.sub(replace, value)


def _rewrite_plugin_references(config: dict[str, Any], base: Path) -> dict[str, Any]:
    plugins = config.get("plugin")
    if not isinstance(plugins, list):
        return config

    def rewrite(spec: Any) -> Any:
        if isinstance(spec, str):
            if not spec.startswith("."):
                return spec
            return (base / spec).resolve().as_uri()
        if (
            isinstance(spec, list)
            and spec
            and isinstance(spec[0], str)
            and spec[0].startswith(".")
        ):
            return [(base / spec[0]).resolve().as_uri(), *spec[1:]]
        return spec

    return {**config, "plugin": [rewrite(spec) for spec in plugins]}


def _environment_references(value: Any) -> set[str]:
    if isinstance(value, dict):
        references: set[str] = set()
        for item in value.values():
            references.update(_environment_references(item))
        return references
    if isinstance(value, list):
        references = set()
        for item in value:
            references.update(_environment_references(item))
        return references
    if isinstance(value, str):
        return set(_ENV_REFERENCE.findall(value))
    return set()


def _validate_component(value: str, label: str) -> None:
    if not _COMPONENT.fullmatch(value):
        raise ConfigurationError(
            f"invalid {label} name {value!r}: expected a safe path component"
        )


def _load_toml(path: Path, label: str) -> dict[str, object]:
    if not path.is_file():
        raise ConfigurationError(f"{label} does not exist: {path}")
    try:
        with path.open("rb") as file:
            return tomllib.load(file)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ConfigurationError(f"could not read {label} {path}: {error}") from error
