import os
from pathlib import Path

import pytest

from telegent import CaptureError, CaptureSettings, ConfigurationError
from telegent.collector.validation import validate_all_targets, validate_target
from telegent.configuration import (
    discover_codex_providers,
    load_codex_target,
)


def _settings(tmp_path: Path, environment: dict[str, str]) -> CaptureSettings:
    executables = []
    for name in ("tshark", "sequence", "codex"):
        path = tmp_path / name
        path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        path.chmod(0o755)
        executables.append(path)
    return CaptureSettings(
        agent="codex",
        capture_root=tmp_path / "captures",
        agent_config_root=tmp_path / "configs",
        sequence_script=executables[1],
        agent_binary=executables[2],
        working_directory=tmp_path,
        capture_interface="eth0",
        capture_filter="port 443",
        tail_seconds=0,
        request_interval_seconds=0,
        capture_start_timeout_seconds=1,
        tshark_binary=executables[0],
        environment=environment,
    )


def _config(tmp_path: Path, profile_provider: str = "provider") -> None:
    model_dir = tmp_path / "configs" / "model"
    model_dir.mkdir(parents=True)
    (model_dir / "config.toml").write_text(
        '[model_providers.provider]\nenv_key = "PROVIDER_KEY"\n', encoding="utf-8"
    )
    (model_dir / "provider.config.toml").write_text(
        f'model_provider = "{profile_provider}"\nmodel = "configured-model"\n',
        encoding="utf-8",
    )


def test_validates_model_provider_profile_and_api_key(tmp_path: Path) -> None:
    _config(tmp_path)
    settings = _settings(tmp_path, {"PROVIDER_KEY": "secret"})
    loaded = load_codex_target(
        settings.agent_config_root,
        settings.environment,
        "model",
        "provider",
    )
    target = validate_target(settings, "model", "provider")

    assert target == loaded
    assert target.configured_model == "configured-model"
    assert target.credential_environment_variables == ("PROVIDER_KEY",)


def test_discovers_codex_providers_in_configuration_order(tmp_path: Path) -> None:
    model_dir = tmp_path / "configs/model"
    model_dir.mkdir(parents=True)
    (model_dir / "config.toml").write_text(
        '[model_providers.zeta]\nenv_key = "ZETA_KEY"\n'
        '[model_providers.alpha]\nenv_key = "ALPHA_KEY"\n',
        encoding="utf-8",
    )

    assert discover_codex_providers(tmp_path / "configs", "model") == [
        "zeta",
        "alpha",
    ]


def test_unsupported_agent_has_no_implicit_fallback(tmp_path: Path) -> None:
    settings = _settings(tmp_path, {})
    object.__setattr__(settings, "agent", "unsupported")

    with pytest.raises(NotImplementedError, match="provider discovery.*unsupported"):
        validate_all_targets(settings, "model")
    with pytest.raises(NotImplementedError, match="target loading.*unsupported"):
        validate_target(settings, "model", "provider")


@pytest.mark.parametrize("name", ["../model", "/model", ".", "model/provider", "model "])
def test_rejects_unsafe_path_components(tmp_path: Path, name: str) -> None:
    with pytest.raises(ConfigurationError, match="safe path component"):
        validate_target(_settings(tmp_path, {}), name, "provider")


def test_rejects_profile_mismatch_and_missing_api_key(tmp_path: Path) -> None:
    _config(tmp_path, profile_provider="other")
    with pytest.raises(ConfigurationError, match="expected 'provider'"):
        validate_target(
            _settings(tmp_path, {"PROVIDER_KEY": "secret"}), "model", "provider"
        )

    (tmp_path / "configs/model/provider.config.toml").write_text(
        'model_provider = "provider"\nmodel = "configured-model"\n', encoding="utf-8"
    )
    with pytest.raises(ConfigurationError, match="PROVIDER_KEY"):
        validate_target(_settings(tmp_path, {}), "model", "provider")


def test_rejects_non_executable_binary(tmp_path: Path) -> None:
    _config(tmp_path)
    settings = _settings(tmp_path, {"PROVIDER_KEY": "secret"})
    os.chmod(settings.agent_binary, 0o644)

    with pytest.raises(CaptureError, match="codex binary is not executable"):
        validate_target(settings, "model", "provider")
