import os
from pathlib import Path

import pytest

from telegent import CaptureError, CaptureSettings
from telegent.collector.config import validate_target


def _settings(tmp_path: Path, environment: dict[str, str]) -> CaptureSettings:
    executables = []
    for name in ("tshark", "sequence", "codex"):
        path = tmp_path / name
        path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        path.chmod(0o755)
        executables.append(path)
    return CaptureSettings(
        capture_root=tmp_path / "captures",
        codex_config_root=tmp_path / "configs",
        sequence_script=executables[1],
        codex_binary=executables[2],
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
    target = validate_target(_settings(tmp_path, {"PROVIDER_KEY": "secret"}), "model", "provider")

    assert target.configured_model == "configured-model"
    assert target.api_key_environment_variable == "PROVIDER_KEY"


@pytest.mark.parametrize("name", ["../model", "/model", ".", "model/provider", "model "])
def test_rejects_unsafe_path_components(tmp_path: Path, name: str) -> None:
    with pytest.raises(CaptureError, match="safe path component"):
        validate_target(_settings(tmp_path, {}), name, "provider")


def test_rejects_profile_mismatch_and_missing_api_key(tmp_path: Path) -> None:
    _config(tmp_path, profile_provider="other")
    with pytest.raises(CaptureError, match="expected 'provider'"):
        validate_target(
            _settings(tmp_path, {"PROVIDER_KEY": "secret"}), "model", "provider"
        )

    (tmp_path / "configs/model/provider.config.toml").write_text(
        'model_provider = "provider"\nmodel = "configured-model"\n', encoding="utf-8"
    )
    with pytest.raises(CaptureError, match="PROVIDER_KEY"):
        validate_target(_settings(tmp_path, {}), "model", "provider")


def test_rejects_non_executable_binary(tmp_path: Path) -> None:
    _config(tmp_path)
    settings = _settings(tmp_path, {"PROVIDER_KEY": "secret"})
    os.chmod(settings.codex_binary, 0o644)

    with pytest.raises(CaptureError, match="Codex binary is not executable"):
        validate_target(settings, "model", "provider")
