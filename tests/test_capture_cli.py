from pathlib import Path

import pytest

from telegent.cli import main


def _executable(path: Path) -> Path:
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def test_capture_dry_run_reports_all_dotenv_paths(
    tmp_path: Path, capsys: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "sentinel-configs/model"
    config.mkdir(parents=True)
    (config / "config.toml").write_text(
        '[model_providers.provider]\nenv_key = "API_KEY"\n', encoding="utf-8"
    )
    (config / "provider.config.toml").write_text(
        'model_provider = "provider"\nmodel = "configured"\n', encoding="utf-8"
    )
    executable = _executable(tmp_path / "sentinel-executable")
    env_file = tmp_path / "capture.env"
    env_file.write_text(
        "API_KEY=secret\n"
        "TELEGENT_CAPTURE_ROOT=sentinel-captures\n"
        "TELEGENT_CODEX_CONFIG_ROOT=sentinel-configs\n"
        "TELEGENT_SEQUENCE_SCRIPT=sentinel-executable\n"
        "TELEGENT_PROMPTS_FILE=sentinel-prompts.txt\n"
        "TELEGENT_CODEX_BINARY=sentinel-executable\n"
        "TELEGENT_TSHARK_BINARY=sentinel-executable\n",
        encoding="utf-8",
    )
    for name in (
        "TELEGENT_CAPTURE_ROOT",
        "TELEGENT_CODEX_CONFIG_ROOT",
        "TELEGENT_SEQUENCE_SCRIPT",
        "TELEGENT_PROMPTS_FILE",
        "TELEGENT_CODEX_BINARY",
        "TELEGENT_TSHARK_BINARY",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)

    result = main(
        [
            "capture",
            "model",
            "provider",
            "--dry-run",
            "--env-file",
            str(env_file),
        ]
    )

    assert result == 0
    output = capsys.readouterr().out  # type: ignore[attr-defined]
    assert "capture dry run" in output
    assert f"dotenv file: {env_file}" in output
    assert f"TELEGENT_CAPTURE_ROOT={tmp_path / 'sentinel-captures'}" in output
    assert f"TELEGENT_CODEX_CONFIG_ROOT={tmp_path / 'sentinel-configs'}" in output
    assert f"TELEGENT_SEQUENCE_SCRIPT={executable}" in output
    assert "TELEGENT_PROMPTS_FILE=sentinel-prompts.txt" in output
    assert f"TELEGENT_CODEX_BINARY={executable}" in output
    assert f"TELEGENT_TSHARK_BINARY={executable}" in output
    assert "API_KEY (set)" in output
    assert "secret" not in output
    assert not (tmp_path / "sentinel-captures").exists()


def test_capture_cli_returns_nonzero_for_validation_error(
    tmp_path: Path, capsys: object
) -> None:
    result = main(["capture", "../unsafe", "provider", "--dry-run"])

    assert result == 1
    assert "safe path component" in capsys.readouterr().err  # type: ignore[attr-defined]
