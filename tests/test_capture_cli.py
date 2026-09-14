from pathlib import Path
from types import SimpleNamespace

import pytest

from telegent import CaptureError
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
            "3",
            "--dry-run",
            "--env-file",
            str(env_file),
        ]
    )

    assert result == 0
    output = capsys.readouterr().out  # type: ignore[attr-defined]
    assert "capture dry run" in output
    assert "repetitions: 3" in output
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


def test_capture_repeats_with_one_resolved_configuration(
    tmp_path: Path, capsys: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    collected: list[tuple[str, str]] = []
    settings_ids: list[int] = []

    def collect(runner: object, model: str, provider: str) -> object:
        collected.append((model, provider))
        settings_ids.append(id(runner.settings))  # type: ignore[attr-defined]
        capture_id = len(collected)
        return SimpleNamespace(
            provider=provider,
            capture_id=capture_id,
            pcap_path=tmp_path / f"provider_{capture_id:02d}.pcap",
            ssl_keylog_path=tmp_path / "sslkeys.key",
            run_directory=tmp_path / f"provider_{capture_id:02d}",
        )

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("telegent.cli.CaptureRunner.collect", collect)

    result = main(["capture", "model", "provider", "3"])

    assert result == 0
    assert collected == [("model", "provider")] * 3
    assert len(set(settings_ids)) == 1
    output = capsys.readouterr().out  # type: ignore[attr-defined]
    assert "capture 1/3: provider_01 complete" in output
    assert "capture 2/3: provider_02 complete" in output
    assert "capture 3/3: provider_03 complete" in output


def test_repeated_capture_stops_after_first_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    attempts = 0

    def collect(_: object, model: str, provider: str) -> object:
        nonlocal attempts
        attempts += 1
        raise CaptureError("failed repetition")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("telegent.cli.CaptureRunner.collect", collect)

    result = main(["capture", "model", "provider", "3"])

    assert result == 1
    assert attempts == 1


@pytest.mark.parametrize("value", ["0", "-1", "not-a-number"])
def test_capture_repetition_count_must_be_positive(value: str) -> None:
    with pytest.raises(SystemExit) as raised:
        main(["capture", "model", "provider", value])

    assert raised.value.code == 2


def test_capture_cli_returns_nonzero_for_validation_error(
    tmp_path: Path, capsys: object
) -> None:
    result = main(["capture", "../unsafe", "provider", "--dry-run"])

    assert result == 1
    assert "safe path component" in capsys.readouterr().err  # type: ignore[attr-defined]
