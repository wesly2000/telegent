from pathlib import Path

import pytest

from telegent import CaptureError, CaptureSettings


def test_cli_environment_dotenv_and_default_precedence(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text(
        "TELEGENT_CAPTURE_ROOT=from-dotenv\n"
        "TELEGENT_CAPTURE_INTERFACE=dotenv-interface\n"
        "TELEGENT_TAIL_SECONDS=7\n"
        "DOTENV_API_KEY=secret\n",
        encoding="utf-8",
    )

    settings = CaptureSettings.resolve(
        {"capture_root": "from-cli"},
        environ={
            "TELEGENT_CAPTURE_INTERFACE": "environment-interface",
            "PATH": "",
        },
        cwd=tmp_path,
    )

    assert settings.capture_root == tmp_path / "from-cli"
    assert settings.capture_interface == "environment-interface"
    assert settings.tail_seconds == 7
    assert settings.capture_filter == "port 443"
    assert settings.environment["DOTENV_API_KEY"] == "secret"
    assert settings.env_file == tmp_path / ".env"
    assert settings.sequence_script.name == "codex-sequence.sh"
    assert settings.sequence_script.is_file()


def test_explicit_env_file_and_invalid_duration(tmp_path: Path) -> None:
    env_file = tmp_path / "capture.env"
    env_file.write_text("TELEGENT_TAIL_SECONDS=-1\n", encoding="utf-8")

    with pytest.raises(CaptureError, match="must not be negative"):
        CaptureSettings.resolve(
            {"env_file": env_file}, environ={"PATH": ""}, cwd=tmp_path
        )

    with pytest.raises(CaptureError, match="environment file does not exist"):
        CaptureSettings.resolve(
            {"env_file": tmp_path / "missing.env"},
            environ={"PATH": ""},
            cwd=tmp_path,
        )


def test_repository_codex_binary_is_preferred_over_path(tmp_path: Path) -> None:
    local_codex = tmp_path / "codex-rs/target/debug/codex"
    local_codex.parent.mkdir(parents=True)
    local_codex.write_text("local", encoding="utf-8")

    settings = CaptureSettings.resolve(environ={"PATH": "/bin"}, cwd=tmp_path)

    assert settings.codex_binary == local_codex


def test_env_example_is_documentation_not_runtime_fallback(tmp_path: Path) -> None:
    (tmp_path / ".env.example").write_text(
        "TELEGENT_CAPTURE_ROOT=example-captures\n"
        "TELEGENT_CODEX_CONFIG_ROOT=example-configs\n"
        "TELEGENT_PROMPTS_FILE=example-prompts.txt\n",
        encoding="utf-8",
    )

    settings = CaptureSettings.resolve(environ={"PATH": ""}, cwd=tmp_path)

    assert settings.env_file is None
    assert settings.capture_root == tmp_path / "capture/chat"
    assert settings.codex_config_root == tmp_path / "codex-third-party"
