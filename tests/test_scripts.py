import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from telegent.collector.settings import CaptureSettings


def _executable(path: Path, body: str) -> Path:
    path.write_text(f"#!/usr/bin/env bash\nset -euo pipefail\n{body}", encoding="utf-8")
    path.chmod(0o755)
    return path


def _scripts_directory(tmp_path: Path) -> Path:
    return CaptureSettings.resolve(environ={"PATH": ""}, cwd=tmp_path).sequence_script.parent


def test_model_launcher_loads_dotenv_and_preserves_process_precedence(
    tmp_path: Path,
) -> None:
    config_root = tmp_path / "configs"
    (config_root / "deepseek").mkdir(parents=True)
    (config_root / "deepseek/config.toml").write_text("model = 'test'\n", encoding="utf-8")
    dotenv_capture_root = tmp_path / "dotenv-captures"
    process_capture_root = tmp_path / "process-captures"
    observed_path = tmp_path / "observed.json"
    fake_codex = _executable(
        tmp_path / "fake-codex",
        "python3 - \"$@\" <<'PYTHON'\n"
        "import json, os, sys\n"
        "observed = {\n"
        "    'args': sys.argv[1:],\n"
        "    'codex_home': os.environ['CODEX_HOME'],\n"
        "    'sslkeylogfile': os.environ['SSLKEYLOGFILE'],\n"
        "    'api_key': os.environ['TEST_API_KEY'],\n"
        "}\n"
        "open(os.environ['OBSERVED_PATH'], 'w').write(json.dumps(observed))\n"
        "PYTHON\n",
    )
    (tmp_path / ".env").write_text(
        f"TELEGENT_CODEX_CONFIG_ROOT={config_root}\n"
        f"TELEGENT_CAPTURE_ROOT={dotenv_capture_root}\n"
        f"TELEGENT_CODEX_BINARY={fake_codex}\n"
        f"OBSERVED_PATH={tmp_path / 'wrong.json'}\n"
        "TEST_API_KEY=dotenv-secret\n",
        encoding="utf-8",
    )
    environment = {
        **os.environ,
        "TELEGENT_CAPTURE_ROOT": str(process_capture_root),
        "TELEGENT_PYTHON_BINARY": sys.executable,
        "OBSERVED_PATH": str(observed_path),
    }

    result = subprocess.run(
        [_scripts_directory(tmp_path) / "codex-deepseek.sh", "exec", "--json"],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(observed_path.read_text(encoding="utf-8")) == {
        "args": ["exec", "--json"],
        "codex_home": str(config_root / "deepseek"),
        "sslkeylogfile": str(process_capture_root / "deepseek/sslkeys.key"),
        "api_key": "dotenv-secret",
    }
    assert not dotenv_capture_root.exists()


def test_sequence_can_load_binary_provider_and_prompts_from_dotenv(tmp_path: Path) -> None:
    fake_codex = _executable(
        tmp_path / "fake-codex",
        "printf '%s\\n' "
        "'{\"type\":\"thread.started\",\"thread_id\":\"thread-1\"}' "
        "'{\"type\":\"item.completed\",\"item\":{\"type\":\"agent_message\",\"text\":\"OK\"}}' "
        "'{\"type\":\"turn.completed\"}'\n",
    )
    prompts = tmp_path / "prompts.txt"
    prompts.write_text("A short test prompt.\n", encoding="utf-8")
    output = tmp_path / "output"
    (tmp_path / ".env").write_text(
        f"TELEGENT_CODEX_BINARY={fake_codex}\n"
        "TELEGENT_MODEL_PROVIDER=test-provider\n"
        f"TELEGENT_PROMPTS_FILE={prompts}\n"
        f"CODEX_SEQUENCE_OUTPUT_DIR={output}\n",
        encoding="utf-8",
    )
    environment = {**os.environ, "TELEGENT_PYTHON_BINARY": sys.executable}

    result = subprocess.run(
        [_scripts_directory(tmp_path) / "codex-sequence.sh"],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    run_directories = list(output.iterdir())
    assert len(run_directories) == 1
    run_directory = run_directories[0]
    assert "A short test prompt." in result.stdout
    assert (run_directory / "turn_01.jsonl").is_file()
    assert "OK" in (run_directory / "answers.txt").read_text(encoding="utf-8")


def test_sequence_waits_only_between_completed_prompts(tmp_path: Path) -> None:
    fake_codex = _executable(
        tmp_path / "fake-codex",
        "printf 'request\\n' >>\"$ACTION_LOG\"\n"
        "printf '%s\\n' "
        "'{\"type\":\"thread.started\",\"thread_id\":\"thread-1\"}' "
        "'{\"type\":\"item.completed\",\"item\":{\"type\":\"agent_message\",\"text\":\"OK\"}}' "
        "'{\"type\":\"turn.completed\"}'\n",
    )
    action_log = tmp_path / "actions.log"
    _executable(tmp_path / "sleep", 'printf \'sleep:%s\\n\' "$1" >>"$ACTION_LOG"\n')
    prompts = tmp_path / "prompts.txt"
    prompts.write_text("First\nSecond\nThird\n", encoding="utf-8")
    environment = {
        **os.environ,
        "PATH": f"{tmp_path}:{os.environ['PATH']}",
        "TELEGENT_PROMPTS_FILE": str(prompts),
        "TELEGENT_REQUEST_INTERVAL_SECONDS": "0.25",
        "CODEX_SEQUENCE_OUTPUT_DIR": str(tmp_path / "output"),
        "ACTION_LOG": str(action_log),
    }

    result = subprocess.run(
        [_scripts_directory(tmp_path) / "codex-sequence.sh", fake_codex, "provider"],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert action_log.read_text(encoding="utf-8").splitlines() == [
        "request",
        "sleep:0.25",
        "request",
        "sleep:0.25",
        "request",
    ]
    assert result.stdout.count("Waiting 0.25 seconds before the next turn...") == 2


@pytest.mark.parametrize("interval", ["-1", "nan", "invalid"])
def test_sequence_rejects_invalid_request_interval(
    tmp_path: Path, interval: str
) -> None:
    fake_codex = _executable(tmp_path / "fake-codex", "exit 0\n")
    prompts = tmp_path / "prompts.txt"
    prompts.write_text("Prompt\n", encoding="utf-8")
    environment = {
        **os.environ,
        "TELEGENT_PROMPTS_FILE": str(prompts),
        "TELEGENT_REQUEST_INTERVAL_SECONDS": interval,
    }

    result = subprocess.run(
        [_scripts_directory(tmp_path) / "codex-sequence.sh", fake_codex, "provider"],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert "must be a nonnegative number" in result.stderr


def test_explicit_missing_env_file_fails_before_launcher(tmp_path: Path) -> None:
    environment = {
        **os.environ,
        "TELEGENT_ENV_FILE": str(tmp_path / "missing.env"),
        "TELEGENT_PYTHON_BINARY": sys.executable,
    }

    result = subprocess.run(
        [_scripts_directory(tmp_path) / "codex-openai.sh", "--version"],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert "environment file does not exist" in result.stderr
