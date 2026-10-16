import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from telegent import CaptureError, CaptureRunner, CaptureSettings, ConfigurationError
from telegent.collector.validation import validate_all_targets
from telegent.configuration import (
    discover_opencode_providers,
    load_opencode_target,
)


def _executable(path: Path, body: str = "exit 0\n") -> Path:
    path.write_text(f"#!/usr/bin/env bash\nset -eu\n{body}", encoding="utf-8")
    path.chmod(0o755)
    return path


def _settings(tmp_path: Path, sequence: Path | None = None) -> CaptureSettings:
    executable = _executable(tmp_path / "agent")
    return CaptureSettings(
        agent="opencode",
        capture_root=tmp_path / "captures",
        agent_config_root=tmp_path / "configs",
        sequence_script=sequence or executable,
        agent_binary=executable,
        working_directory=tmp_path / "work",
        capture_interface="test0",
        capture_filter="port 443",
        tail_seconds=0,
        request_interval_seconds=0,
        capture_start_timeout_seconds=1,
        tshark_binary=executable,
        environment={"DEEPSEEK_API_KEY": "secret", "HOME": "/sentinel-home"},
    )


def _native_config(tmp_path: Path, provider: str = "official") -> Path:
    model_dir = tmp_path / "configs/deepseek"
    model_dir.mkdir(parents=True, exist_ok=True)
    (model_dir / "system.txt").write_text("Be concise", encoding="utf-8")
    path = model_dir / f"{provider}.opencode.jsonc"
    path.write_text(
        """{
          // This is passed directly to OpenCode.
          model: "deepseek/deepseek-chat",
          provider: {
            deepseek: {
              npm: "@ai-sdk/openai-compatible",
              options: { apiKey: "{env:DEEPSEEK_API_KEY}" },
            },
          },
          instructions: ["{file:./system.txt}"],
        }
        """,
        encoding="utf-8",
    )
    return path


def test_native_jsonc_is_normalized_and_file_references_are_anchored(
    tmp_path: Path,
) -> None:
    source = _native_config(tmp_path)
    target = load_opencode_target(
        tmp_path / "configs",
        {"DEEPSEEK_API_KEY": "secret"},
        "deepseek",
        "official",
    )

    assert target.config_path == source
    assert target.configured_model == "deepseek/deepseek-chat"
    assert target.credential_environment_variables == ("DEEPSEEK_API_KEY",)
    normalized = json.loads(target.inline_config or "")
    assert normalized["provider"]["deepseek"]["options"]["apiKey"] == (
        "{env:DEEPSEEK_API_KEY}"
    )
    assert normalized["instructions"] == [
        f"{{file:{source.parent / 'system.txt'}}}"
    ]


def test_opencode_discovery_is_lexical_and_rejects_ambiguous_or_missing_env(
    tmp_path: Path,
) -> None:
    first = _native_config(tmp_path, "zeta")
    (first.parent / "alpha.opencode.json").write_text(
        '{"model":"deepseek/deepseek-chat"}', encoding="utf-8"
    )
    assert discover_opencode_providers(tmp_path / "configs", "deepseek") == [
        "alpha",
        "zeta",
    ]

    with pytest.raises(ConfigurationError, match="DEEPSEEK_API_KEY"):
        load_opencode_target(tmp_path / "configs", {}, "deepseek", "zeta")
    (first.parent / "zeta.opencode.json").write_text(
        '{"model":"deepseek/deepseek-chat"}', encoding="utf-8"
    )
    with pytest.raises(ConfigurationError, match="both JSON and JSONC"):
        discover_opencode_providers(tmp_path / "configs", "deepseek")


def test_validate_all_opencode_targets_uses_native_files_only(tmp_path: Path) -> None:
    _native_config(tmp_path)
    settings = _settings(tmp_path)
    targets = validate_all_targets(settings, "deepseek")
    assert [(target.provider, target.agent) for target in targets] == [
        ("official", "opencode")
    ]


def test_capture_runner_isolates_opencode_and_records_generic_metadata(
    tmp_path: Path,
) -> None:
    _native_config(tmp_path)
    (tmp_path / "work").mkdir()
    tshark = _executable(
        tmp_path / "tshark",
        """output=
while (($#)); do
  if [[ $1 == -w ]]; then output=$2; shift 2; else shift; fi
done
printf '\\x0a\\x0d\\x0d\\x0a' >"$output"
echo 'Capture started' >&2
trap 'exit 0' INT TERM
while true; do sleep 0.05; done
""",
    )
    sequence = _executable(
        tmp_path / "sequence",
        """mkdir -p "$TELEGENT_AGENT_OUTPUT_DIR"
""" + sys.executable + """ - "$TELEGENT_AGENT_OUTPUT_DIR/observed.json" "$@" <<'PY'
import json, os, sys
names = ("XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME")
data = {
    "args": sys.argv[2:],
    "home": os.environ.get("HOME"),
    "xdg": {name: os.environ[name] for name in names},
    "flags": {name: os.environ[name] for name in (
        "OPENCODE_DISABLE_PROJECT_CONFIG", "OPENCODE_PURE",
        "OPENCODE_DISABLE_AUTOUPDATE", "OPENCODE_DISABLE_AUTOCOMPACT",
        "OPENCODE_DISABLE_MODELS_FETCH", "OPENCODE_AUTH_CONTENT",
    )},
    "config": json.loads(os.environ["OPENCODE_CONFIG_CONTENT"]),
    "key_present": bool(os.environ.get("DEEPSEEK_API_KEY")),
}
open(sys.argv[1], "w").write(json.dumps(data))
open(os.environ["SSLKEYLOGFILE"], "a").write("CLIENT_HANDSHAKE_TRAFFIC_SECRET test secret\\n")
PY
""",
    )
    settings = _settings(tmp_path, sequence)
    settings = CaptureSettings(
        **{
            **settings.__dict__,
            "tshark_binary": tshark,
        }
    )

    result = CaptureRunner(settings).collect("deepseek", "official")
    observed = json.loads(
        (result.run_directory / "agent/observed.json").read_text(encoding="utf-8")
    )
    assert observed["args"] == [
        str(settings.agent_binary),
        "deepseek/deepseek-chat",
        str(settings.working_directory),
    ]
    assert observed["home"] == "/sentinel-home"
    assert observed["key_present"] is True
    assert set(observed["flags"].values()) == {"1", "{}"}
    assert all(
        Path(path).is_relative_to(result.run_directory / "agent-state")
        for path in observed["xdg"].values()
    )
    metadata_text = result.metadata_path.read_text(encoding="utf-8")
    metadata = json.loads(metadata_text)
    assert metadata["agent"] == "opencode"
    assert metadata["configuration"]["selected_config"].endswith(
        "official.opencode.jsonc"
    )
    assert metadata["configuration"]["isolated_state_path"] == str(
        result.run_directory / "agent-state"
    )
    assert "secret" not in metadata_text


def test_opencode_sequence_resumes_session_and_saves_answers(tmp_path: Path) -> None:
    agent = tmp_path / "fake-opencode"
    agent.write_text(
        """#!/usr/bin/env python3
import json, os, sys
with open(os.environ["ACTION_LOG"], "a") as output:
    output.write(json.dumps(sys.argv[1:]) + "\\n")
print(json.dumps({"type":"step_start","sessionID":"session-1","part":{}}))
print(json.dumps({"type":"text","sessionID":"session-1","part":{"type":"text","text":"OK"}}))
print(json.dumps({"type":"step_finish","sessionID":"session-1","part":{}}))
""",
        encoding="utf-8",
    )
    agent.chmod(0o755)
    prompts = tmp_path / "prompts.txt"
    prompts.write_text("First\nSecond\n", encoding="utf-8")
    output = tmp_path / "output"
    environment = {
        **os.environ,
        "ACTION_LOG": str(tmp_path / "actions.jsonl"),
        "TELEGENT_PROMPTS_FILE": str(prompts),
        "TELEGENT_AGENT_OUTPUT_DIR": str(output),
    }
    script = (
        Path(__file__).resolve().parents[1]
        / "src/telegent/scripts/opencode-sequence.sh"
    )

    completed = subprocess.run(
        [script, agent, "deepseek/deepseek-chat", str(tmp_path)],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    calls = [
        json.loads(line)
        for line in (tmp_path / "actions.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert "--session" not in calls[0]
    assert calls[1][calls[1].index("--session") + 1] == "session-1"
    run_directory = next(output.iterdir())
    assert (run_directory / "turn_01.jsonl").is_file()
    assert (run_directory / "turn_02.jsonl").is_file()
    assert (run_directory / "answers.txt").read_text(encoding="utf-8").count("OK") == 2


@pytest.mark.parametrize(
    ("events", "expected_error"),
    (
        ([{"type": "error", "sessionID": "session-1"}], "reported an error"),
        (
            [{"type": "text", "part": {"type": "text", "text": "OK"}}],
            "did not emit a session ID",
        ),
        (
            [{"type": "step_start", "sessionID": "session-1", "part": {}}],
            "did not emit text",
        ),
    ),
)
def test_opencode_sequence_rejects_error_and_incomplete_streams(
    tmp_path: Path, events: list[dict[str, object]], expected_error: str
) -> None:
    agent = tmp_path / "fake-opencode"
    agent.write_text(
        "#!/usr/bin/env python3\n"
        "import json\n"
        f"events = {events!r}\n"
        "for event in events: print(json.dumps(event))\n",
        encoding="utf-8",
    )
    agent.chmod(0o755)
    prompts = tmp_path / "prompts.txt"
    prompts.write_text("Only turn\n", encoding="utf-8")
    script = (
        Path(__file__).resolve().parents[1]
        / "src/telegent/scripts/opencode-sequence.sh"
    )
    completed = subprocess.run(
        [script, agent, "deepseek/deepseek-flash", str(tmp_path)],
        env={
            **os.environ,
            "TELEGENT_PROMPTS_FILE": str(prompts),
            "TELEGENT_AGENT_OUTPUT_DIR": str(tmp_path / "output"),
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 1
    assert expected_error in completed.stderr
