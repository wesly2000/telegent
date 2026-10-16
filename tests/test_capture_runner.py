import json
import stat
from pathlib import Path

import pytest

from telegent import CaptureError, CaptureRunner, CaptureSettings
from telegent.configuration import AgentTarget


def _executable(path: Path, body: str) -> Path:
    path.write_text(f"#!/usr/bin/python3\n{body}", encoding="utf-8")
    path.chmod(0o755)
    return path


def _fixture(
    tmp_path: Path,
    *,
    sequence_exit: int = 0,
    tail: float = 0.02,
    request_interval: float = 0,
) -> CaptureSettings:
    config_dir = tmp_path / "configs" / "model"
    config_dir.mkdir(parents=True)
    (config_dir / "config.toml").write_text(
        '[model_providers.provider]\nenv_key = "PROVIDER_KEY"\n', encoding="utf-8"
    )
    (config_dir / "provider.config.toml").write_text(
        'model_provider = "provider"\nmodel = "configured-model"\n', encoding="utf-8"
    )
    tshark = _executable(
        tmp_path / "tshark",
        "import signal, sys, time\n"
        "output = sys.argv[sys.argv.index('-w') + 1]\n"
        "open(output, 'wb').write(b'\\x0a\\x0d\\x0d\\x0a')\n"
        "print('Capture started', file=sys.stderr, flush=True)\n"
        "signal.signal(signal.SIGINT, lambda *_: sys.exit(0))\n"
        "signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))\n"
        "while True: time.sleep(0.05)\n",
    )
    sequence = _executable(
        tmp_path / "sequence",
        "import json, os, pathlib, sys\n"
        "output = pathlib.Path(os.environ['TELEGENT_AGENT_OUTPUT_DIR'])\n"
        "output.mkdir(parents=True)\n"
        "observed = {\n"
        "  'args': sys.argv[1:],\n"
        "  'codex_home': os.environ['CODEX_HOME'],\n"
        "  'sslkeylogfile': os.environ['SSLKEYLOGFILE'],\n"
        "  'request_interval': os.environ['TELEGENT_REQUEST_INTERVAL_SECONDS'],\n"
        "  'api_key_present': bool(os.environ.get('PROVIDER_KEY')),\n"
        "}\n"
        "(output / 'observed.json').write_text(json.dumps(observed))\n"
        "with open(os.environ['SSLKEYLOGFILE'], 'a') as keys: keys.write('NEWKEY\\n')\n"
        f"sys.exit({sequence_exit})\n",
    )
    codex = _executable(tmp_path / "codex", "import sys\nsys.exit(0)\n")
    return CaptureSettings(
        agent="codex",
        capture_root=tmp_path / "captures",
        agent_config_root=tmp_path / "configs",
        sequence_script=sequence,
        agent_binary=codex,
        working_directory=tmp_path,
        capture_interface="test0",
        capture_filter="port 443",
        tail_seconds=tail,
        request_interval_seconds=request_interval,
        capture_start_timeout_seconds=1,
        tshark_binary=tshark,
        environment={"PROVIDER_KEY": "top-secret"},
    )


def test_collect_publishes_artifacts_metadata_and_child_configuration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _fixture(tmp_path, tail=3, request_interval=1.25)
    tail_sleeps: list[float] = []
    monkeypatch.setattr("telegent.collector.runner.sleep", tail_sleeps.append)
    model_dir = settings.capture_root / "model"
    model_dir.mkdir(parents=True)
    (model_dir / "sslkeys.key").write_text("EXISTING\n", encoding="utf-8")

    result = CaptureRunner(settings).collect("model", "provider")

    assert result.capture_id == 1
    assert result.pcap_path.name == "provider_01.pcap"
    assert result.pcap_path.read_bytes() == b"\x0a\x0d\x0d\x0a"
    assert result.ssl_keylog_path.read_text(encoding="utf-8") == "EXISTING\nNEWKEY\n"
    assert stat.S_IMODE(result.ssl_keylog_path.stat().st_mode) == 0o600
    observed = json.loads(
        (result.run_directory / "agent/observed.json").read_text(encoding="utf-8")
    )
    assert observed == {
        "args": [str(settings.agent_binary), "provider"],
        "codex_home": str(settings.agent_config_root / "model"),
        "sslkeylogfile": str(result.ssl_keylog_path),
        "request_interval": "1.25",
        "api_key_present": True,
    }
    metadata_text = result.metadata_path.read_text(encoding="utf-8")
    metadata = json.loads(metadata_text)
    assert metadata["processes"]["agent"]["returncode"] == 0
    assert metadata["processes"]["tshark"]["returncode"] == 0
    assert metadata["configuration"]["request_interval_seconds"] == 1.25
    assert "top-secret" not in metadata_text
    assert "top-secret" not in result.capture_log_path.read_text(encoding="utf-8")
    assert not result.pcap_path.with_suffix(".pcap.partial").exists()
    assert tail_sleeps == [3]


def test_agent_failure_cleans_artifacts_preserves_log_and_reuses_id(tmp_path: Path) -> None:
    settings = _fixture(tmp_path, sequence_exit=7)
    runner = CaptureRunner(settings)

    with pytest.raises(CaptureError, match="status 7") as raised:
        runner.collect("model", "provider")

    assert raised.value.failure_log_path is not None
    failure_log = Path(raised.value.failure_log_path)
    assert failure_log.is_file()
    assert "status 7" in failure_log.read_text(encoding="utf-8")
    model_dir = settings.capture_root / "model"
    assert not (model_dir / "provider_01").exists()
    assert not (model_dir / "provider_01.pcap.partial").exists()
    assert not (model_dir / "provider_01.pcap").exists()

    with pytest.raises(CaptureError):
        runner.collect("model", "provider")
    failure_logs = list((model_dir / "failures").glob("provider_*.log"))
    assert len(failure_logs) == 2
    assert not (model_dir / "provider_02").exists()


def test_dry_run_validates_without_reserving_or_exposing_key(tmp_path: Path) -> None:
    settings = _fixture(tmp_path)

    output = CaptureRunner(settings).dry_run("model", "provider")

    assert "no ID reserved" in output
    assert "PROVIDER_KEY (set)" in output
    assert "TELEGENT_PROMPTS_FILE=<not set; sequence default applies>" in output
    assert "TELEGENT_REQUEST_INTERVAL_SECONDS=0" in output
    assert "top-secret" not in output
    assert not settings.capture_root.exists()


def test_unsupported_agent_has_no_workload_fallback(tmp_path: Path) -> None:
    settings = _fixture(tmp_path)
    target = AgentTarget(
        agent="codex",
        model="model",
        provider="provider",
        config_directory=tmp_path,
        config_path=tmp_path / "config.toml",
        configured_model="configured-model",
        credential_environment_variables=(),
    )
    object.__setattr__(target, "agent", "unsupported")

    with pytest.raises(NotImplementedError, match="workload command.*unsupported"):
        CaptureRunner(settings)._workload_command(target)


def test_interruption_cleans_up_without_tail_delay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _fixture(tmp_path, tail=10)

    def interrupt(_: float) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr("telegent.collector.runner.sleep", interrupt)
    with pytest.raises(CaptureError, match="interrupted") as raised:
        CaptureRunner(settings).collect("model", "provider")

    assert raised.value.interrupted
    assert raised.value.failure_log_path is not None
    assert not (settings.capture_root / "model/provider_01").exists()
