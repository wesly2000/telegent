import signal
import subprocess
from pathlib import Path

import pytest

from telegent import CaptureError
from telegent.collector.process import CaptureLog, ManagedProcess, start_tshark, stop_process


def _script(tmp_path: Path, body: str) -> Path:
    path = tmp_path / f"script-{len(list(tmp_path.iterdir()))}.py"
    path.write_text(f"#!/usr/bin/python3\n{body}", encoding="utf-8")
    path.chmod(0o755)
    return path


def _command(script: Path, pcap: Path) -> list[str]:
    return [str(script), "-w", str(pcap)]


def test_readiness_from_stderr(tmp_path: Path) -> None:
    script = _script(
        tmp_path,
        "import signal, sys, time\n"
        "open(sys.argv[-1], 'wb').write(b'\\x0a\\x0d\\x0d\\x0a')\n"
        "print('Capture started', file=sys.stderr, flush=True)\n"
        "signal.signal(signal.SIGINT, lambda *_: sys.exit(0))\n"
        "while True: time.sleep(0.05)\n",
    )
    capture_log = CaptureLog(tmp_path / "capture.log")
    managed = start_tshark(_command(script, tmp_path / "ready.pcap"), tmp_path / "ready.pcap", capture_log, 1)

    result = stop_process(managed, signal.SIGINT)
    capture_log.close()
    assert result.returncode == 0
    assert "Capture started" in (tmp_path / "capture.log").read_text(encoding="utf-8")


def test_readiness_from_stable_pcap_header(tmp_path: Path) -> None:
    script = _script(
        tmp_path,
        "import signal, sys, time\n"
        "open(sys.argv[-1], 'wb').write(b'\\xd4\\xc3\\xb2\\xa1')\n"
        "signal.signal(signal.SIGINT, lambda *_: sys.exit(0))\n"
        "while True: time.sleep(0.05)\n",
    )
    capture_log = CaptureLog(tmp_path / "capture.log")
    managed = start_tshark(
        _command(script, tmp_path / "fallback.pcap"),
        tmp_path / "fallback.pcap",
        capture_log,
        1,
        header_stability_seconds=0.05,
    )

    assert stop_process(managed, signal.SIGINT).returncode == 0
    capture_log.close()


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ("import sys\nprint('bad filter', file=sys.stderr)\nsys.exit(2)\n", "exited before"),
        ("import time\nwhile True: time.sleep(0.05)\n", "was not ready"),
    ],
)
def test_startup_failure_modes(tmp_path: Path, body: str, message: str) -> None:
    script = _script(tmp_path, body)
    capture_log = CaptureLog(tmp_path / "capture.log")

    with pytest.raises(CaptureError, match=message):
        start_tshark(
            _command(script, tmp_path / "failed.pcap"),
            tmp_path / "failed.pcap",
            capture_log,
            0.15,
        )
    capture_log.close()


def test_shutdown_escalates_from_graceful_signal_to_term() -> None:
    class FakeProcess:
        pid = 999_999_999

        def __init__(self) -> None:
            self.signals: list[signal.Signals] = []
            self.waits = 0

        def poll(self) -> None:
            return None

        def send_signal(self, sent_signal: signal.Signals) -> None:
            self.signals.append(sent_signal)

        def wait(self, timeout: float) -> int:
            self.waits += 1
            if self.waits == 1:
                raise subprocess.TimeoutExpired("fake", timeout)
            return 0

    process = FakeProcess()
    managed = ManagedProcess(process, ("fake",), "start")

    result = stop_process(managed, signal.SIGINT, graceful_timeout=0, terminate_timeout=0)

    assert process.signals == [signal.SIGINT, signal.SIGTERM]
    assert result.termination == "SIGTERM"
    assert result.returncode == 0
