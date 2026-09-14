"""Process startup, readiness detection, logging, and bounded shutdown."""

import os
import signal
import subprocess
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import IO, Any

from ..errors import CaptureError

# Four-byte file signatures for pcapng and classic pcap byte-order variants.
_PCAP_MAGICS = {
    b"\x0a\x0d\x0d\x0a",
    b"\xa1\xb2\xc3\xd4",
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
    b"\x4d\x3c\xb2\xa1",
}


@dataclass(frozen=True)
class ProcessResult:
    command: tuple[str, ...]
    pid: int
    started_at: str
    ended_at: str
    returncode: int
    termination: str


class CaptureLog:
    """Serialize output from concurrent tshark and workload reader threads."""

    def __init__(self, path: Path) -> None:
        self._output = path.open("x", encoding="utf-8", buffering=1)
        self._lock = threading.Lock()

    def write(self, source: str, text: str) -> None:
        with self._lock:
            for line in text.splitlines(keepends=True):
                self._output.write(f"[{source}] {line}")
            if text and not text.endswith("\n"):
                self._output.write("\n")

    def close(self) -> None:
        with self._lock:
            self._output.close()


@dataclass
class ManagedProcess:
    process: Any
    command: tuple[str, ...]
    started_at: str
    output_thread: threading.Thread | None = None


def start_tshark(
    command: Sequence[str],
    pcap_path: Path,
    capture_log: CaptureLog,
    timeout: float,
    *,
    popen: Callable[..., Any] = subprocess.Popen,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    header_stability_seconds: float = 0.2,
) -> ManagedProcess:
    """Start tshark and wait for a message or stable pcap header readiness signal."""

    ready = threading.Event()
    try:
        process = popen(
            list(command),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            start_new_session=True,
        )
    except OSError as error:
        raise CaptureError(f"could not start tshark: {error}") from error
    started_at = _timestamp()
    thread = threading.Thread(
        target=_copy_output,
        args=(process.stderr, capture_log, "tshark", ready),
        daemon=True,
    )
    thread.start()
    managed = ManagedProcess(process, tuple(command), started_at, thread)
    deadline = monotonic() + timeout
    header_seen_at: float | None = None
    while True:
        if ready.is_set():
            return managed
        returncode = process.poll()
        if returncode is not None:
            thread.join(timeout=1)
            raise CaptureError(f"tshark exited before capture was ready ({returncode})")
        now = monotonic()
        if _has_pcap_header(pcap_path):
            header_seen_at = header_seen_at or now
            if now - header_seen_at >= header_stability_seconds:
                return managed
        else:
            header_seen_at = None
        if now >= deadline:
            stop_process(managed, signal.SIGINT)
            raise CaptureError(f"tshark was not ready within {timeout:g} seconds")
        sleep(min(0.05, max(0.0, deadline - now)))


def start_workload(
    command: Sequence[str],
    environment: dict[str, str],
    capture_log: CaptureLog,
    *,
    popen: Callable[..., Any] = subprocess.Popen,
) -> ManagedProcess:
    try:
        process = popen(
            list(command),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env=environment,
            start_new_session=True,
        )
    except OSError as error:
        raise CaptureError(f"could not start Codex sequence: {error}") from error
    thread = threading.Thread(
        target=_copy_output,
        args=(process.stdout, capture_log, "agent", None),
        daemon=True,
    )
    thread.start()
    return ManagedProcess(process, tuple(command), _timestamp(), thread)


def wait_process(managed: ManagedProcess) -> ProcessResult:
    returncode = managed.process.wait()
    _join_output(managed)
    return _result(managed, returncode, "exited")


def stop_process(
    managed: ManagedProcess,
    first_signal: signal.Signals,
    *,
    graceful_timeout: float = 5,
    terminate_timeout: float = 3,
    kill_timeout: float = 2,
) -> ProcessResult:
    """Stop a process group using bounded graceful, TERM, and KILL phases."""

    returncode = managed.process.poll()
    termination = "already exited"
    if returncode is None:
        termination = first_signal.name
        _signal_group(managed.process, first_signal)
        returncode = _wait_bounded(managed.process, graceful_timeout)
    if returncode is None:
        termination = signal.SIGTERM.name
        _signal_group(managed.process, signal.SIGTERM)
        returncode = _wait_bounded(managed.process, terminate_timeout)
    if returncode is None:
        termination = signal.SIGKILL.name
        _signal_group(managed.process, signal.SIGKILL)
        returncode = _wait_bounded(managed.process, kill_timeout)
    if returncode is None:
        raise CaptureError(f"process {managed.process.pid} did not stop after SIGKILL")
    _join_output(managed)
    return _result(managed, returncode, termination)


def process_result_dict(result: ProcessResult) -> dict[str, object]:
    return {
        "command": list(result.command),
        "pid": result.pid,
        "started_at": result.started_at,
        "ended_at": result.ended_at,
        "returncode": result.returncode,
        "termination": result.termination,
    }


def _copy_output(
    stream: IO[str] | None,
    capture_log: CaptureLog,
    source: str,
    ready: threading.Event | None,
) -> None:
    if stream is None:
        return
    for line in stream:
        capture_log.write(source, line)
        if ready is not None and "Capture started" in line:
            ready.set()
    stream.close()


def _has_pcap_header(path: Path) -> bool:
    try:
        with path.open("rb") as capture:
            return capture.read(4) in _PCAP_MAGICS
    except OSError:
        return False


def _wait_bounded(process: Any, timeout: float) -> int | None:
    try:
        return process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        return None


def _signal_group(process: Any, requested_signal: signal.Signals) -> None:
    try:
        os.killpg(process.pid, requested_signal)
    except (OSError, ProcessLookupError):
        try:
            process.send_signal(requested_signal)
        except ProcessLookupError:
            pass


def _join_output(managed: ManagedProcess) -> None:
    if managed.output_thread is not None:
        managed.output_thread.join(timeout=2)


def _result(managed: ManagedProcess, returncode: int, termination: str) -> ProcessResult:
    return ProcessResult(
        command=managed.command,
        pid=managed.process.pid,
        started_at=managed.started_at,
        ended_at=_timestamp(),
        returncode=returncode,
        termination=termination,
    )


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()
