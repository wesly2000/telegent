"""High-level automated agent traffic collection."""

import shlex
import signal
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from time import sleep

from ..configuration import AgentTarget, CaptureSettings
from ..errors import CaptureError
from .process import CaptureLog
from .process import ManagedProcess
from .process import ProcessResult
from .process import process_result_dict
from .process import start_tshark
from .process import start_workload
from .process import stop_process
from .process import wait_process
from .storage import CaptureReservation
from .storage import finalize_capture
from .storage import preserve_failure
from .storage import reserve_capture
from .validation import validate_target


@dataclass(frozen=True)
class CaptureResult:
    capture_id: int
    model: str
    provider: str
    run_directory: Path
    pcap_path: Path
    ssl_keylog_path: Path
    capture_log_path: Path
    metadata_path: Path
    started_at: str
    ended_at: str
    agent_process: ProcessResult
    tshark_process: ProcessResult


class CaptureRunner:
    """Validate and collect one agent sequence capture on POSIX systems."""

    def __init__(self, settings: CaptureSettings) -> None:
        self.settings = settings

    def dry_run(self, model: str, provider: str) -> str:
        """Validate a capture and describe it without reserving an ID."""

        target = validate_target(self.settings, model, provider)
        prompts_file = self.settings.environment.get(
            "TELEGENT_PROMPTS_FILE", "<not set; sequence default applies>"
        )
        partial = self.settings.capture_root / model / f"{provider}_<id>.pcap.partial"
        tshark_command = self._tshark_command(partial)
        workload_command = self._workload_command(target)
        credential_names = ", ".join(
            f"{name} (set)" for name in target.credential_environment_variables
        )
        lines = (
            "capture dry run (no ID reserved)",
            f"dotenv file: {self.settings.env_file or '<not loaded>'}",
            f"agent: {self.settings.agent}",
            f"model: {model}",
            f"provider: {provider}",
            f"configured model: {target.configured_model}",
            f"TELEGENT_AGENT_CONFIG_ROOT={self.settings.agent_config_root}",
            f"selected config: {target.config_path}",
            f"TELEGENT_CAPTURE_ROOT={self.settings.capture_root}",
            f"TLS key log: {self.settings.capture_root / model / 'sslkeys.key'}",
            f"TELEGENT_SEQUENCE_SCRIPT={self.settings.sequence_script}",
            f"TELEGENT_PROMPTS_FILE={prompts_file}",
            f"TELEGENT_AGENT_BINARY={self.settings.agent_binary}",
            f"TELEGENT_TSHARK_BINARY={self.settings.tshark_binary}",
            f"TELEGENT_CAPTURE_INTERFACE={self.settings.capture_interface}",
            f"TELEGENT_CAPTURE_FILTER={self.settings.capture_filter}",
            f"TELEGENT_TAIL_SECONDS={self.settings.tail_seconds:g}",
            "TELEGENT_REQUEST_INTERVAL_SECONDS="
            f"{self.settings.request_interval_seconds:g}",
            "TELEGENT_CAPTURE_START_TIMEOUT_SECONDS="
            f"{self.settings.capture_start_timeout_seconds:g}",
            f"credential environment variables: {credential_names or '<none>'}",
            f"tshark command: {shlex.join(tshark_command)}",
            f"workload command: {shlex.join(workload_command)}",
        )
        return "\n".join(lines)

    def collect(self, model: str, provider: str) -> CaptureResult:
        """Capture one configured agent workload and publish its artifacts."""

        target = validate_target(self.settings, model, provider)
        reservation = reserve_capture(self.settings, model, provider)
        started_at = _timestamp()
        capture_log: CaptureLog | None = None
        tshark: ManagedProcess | None = None
        workload: ManagedProcess | None = None
        try:
            reservation.ssl_keylog_path.touch(mode=0o600, exist_ok=True)
            reservation.ssl_keylog_path.chmod(0o600)
            capture_log = CaptureLog(reservation.capture_log_path)
            tshark_command = self._tshark_command(reservation.partial_pcap_path)
            workload_command = self._workload_command(target)
            capture_log.write("telegent", f"tshark command: {shlex.join(tshark_command)}\n")
            capture_log.write(
                "telegent", f"workload command: {shlex.join(workload_command)}\n"
            )
            tshark = start_tshark(
                tshark_command,
                reservation.partial_pcap_path,
                capture_log,
                self.settings.capture_start_timeout_seconds,
            )
            workload = start_workload(
                workload_command,
                self._child_environment(target, reservation),
                capture_log,
            )
            agent_result = wait_process(workload)
            if agent_result.returncode != 0:
                raise CaptureError(
                    f"{self.settings.agent} sequence exited with status "
                    f"{agent_result.returncode}"
                )
            sleep(self.settings.tail_seconds)
            tshark_result = stop_process(tshark, signal.SIGINT)
            if tshark_result.returncode != 0:
                raise CaptureError(
                    "tshark did not close the capture successfully "
                    f"(status {tshark_result.returncode}, {tshark_result.termination})"
                )
            ended_at = _timestamp()
            capture_log.close()
            capture_log = None
            result = CaptureResult(
                capture_id=reservation.capture_id,
                model=model,
                provider=provider,
                run_directory=reservation.run_directory,
                pcap_path=reservation.pcap_path,
                ssl_keylog_path=reservation.ssl_keylog_path,
                capture_log_path=reservation.capture_log_path,
                metadata_path=reservation.metadata_path,
                started_at=started_at,
                ended_at=ended_at,
                agent_process=agent_result,
                tshark_process=tshark_result,
            )
            finalize_capture(reservation, self._metadata(result, target))
            return result
        except (Exception, KeyboardInterrupt) as error:
            interrupted = isinstance(error, KeyboardInterrupt)
            self._stop_failed_process(workload, signal.SIGTERM)
            self._stop_failed_process(tshark, signal.SIGINT)
            if capture_log is not None:
                capture_log.close()
            message = "capture interrupted" if interrupted else str(error)
            try:
                failure_path = preserve_failure(
                    reservation, message, datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
                )
            except OSError as cleanup_error:
                raise CaptureError(
                    f"{message}; additionally failed to preserve the failure log: "
                    f"{cleanup_error}",
                    interrupted=interrupted,
                ) from error
            raise CaptureError(
                message, failure_path, interrupted=interrupted
            ) from error

    def _tshark_command(self, pcap_path: Path) -> list[str]:
        return [
            str(self.settings.tshark_binary),
            "-i",
            self.settings.capture_interface,
            "-f",
            self.settings.capture_filter,
            "-w",
            str(pcap_path),
        ]

    def _workload_command(self, target: AgentTarget) -> list[str]:
        command = [str(self.settings.sequence_script), str(self.settings.agent_binary)]
        if target.agent == "opencode":
            return command + [target.configured_model, str(self.settings.working_directory)]
        elif target.agent == "codex":
            return command + [target.provider]
        else:
            raise NotImplementedError(
                f"workload command is not implemented for agent {target.agent!r}"
            )

    def _child_environment(
        self, target: AgentTarget, reservation: CaptureReservation
    ) -> dict[str, str]:
        environment = dict(self.settings.environment)
        environment.update(
            {
                "SSLKEYLOGFILE": str(reservation.ssl_keylog_path),
                "TELEGENT_AGENT_OUTPUT_DIR": str(reservation.run_directory / "agent"),
                "TELEGENT_REQUEST_INTERVAL_SECONDS": (
                    f"{self.settings.request_interval_seconds:g}"
                ),
            }
        )
        if target.agent == "codex":
            environment["CODEX_HOME"] = str(target.config_directory)
            if target.model_catalog is not None:
                environment["TELEGENT_CODEX_MODEL_CATALOG"] = str(target.model_catalog)
        elif target.agent == "opencode":
            state_root = reservation.run_directory / "agent-state"
            xdg_paths = {
                "XDG_CONFIG_HOME": state_root / "config",
                "XDG_DATA_HOME": state_root / "data",
                "XDG_STATE_HOME": state_root / "state",
                "XDG_CACHE_HOME": state_root / "cache",
            }
            for path in xdg_paths.values():
                path.mkdir(parents=True, exist_ok=True)
            environment.update({name: str(path) for name, path in xdg_paths.items()})
            environment.update(
                {
                    "OPENCODE_CONFIG_CONTENT": target.inline_config or "{}",
                    "OPENCODE_DISABLE_PROJECT_CONFIG": "1",
                    "OPENCODE_DISABLE_AUTOUPDATE": "1",
                    "OPENCODE_DISABLE_AUTOCOMPACT": "1",
                    "OPENCODE_DISABLE_MODELS_FETCH": "1",
                    "OPENCODE_AUTH_CONTENT": "{}",
                }
            )
        else:
            raise NotImplementedError(
                f"child environment is not implemented for agent {target.agent!r}"
            )
        return environment

    def _metadata(
        self, result: CaptureResult, target: AgentTarget
    ) -> dict[str, object]:
        if target.agent == "opencode":
            isolated_state_path = str(result.run_directory / "agent-state")
        elif target.agent == "codex":
            isolated_state_path = None
        else:
            raise NotImplementedError(
                f"capture metadata is not implemented for agent {target.agent!r}"
            )
        return {
            "capture_id": result.capture_id,
            "agent": target.agent,
            "model": result.model,
            "provider": result.provider,
            "configured_model": target.configured_model,
            "started_at": result.started_at,
            "ended_at": result.ended_at,
            "configuration": {
                "capture_interface": self.settings.capture_interface,
                "capture_filter": self.settings.capture_filter,
                "tail_seconds": self.settings.tail_seconds,
                "request_interval_seconds": self.settings.request_interval_seconds,
                "capture_start_timeout_seconds": (
                    self.settings.capture_start_timeout_seconds
                ),
                "agent_config_root": str(self.settings.agent_config_root),
                "selected_config": str(target.config_path),
                "sequence_script": str(self.settings.sequence_script),
                "agent_binary": str(self.settings.agent_binary),
                "tshark_binary": str(self.settings.tshark_binary),
                "credential_environment_variables": list(
                    target.credential_environment_variables
                ),
                "isolated_state_path": isolated_state_path,
            },
            "artifacts": {
                "run_directory": str(result.run_directory),
                "pcap": str(result.pcap_path),
                "ssl_keylog": str(result.ssl_keylog_path),
                "capture_log": str(result.capture_log_path),
                "agent_output_directory": str(result.run_directory / "agent"),
            },
            "processes": {
                "agent": process_result_dict(result.agent_process),
                "tshark": process_result_dict(result.tshark_process),
            },
        }

    @staticmethod
    def _stop_failed_process(
        managed: ManagedProcess | None, first_signal: signal.Signals
    ) -> None:
        if managed is None:
            return
        try:
            stop_process(managed, first_signal)
        except CaptureError:
            pass


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()
