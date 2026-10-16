"""Run configured providers through their actual agents."""

import json
import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from time import perf_counter
from typing import Literal

from ..configuration import (
    AgentTarget,
    ProbeSettings,
    discover_providers,
    load_target,
)
from ..errors import ConfigurationError, TelegentError


@dataclass(frozen=True)
class ProbeResult:
    provider: str
    status: Literal["PASS", "FAIL", "READY"]
    detail: str
    elapsed_ms: float | None = None


class EndpointProbe:
    """Test each configured provider through the selected agent binary."""

    def __init__(self, settings: ProbeSettings) -> None:
        self.settings = settings

    def run(
        self, model: str, provider: str | None = None, *, dry_run: bool = False
    ) -> list[ProbeResult]:
        if self.settings.agent == "opencode":
            invoke = self._invoke_opencode
        elif self.settings.agent == "codex":
            invoke = self._invoke_codex
        else:
            raise NotImplementedError(
                f"agent probing is not implemented for agent {self.settings.agent!r}"
            )
        names = discover_providers(
            self.settings.agent, self.settings.agent_config_root, model
        )
        if provider is not None:
            if provider not in names:
                raise TelegentError(f"provider {provider!r} is not configured for {model!r}")
            names = [provider]
        results = []
        for name in names:
            try:
                target = load_target(
                    self.settings.agent,
                    self.settings.agent_config_root,
                    self.settings.environment,
                    model,
                    name,
                )
            except ConfigurationError as error:
                results.append(ProbeResult(name, "FAIL", str(error)))
                continue
            detail = _target_detail(target)
            if dry_run:
                results.append(ProbeResult(name, "READY", detail))
                continue
            started = perf_counter()
            passed, reason = invoke(target)
            results.append(
                ProbeResult(
                    name,
                    "PASS" if passed else "FAIL",
                    f"{detail}; {reason}",
                    (perf_counter() - started) * 1000,
                )
            )
        return results

    def _invoke_codex(self, target: AgentTarget) -> tuple[bool, str]:
        binary = self.settings.agent_binary
        if not binary.is_file() or not os.access(binary, os.X_OK):
            return False, f"Codex binary is not executable: {binary}"
        environment = dict(self.settings.environment)
        environment["CODEX_HOME"] = str(target.config_directory)
        command = [str(binary), "exec", "-p", target.provider]
        if target.model_catalog is not None:
            command.extend(["-c", f'model_catalog_json="{target.model_catalog}"'])
        command.extend(["--json", "-s", "read-only", "--skip-git-repo-check", "Hi"])
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                env=environment,
                cwd=self.settings.working_directory,
                timeout=self.settings.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return False, f"Codex timed out after {self.settings.timeout_seconds:g} seconds"
        except OSError as error:
            return False, f"could not start Codex: {error}"
        events = _json_events(completed.stdout)
        if completed.returncode != 0:
            return False, f"Codex exited with status {completed.returncode}"
        if any(
            event.get("type") == "item.completed"
            and isinstance(event.get("item"), dict)
            and event["item"].get("type") == "error"
            for event in events
        ):
            return False, "Codex emitted an error event"
        if not any(event.get("type") == "turn.completed" for event in events):
            return False, "Codex did not complete the turn"
        if not any(
            event.get("type") == "item.completed"
            and isinstance(event.get("item"), dict)
            and event["item"].get("type") == "agent_message"
            and isinstance(event["item"].get("text"), str)
            for event in events
        ):
            return False, "Codex did not emit a text response"
        return True, "completed a minimal Codex prompt"

    def _invoke_opencode(self, target: AgentTarget) -> tuple[bool, str]:
        binary = self.settings.agent_binary
        if not binary.is_file() or not os.access(binary, os.X_OK):
            return False, f"OpenCode binary is not executable: {binary}"
        with tempfile.TemporaryDirectory(prefix="telegent-opencode-probe-") as temporary:
            state_root = Path(temporary)
            environment = dict(self.settings.environment)
            for name, leaf in (
                ("XDG_CONFIG_HOME", "config"),
                ("XDG_DATA_HOME", "data"),
                ("XDG_STATE_HOME", "state"),
                ("XDG_CACHE_HOME", "cache"),
            ):
                path = state_root / leaf
                path.mkdir()
                environment[name] = str(path)
            environment.update(
                {
                    "OPENCODE_CONFIG_CONTENT": target.inline_config or "{}",
                    "OPENCODE_DISABLE_PROJECT_CONFIG": "1",
                    "OPENCODE_PURE": "1",
                    "OPENCODE_DISABLE_AUTOUPDATE": "1",
                    "OPENCODE_DISABLE_AUTOCOMPACT": "1",
                    "OPENCODE_DISABLE_MODELS_FETCH": "1",
                    "OPENCODE_AUTH_CONTENT": "{}",
                }
            )
            command = [
                str(binary),
                "run",
                "--pure",
                "--format",
                "json",
                "--model",
                target.configured_model,
                "--dir",
                str(self.settings.working_directory),
                "Hi",
            ]
            try:
                completed = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    env=environment,
                    cwd=self.settings.working_directory,
                    timeout=self.settings.timeout_seconds,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                return False, f"OpenCode timed out after {self.settings.timeout_seconds:g} seconds"
            except OSError as error:
                return False, f"could not start OpenCode: {error}"
        events = _json_events(completed.stdout)
        if completed.returncode != 0:
            return False, f"OpenCode exited with status {completed.returncode}"
        if any(event.get("type") == "error" for event in events):
            return False, "OpenCode emitted an error event"
        if not any(
            event.get("type") == "text"
            and isinstance(event.get("part"), dict)
            and isinstance(event["part"].get("text"), str)
            for event in events
        ):
            return False, "OpenCode did not emit a text response"
        return True, "completed a minimal OpenCode prompt"


def _target_detail(target: AgentTarget) -> str:
    credentials = ", ".join(target.credential_environment_variables) or "none"
    return (
        f"{target.configured_model} via {target.config_path} "
        f"(environment: {credentials})"
    )


def _json_events(output: str) -> list[dict]:
    events = []
    for line in output.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict):
            events.append(event)
    return events
