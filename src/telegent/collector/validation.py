"""Capture-specific validation layered on shared agent configuration."""

import os
from pathlib import Path

from ..configuration import AgentTarget, CaptureSettings, load_target, load_targets
from ..errors import CaptureError


def validate_all_targets(settings: CaptureSettings, model: str) -> list[AgentTarget]:
    """Load every provider target and validate capture executables."""

    targets = load_targets(
        settings.agent,
        settings.agent_config_root,
        settings.environment,
        model,
    )
    _validate_capture_executables(settings)
    return targets


def validate_target(
    settings: CaptureSettings, model: str, provider: str
) -> AgentTarget:
    """Load one provider target and validate capture executables."""

    target = load_target(
        settings.agent,
        settings.agent_config_root,
        settings.environment,
        model,
        provider,
    )
    _validate_capture_executables(settings)
    return target


def _validate_capture_executables(settings: CaptureSettings) -> None:
    for label, path in (
        ("tshark binary", settings.tshark_binary),
        ("sequence script", settings.sequence_script),
        (f"{settings.agent} binary", settings.agent_binary),
    ):
        _validate_executable(path, label)


def _validate_executable(path: Path, label: str) -> None:
    if not path.is_file():
        raise CaptureError(f"{label} does not exist: {path}")
    if not os.access(path, os.X_OK):
        raise CaptureError(f"{label} is not executable: {path}")
