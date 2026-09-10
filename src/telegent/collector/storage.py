"""Atomic capture ID reservation and artifact finalization."""

import json
import os
import shutil
from dataclasses import dataclass
from pathlib import Path

from ..errors import CaptureError
from .settings import CaptureSettings


@dataclass(frozen=True)
class CaptureReservation:
    capture_id: int
    capture_label: str
    model_directory: Path
    run_directory: Path
    partial_pcap_path: Path
    pcap_path: Path
    ssl_keylog_path: Path
    capture_log_path: Path
    metadata_path: Path


def reserve_capture(
    settings: CaptureSettings, model: str, provider: str
) -> CaptureReservation:
    """Atomically reserve the lowest available provider-specific capture ID."""

    model_directory = settings.capture_root / model
    try:
        model_directory.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise CaptureError(f"could not create capture directory: {error}") from error

    capture_id = 1
    while True:
        capture_label = f"{provider}_{capture_id:02d}"
        run_directory = model_directory / capture_label
        pcap_path = model_directory / f"{capture_label}.pcap"
        partial_pcap_path = model_directory / f"{capture_label}.pcap.partial"
        if pcap_path.exists() or partial_pcap_path.exists():
            capture_id += 1
            continue
        try:
            run_directory.mkdir()
        except FileExistsError:
            capture_id += 1
            continue
        except OSError as error:
            raise CaptureError(f"could not reserve capture ID: {error}") from error
        return CaptureReservation(
            capture_id=capture_id,
            capture_label=capture_label,
            model_directory=model_directory,
            run_directory=run_directory,
            partial_pcap_path=partial_pcap_path,
            pcap_path=pcap_path,
            ssl_keylog_path=model_directory / "sslkeys.key",
            capture_log_path=run_directory / "capture.log",
            metadata_path=run_directory / "capture.json",
        )


def finalize_capture(reservation: CaptureReservation, metadata: dict[str, object]) -> None:
    """Atomically publish the pcap and metadata after successful shutdown."""

    if not reservation.partial_pcap_path.is_file():
        raise CaptureError(
            f"tshark did not create a capture: {reservation.partial_pcap_path}"
        )
    if reservation.partial_pcap_path.stat().st_size == 0:
        raise CaptureError("tshark created an empty capture")
    try:
        os.replace(reservation.partial_pcap_path, reservation.pcap_path)
        temporary_metadata = reservation.metadata_path.with_suffix(".json.partial")
        with temporary_metadata.open("x", encoding="utf-8") as output:
            json.dump(metadata, output, indent=2, sort_keys=True)
            output.write("\n")
        os.replace(temporary_metadata, reservation.metadata_path)
    except OSError as error:
        raise CaptureError(f"could not finalize capture artifacts: {error}") from error


def preserve_failure(
    reservation: CaptureReservation, message: str, timestamp: str
) -> Path:
    """Move the run log out of a failed reservation and make its ID reusable."""

    failures = reservation.model_directory / "failures"
    try:
        failures.mkdir(parents=True, exist_ok=True)
        base_name = f"{reservation.capture_label.rsplit('_', 1)[0]}_{timestamp}.log"
        failure_path = _exclusive_path(failures, base_name)
        if reservation.capture_log_path.exists():
            with reservation.capture_log_path.open("a", encoding="utf-8") as output:
                output.write(f"\nerror: {message}\n")
            os.replace(reservation.capture_log_path, failure_path)
        else:
            failure_path.write_text(f"error: {message}\n", encoding="utf-8")
    finally:
        reservation.partial_pcap_path.unlink(missing_ok=True)
        reservation.pcap_path.unlink(missing_ok=True)
        shutil.rmtree(reservation.run_directory, ignore_errors=True)
    return failure_path


def _exclusive_path(directory: Path, base_name: str) -> Path:
    candidate = directory / base_name
    suffix = 2
    while True:
        try:
            descriptor = os.open(candidate, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            candidate = directory / f"{Path(base_name).stem}_{suffix}.log"
            suffix += 1
            continue
        os.close(descriptor)
        return candidate
