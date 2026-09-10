from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from telegent import CaptureSettings
from telegent.collector.storage import preserve_failure, reserve_capture


def _settings(tmp_path: Path) -> CaptureSettings:
    return CaptureSettings(
        capture_root=tmp_path,
        codex_config_root=tmp_path,
        sequence_script=tmp_path,
        codex_binary=tmp_path,
        capture_interface="eth0",
        capture_filter="port 443",
        tail_seconds=0,
        capture_start_timeout_seconds=1,
        tshark_binary=tmp_path,
        environment={},
    )


def test_ids_are_provider_specific_expand_above_99_and_reuse_failures(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    model_dir = tmp_path / "model"
    model_dir.mkdir()
    for capture_id in range(1, 101):
        (model_dir / f"provider_{capture_id:02d}").mkdir()

    reservation = reserve_capture(settings, "model", "provider")
    other_provider = reserve_capture(settings, "model", "other")

    assert reservation.capture_label == "provider_101"
    assert other_provider.capture_label == "other_01"
    reservation.capture_log_path.write_text("details\n", encoding="utf-8")
    failure = preserve_failure(reservation, "failed", "20260909T120000")
    reused = reserve_capture(settings, "model", "provider")
    assert failure.name == "provider_20260909T120000.log"
    assert reused.capture_label == "provider_101"


def test_concurrent_reservations_are_unique(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    with ThreadPoolExecutor(max_workers=8) as executor:
        reservations = list(
            executor.map(lambda _: reserve_capture(settings, "model", "provider"), range(20))
        )

    assert sorted(item.capture_id for item in reservations) == list(range(1, 21))
