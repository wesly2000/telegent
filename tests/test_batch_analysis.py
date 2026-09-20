from pathlib import Path

import pytest

from telegent.cli import main


class FakeAnalyzer:
    calls: list[tuple[Path, Path]] = []

    def analyze_capture(
        self, pcap_path: Path | str, keylog_path: Path | str
    ) -> list[object]:
        self.calls.append((Path(pcap_path), Path(keylog_path)))
        return []


def test_batch_analysis_creates_timing_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    capture_dir = tmp_path / "captures"
    capture_dir.mkdir()
    (capture_dir / "official_01.pcap").touch()
    (capture_dir / "sslkeys.key").touch()
    analysis_dir = tmp_path / "analysis"

    FakeAnalyzer.calls = []
    monkeypatch.setattr("telegent.cli.TsharkAnalyzer", FakeAnalyzer)

    result = main(
        [
            "analyze",
            "--capture-dir",
            str(capture_dir),
            "--analysis-dir",
            str(analysis_dir),
        ]
    )

    assert result == 0
    assert (analysis_dir / "timing/official_01.csv").is_file()


def test_batch_analysis_writes_one_csv_per_new_pcap_and_skips_existing(
    tmp_path: Path, capsys: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    capture_dir = tmp_path / "captures"
    capture_dir.mkdir()
    for name in ("openrouter_02.pcap", "openrouter_01.pcap", "official_01.pcap"):
        (capture_dir / name).touch()
    (capture_dir / "sslkeys.key").touch()
    (capture_dir / "unfinished.pcap.partial").touch()
    nested = capture_dir / "nested"
    nested.mkdir()
    (nested / "nested.pcap").touch()

    analysis_dir = tmp_path / "analysis"
    timing_dir = analysis_dir / "timing"
    timing_dir.mkdir(parents=True)
    existing = timing_dir / "openrouter_01.csv"
    existing.write_text("existing result\n", encoding="utf-8")

    FakeAnalyzer.calls = []
    monkeypatch.setattr("telegent.cli.TsharkAnalyzer", FakeAnalyzer)

    result = main(
        [
            "analyze",
            "--capture-dir",
            str(capture_dir),
            "--analysis-dir",
            str(analysis_dir),
        ]
    )

    assert result == 0
    assert FakeAnalyzer.calls == [
        (capture_dir / "official_01.pcap", capture_dir / "sslkeys.key"),
        (capture_dir / "openrouter_02.pcap", capture_dir / "sslkeys.key"),
    ]
    assert sorted(path.name for path in timing_dir.iterdir()) == [
        "official_01.csv",
        "openrouter_01.csv",
        "openrouter_02.csv",
    ]
    assert existing.read_text(encoding="utf-8") == "existing result\n"
    assert (timing_dir / "official_01.csv").read_text(encoding="utf-8").startswith(
        "capture_path,sni,http_version"
    )
    output = capsys.readouterr().out  # type: ignore[attr-defined]
    assert f"skipped {capture_dir / 'openrouter_01.pcap'}" in output
    assert "batch analysis complete: 2 analyzed, 1 skipped" in output


@pytest.mark.parametrize(
    "arguments",
    [
        ["--capture-dir", "captures", "--output", "timings.csv"],
        ["--input", "capture.pcap", "keys.log", "--analysis-dir", "analysis"],
    ],
)
def test_analysis_input_and_output_modes_must_match(arguments: list[str]) -> None:
    with pytest.raises(SystemExit) as raised:
        main(["analyze", *arguments])

    assert raised.value.code == 2
