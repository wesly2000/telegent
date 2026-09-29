from pathlib import Path

import pytest

from telegent.cli import main


def test_metric_cli_reads_dotenv_and_reports_update(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    analysis_root = tmp_path / "analysis"
    source_path = analysis_root / "chat/deepseek/timing/official_01.csv"
    source_path.parent.mkdir(parents=True)
    source_path.write_text("latency_ms\n10\n20\n", encoding="utf-8")
    database_path = tmp_path / "metrics.csv"
    env_file = tmp_path / "metrics.env"
    env_file.write_text(
        f"TELEGENT_ANALYSIS_ROOT={analysis_root}\n"
        f"TELEGENT_METRICS_DB={database_path}\n",
        encoding="utf-8",
    )
    monkeypatch.delenv("TELEGENT_ANALYSIS_ROOT", raising=False)
    monkeypatch.delenv("TELEGENT_METRICS_DB", raising=False)

    result = main(
        [
            "metric",
            "--input",
            str(source_path),
            "--column",
            "latency_ms",
            "--operator",
            "mean",
            "--env-file",
            str(env_file),
        ]
    )

    assert result == 0
    assert database_path.read_text(encoding="utf-8").splitlines() == [
        "source_id,mean__latency_ms",
        "chat/deepseek/timing/official_01.csv,15.0",
    ]
    output = capsys.readouterr().out
    assert "source: chat/deepseek/timing/official_01.csv" in output
    assert "metric: mean__latency_ms" in output
    assert "value: 15.0" in output
    assert f"database: {database_path}" in output


def test_metric_cli_failure_does_not_change_database(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    analysis_root = tmp_path / "analysis"
    source_path = analysis_root / "timing/official_01.csv"
    source_path.parent.mkdir(parents=True)
    source_path.write_text("latency_ms\n10\n", encoding="utf-8")
    database_path = tmp_path / "metrics.csv"
    original = "source_id,mean__latency_ms\ntiming/existing.csv,5.0\n"
    database_path.write_text(original, encoding="utf-8")
    monkeypatch.setenv("TELEGENT_ANALYSIS_ROOT", str(analysis_root))
    monkeypatch.setenv("TELEGENT_METRICS_DB", str(database_path))

    with pytest.raises(SystemExit) as raised:
        main(
            [
                "metric",
                "--input",
                str(source_path),
                "--column",
                "missing_column",
                "--operator",
                "mean",
            ]
        )

    assert raised.value.code == 2
    assert database_path.read_text(encoding="utf-8") == original
