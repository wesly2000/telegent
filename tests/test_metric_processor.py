from pathlib import Path

import pytest

from telegent import Mean, MetricProcessor, MetricSettings, TelegentError


def test_metric_settings_require_and_resolve_both_paths(tmp_path: Path) -> None:
    settings = MetricSettings.resolve(
        environ={
            "TELEGENT_ANALYSIS_ROOT": "analysis",
            "TELEGENT_METRICS_DB": "results/metrics.csv",
        },
        cwd=tmp_path,
    )

    assert settings.analysis_root == tmp_path / "analysis"
    assert settings.database_path == tmp_path / "results/metrics.csv"

    with pytest.raises(TelegentError, match="TELEGENT_METRICS_DB is required"):
        MetricSettings.resolve(
            environ={"TELEGENT_ANALYSIS_ROOT": "analysis"},
            cwd=tmp_path,
        )


def test_processor_updates_one_reusable_metric_cell(tmp_path: Path) -> None:
    analysis_root = tmp_path / "analysis"
    source_path = analysis_root / "chat/deepseek/timing/official_01.csv"
    source_path.parent.mkdir(parents=True)
    source_path.write_text("latency_ms\n10\n20\n", encoding="utf-8")
    settings = MetricSettings(analysis_root, tmp_path / "metrics.csv")

    result = MetricProcessor(settings).process_file(
        source_path,
        "latency_ms",
        Mean(),
    )

    assert result.source_id == "chat/deepseek/timing/official_01.csv"
    assert result.metric_key == "mean__latency_ms"
    assert result.value == 15
    assert result.database_path == tmp_path / "metrics.csv"


def test_processor_recursively_processes_csv_files_in_path_order(
    tmp_path: Path,
) -> None:
    analysis_root = tmp_path / "telegent-analysis"
    first = analysis_root / "chat/deepseek/timing/official_01.csv"
    second = analysis_root / "chat/glm/timing/official_01.csv"
    first.parent.mkdir(parents=True)
    second.parent.mkdir(parents=True)
    first.write_text("latency_ms\n10\n20\n", encoding="utf-8")
    second.write_text("latency_ms\n30\n40\n", encoding="utf-8")
    database_path = analysis_root / "database.csv"
    database_path.write_text("source_id\n", encoding="utf-8")
    settings = MetricSettings(analysis_root, database_path)

    results = MetricProcessor(settings).process_directory("latency_ms", Mean())

    assert [result.source_id for result in results] == [
        "chat/deepseek/timing/official_01.csv",
        "chat/glm/timing/official_01.csv",
    ]
    assert [result.value for result in results] == [15, 35]
    assert database_path.read_text(encoding="utf-8").splitlines() == [
        "source_id,mean__latency_ms",
        "chat/deepseek/timing/official_01.csv,15.0",
        "chat/glm/timing/official_01.csv,35.0",
    ]
