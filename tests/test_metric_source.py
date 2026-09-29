from pathlib import Path

import pytest

from telegent import TelegentError
from telegent.metrics.source import load_metric_source


def test_metric_source_uses_root_relative_id_and_ignores_unusable_values(
    tmp_path: Path,
) -> None:
    analysis_root = tmp_path / "analysis"
    source_path = analysis_root / "chat/deepseek/timing/official_01.csv"
    source_path.parent.mkdir(parents=True)
    source_path.write_text(
        "latency_ms,label\n"
        "1.5,valid\n"
        ",blank\n"
        "NaN,nan\n"
        "inf,infinite\n"
        "not-a-number,text\n"
        "2.5,valid\n",
        encoding="utf-8",
    )

    source = load_metric_source(source_path, "latency_ms", analysis_root)

    assert source.source_id == "chat/deepseek/timing/official_01.csv"
    assert source.values == (1.5, 2.5)


def test_metric_source_rejects_paths_outside_root(tmp_path: Path) -> None:
    analysis_root = tmp_path / "analysis"
    analysis_root.mkdir()
    outside = tmp_path / "outside.csv"
    outside.write_text("value\n1\n", encoding="utf-8")

    with pytest.raises(TelegentError, match="outside TELEGENT_ANALYSIS_ROOT"):
        load_metric_source(outside, "value", analysis_root)
