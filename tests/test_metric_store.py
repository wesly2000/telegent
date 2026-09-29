import csv
import math
from pathlib import Path

import pytest

from telegent import TelegentError
from telegent.metrics.store import MetricStore


def test_metric_store_expands_schema_and_overwrites_cells(tmp_path: Path) -> None:
    database_path = tmp_path / "metrics.csv"
    store = MetricStore(database_path)

    store.upsert("chat/deepseek/timing/official_01.csv", "mean__latency_ms", 10)
    store.upsert("chat/glm/timing/official_01.csv", "p95__latency_ms", 30)
    store.upsert("chat/deepseek/timing/official_01.csv", "mean__latency_ms", 20)
    store.upsert("chat/glm/timing/official_01.csv", "p95__latency_ms", math.nan)

    with database_path.open(encoding="utf-8", newline="") as database:
        rows = list(csv.reader(database))
    assert rows == [
        ["source_id", "mean__latency_ms", "p95__latency_ms"],
        ["chat/deepseek/timing/official_01.csv", "20.0", "NaN"],
        ["chat/glm/timing/official_01.csv", "NaN", "NaN"],
    ]
    assert not list(tmp_path.glob(".metrics.csv.*.tmp"))


def test_metric_store_rejects_malformed_database_without_changing_it(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "metrics.csv"
    original = "source_id,mean__latency_ms\nfile.csv,1,extra\n"
    database_path.write_text(original, encoding="utf-8")

    with pytest.raises(TelegentError, match="expected 2"):
        MetricStore(database_path).upsert("other.csv", "mean__latency_ms", 2)

    assert database_path.read_text(encoding="utf-8") == original
