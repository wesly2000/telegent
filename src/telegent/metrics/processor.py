"""Reusable single-file metric computation workflow."""

from dataclasses import dataclass
from pathlib import Path

from ..errors import TelegentError
from .op import Operator
from .settings import MetricSettings
from .source import load_metric_source
from .store import MetricStore


@dataclass(frozen=True)
class MetricResult:
    """One computed metric and its persistence location."""

    source_id: str
    metric_key: str
    value: float
    database_path: Path


class MetricProcessor:
    """Compute and persist scalar metrics from analysis CSV files."""

    def __init__(self, settings: MetricSettings) -> None:
        self.settings = settings
        self._store = MetricStore(settings.database_path)

    def process_file(
        self,
        input_path: Path | str,
        column: str,
        operator: Operator,
    ) -> MetricResult:
        """Compute one source/column/operator combination and upsert it."""

        input_file = Path(input_path).expanduser().resolve()
        if input_file == self.settings.database_path.resolve():
            raise TelegentError("metric input must not be the metrics database")
        source = load_metric_source(
            input_file,
            column,
            self.settings.analysis_root,
        )
        value = operator.compute(source.values)
        metric_key = f"{operator.name}__{column}"
        self._store.upsert(source.source_id, metric_key, value)
        return MetricResult(
            source_id=source.source_id,
            metric_key=metric_key,
            value=value,
            database_path=self.settings.database_path,
        )

    def process_directory(
        self,
        column: str,
        operator: Operator,
    ) -> list[MetricResult]:
        """Recursively process every CSV beneath the configured analysis root."""

        root = self.settings.analysis_root.resolve()
        if not root.is_dir():
            raise TelegentError(f"analysis root does not exist: {root}")
        database_path = self.settings.database_path.resolve()
        inputs = sorted(
            (
                path
                for path in root.rglob("*.csv")
                if path.is_file() and path.resolve() != database_path
            ),
            key=lambda path: path.relative_to(root).as_posix(),
        )
        if not inputs:
            raise TelegentError(f"no .csv files found under analysis root: {root}")
        return [self.process_file(path, column, operator) for path in inputs]
