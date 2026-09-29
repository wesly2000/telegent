"""Load numeric metric inputs and derive portable source identifiers."""

import csv
import math
from dataclasses import dataclass
from pathlib import Path

from ..errors import TelegentError


@dataclass(frozen=True)
class MetricSource:
    """A portable source identifier and its usable numeric values."""

    source_id: str
    values: tuple[float, ...]


def load_metric_source(
    input_path: Path | str,
    column: str,
    analysis_root: Path,
) -> MetricSource:
    """Load finite values from one CSV column beneath the analysis root."""

    root = analysis_root.resolve()
    if not root.is_dir():
        raise TelegentError(f"analysis root does not exist: {root}")

    path = Path(input_path).expanduser().resolve()
    if not path.is_file():
        raise TelegentError(f"metric input does not exist: {path}")
    if path.suffix != ".csv":
        raise TelegentError(f"metric input must be a .csv file: {path}")
    try:
        relative_path = path.relative_to(root)
    except ValueError as error:
        raise TelegentError(
            f"metric input is outside TELEGENT_ANALYSIS_ROOT: {path}"
        ) from error

    try:
        with path.open("r", encoding="utf-8", newline="") as input_file:
            reader = csv.reader(input_file)
            try:
                header = next(reader)
            except StopIteration as error:
                raise TelegentError(f"metric input has no header: {path}") from error
            _validate_header(header, path)
            try:
                column_index = header.index(column)
            except ValueError as error:
                raise TelegentError(
                    f"metric input column does not exist: {column}"
                ) from error

            values = []
            for row in reader:
                if column_index >= len(row):
                    continue
                text = row[column_index].strip()
                if not text:
                    continue
                try:
                    value = float(text)
                except ValueError:
                    continue
                if math.isfinite(value):
                    values.append(value)
    except (OSError, UnicodeError, csv.Error) as error:
        raise TelegentError(f"could not read metric input {path}: {error}") from error

    return MetricSource(relative_path.as_posix(), tuple(values))


def _validate_header(header: list[str], path: Path) -> None:
    if not header or all(not item for item in header):
        raise TelegentError(f"metric input has no header: {path}")
    if len(header) != len(set(header)):
        raise TelegentError(f"metric input has duplicate columns: {path}")
