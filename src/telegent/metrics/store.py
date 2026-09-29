"""Persistent wide-CSV storage for computed metrics."""

import csv
import math
import os
import tempfile
from pathlib import Path

from ..errors import TelegentError

_INDEX_COLUMN = "source_id"
_MISSING_VALUE = "NaN"


class MetricStore:
    """Upsert scalar values into a source-by-metric CSV table."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)

    def upsert(self, source_id: str, metric_key: str, value: float) -> None:
        """Insert or replace one metric cell and preserve every other cell."""

        header, rows = self._read()
        if metric_key not in header:
            header.append(metric_key)
            for row in rows:
                row.append(_MISSING_VALUE)

        metric_index = header.index(metric_key)
        matching_row = next((row for row in rows if row[0] == source_id), None)
        if matching_row is None:
            matching_row = [source_id, *[_MISSING_VALUE] * (len(header) - 1)]
            rows.append(matching_row)
        matching_row[metric_index] = _format_value(value)
        self._write(header, rows)

    def _read(self) -> tuple[list[str], list[list[str]]]:
        if not self.path.exists():
            return [_INDEX_COLUMN], []
        if not self.path.is_file():
            raise TelegentError(f"metrics database is not a file: {self.path}")
        try:
            with self.path.open("r", encoding="utf-8", newline="") as database:
                reader = csv.reader(database)
                try:
                    header = next(reader)
                except StopIteration as error:
                    raise TelegentError(
                        f"metrics database has no header: {self.path}"
                    ) from error
                if not header or header[0] != _INDEX_COLUMN:
                    raise TelegentError(
                        "metrics database must start with "
                        f"{_INDEX_COLUMN!r}: {self.path}"
                    )
                if len(header) != len(set(header)):
                    raise TelegentError(
                        f"metrics database has duplicate columns: {self.path}"
                    )
                rows = list(reader)
        except (OSError, UnicodeError, csv.Error) as error:
            raise TelegentError(
                f"could not read metrics database {self.path}: {error}"
            ) from error

        source_ids = set()
        for row_number, row in enumerate(rows, start=2):
            if len(row) != len(header):
                raise TelegentError(
                    f"metrics database row {row_number} has {len(row)} fields; "
                    f"expected {len(header)}"
                )
            if not row[0]:
                raise TelegentError(
                    f"metrics database row {row_number} has an empty source_id"
                )
            if row[0] in source_ids:
                raise TelegentError(
                    f"metrics database has duplicate source_id: {row[0]}"
                )
            source_ids.add(row[0])
        return header, rows

    def _write(self, header: list[str], rows: list[list[str]]) -> None:
        parent = self.path.parent
        try:
            parent.mkdir(parents=True, exist_ok=True)
            descriptor, temporary_name = tempfile.mkstemp(
                dir=parent,
                prefix=f".{self.path.name}.",
                suffix=".tmp",
                text=True,
            )
        except OSError as error:
            raise TelegentError(
                f"could not prepare metrics database {self.path}: {error}"
            ) from error

        temporary_path = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as output:
                writer = csv.writer(output)
                writer.writerow(header)
                writer.writerows(rows)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary_path, self.path)
        except (OSError, csv.Error) as error:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise TelegentError(
                f"could not write metrics database {self.path}: {error}"
            ) from error


def _format_value(value: float) -> str:
    numeric_value = float(value)
    if not math.isfinite(numeric_value):
        return _MISSING_VALUE
    return repr(numeric_value)
