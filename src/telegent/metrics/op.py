"""Scalar operators for CSV metric columns."""

import math
import statistics
from abc import ABC, abstractmethod
from collections.abc import Sequence


class Operator(ABC):
    """Compute one named scalar metric from a sequence of numeric values."""

    @property
    def name(self) -> str:
        """Return the lowercase class name used in metric keys and the CLI."""

        return type(self).__name__.lower()

    @abstractmethod
    def compute(self, values: Sequence[float]) -> float:
        """Return one scalar result, or NaN when it cannot be computed."""


class Mean(Operator):
    """Compute the arithmetic mean of the available values."""

    def compute(self, values: Sequence[float]) -> float:
        if not values:
            return math.nan
        return float(statistics.mean(values))


class Std(Operator):
    """Compute the sample standard deviation of the available values."""

    def compute(self, values: Sequence[float]) -> float:
        if len(values) < 2:
            return math.nan
        return float(statistics.stdev(values))


class P50(Operator):
    """Compute the 50th percentile using the nearest-rank method."""

    def compute(self, values: Sequence[float]) -> float:
        return _percentile(values, 50)


class P95(Operator):
    """Compute the 95th percentile using the nearest-rank method."""

    def compute(self, values: Sequence[float]) -> float:
        return _percentile(values, 95)


def _percentile(values: Sequence[float], percentile: int) -> float:
    if not values:
        return math.nan

    import numpy

    return float(numpy.percentile(values, percentile, method="inverted_cdf"))
