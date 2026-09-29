import math

import pytest

from telegent.metrics.op import Mean, P50, P95, Std


def test_builtin_operators_use_expected_names_and_semantics() -> None:
    assert Mean().name == "mean"
    assert Std().name == "std"
    assert P50().name == "p50"
    assert P95().name == "p95"
    assert Mean().compute([1, 2, 3, 4]) == 2.5
    assert Std().compute([1, 2, 3]) == pytest.approx(1.0)
    assert P50().compute([1, 2, 3, 4]) == 2
    assert P95().compute(list(range(1, 21))) == 19
    assert math.isnan(Mean().compute([]))
    assert math.isnan(Std().compute([1]))
    assert math.isnan(P95().compute([]))
