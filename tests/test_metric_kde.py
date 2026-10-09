import numpy
import pytest

from telegent.metrics import kde_modes


def test_kde_modes_finds_separated_density_modes() -> None:
    data = numpy.array([100] * 50 + [200] * 30 + [300] * 20)

    assert kde_modes(data) == [100, 200, 300]


def test_kde_modes_filters_clusters_below_mass_threshold() -> None:
    data = [100] * 91 + [200] * 9

    assert kde_modes(data, bandwidth=20, mass_threshold=0.1) == [100]


def test_kde_modes_includes_cluster_at_mass_threshold() -> None:
    data = [100] * 90 + [200] * 10

    assert kde_modes(data, bandwidth=20, mass_threshold=0.1) == [100, 200]


def test_kde_modes_merges_nearby_observations_into_one_mode() -> None:
    data = [100] * 20 + [110] * 60 + [120] * 20

    assert kde_modes(data) == [110]


def test_kde_modes_handles_empty_and_single_value_data() -> None:
    assert kde_modes([]) == []
    assert kde_modes([123] * 10) == [123]


@pytest.mark.parametrize("data", [[[1, 2]], [1, 2.5], [1, numpy.nan]])
def test_kde_modes_rejects_invalid_data(data: list[object]) -> None:
    with pytest.raises((TypeError, ValueError)):
        kde_modes(data)  # type: ignore[arg-type]


@pytest.mark.parametrize("bandwidth", [0, -1, numpy.inf, True])
def test_kde_modes_rejects_invalid_bandwidth(bandwidth: object) -> None:
    with pytest.raises(ValueError, match="bandwidth"):
        kde_modes([1, 2], bandwidth=bandwidth)  # type: ignore[arg-type]


@pytest.mark.parametrize("threshold", [-0.1, 1.1, numpy.nan, True])
def test_kde_modes_rejects_invalid_mass_threshold(threshold: object) -> None:
    with pytest.raises(ValueError, match="mass_threshold"):
        kde_modes([1, 2], mass_threshold=threshold)  # type: ignore[arg-type]
