"""One-dimensional KDE modal clustering for integer-valued metrics."""

from collections.abc import Sequence
from numbers import Real

import numpy


def kde_modes(
    data: Sequence[int] | numpy.ndarray,
    bandwidth: float = 20,
    mass_threshold: float = 0.1,
) -> list[int]:
    """Return the modes of sufficiently large KDE density basins.

    A Gaussian kernel density estimate is evaluated at every integer between
    the smallest and largest observation. Local density minima split adjacent
    modes into clusters. A mode is returned only when its cluster contains at
    least ``mass_threshold`` of all observations.

    The returned modes are integer byte sizes in ascending order. Empty input
    produces an empty list.
    """

    samples = _validate_data(data)
    bandwidth = _validate_bandwidth(bandwidth)
    mass_threshold = _validate_mass_threshold(mass_threshold)
    if samples.size == 0:
        return []

    grid = _integer_grid(samples)
    density = _estimate_density(samples, grid, bandwidth)
    mode_indices = _find_mode_indices(density)
    boundaries = _find_cluster_boundaries(density, mode_indices)
    masses = _cluster_masses(samples, grid, boundaries, len(mode_indices))

    return [
        int(grid[mode_index])
        for mode_index, mass in zip(mode_indices, masses, strict=True)
        if mass >= mass_threshold
    ]


def _validate_data(data: Sequence[int] | numpy.ndarray) -> numpy.ndarray:
    samples = numpy.asarray(data)
    if samples.ndim != 1:
        raise ValueError("data must be one-dimensional")
    if samples.size == 0:
        return numpy.array([], dtype=numpy.int64)
    if not numpy.issubdtype(samples.dtype, numpy.number) or numpy.issubdtype(
        samples.dtype, numpy.bool_
    ):
        raise TypeError("data must contain integers")

    numeric_samples = samples.astype(numpy.float64)
    if not numpy.isfinite(numeric_samples).all():
        raise ValueError("data must contain only finite values")
    if not numpy.equal(numeric_samples, numpy.floor(numeric_samples)).all():
        raise ValueError("data must contain integers")

    integer_limits = numpy.iinfo(numpy.int64)
    if (
        numeric_samples.min() < integer_limits.min
        or numeric_samples.max() > integer_limits.max
    ):
        raise ValueError("data values must fit in signed 64-bit integers")
    return numeric_samples.astype(numpy.int64)


def _validate_bandwidth(bandwidth: float) -> float:
    if (
        isinstance(bandwidth, bool)
        or not isinstance(bandwidth, Real)
        or not numpy.isfinite(bandwidth)
        or bandwidth <= 0
    ):
        raise ValueError("bandwidth must be a finite positive number")
    return float(bandwidth)


def _validate_mass_threshold(mass_threshold: float) -> float:
    if (
        isinstance(mass_threshold, bool)
        or not isinstance(mass_threshold, Real)
        or not numpy.isfinite(mass_threshold)
        or not 0 <= mass_threshold <= 1
    ):
        raise ValueError("mass_threshold must be between 0 and 1")
    return float(mass_threshold)


def _integer_grid(samples: numpy.ndarray) -> numpy.ndarray:
    start = int(samples.min())
    stop = int(samples.max()) + 1
    return numpy.arange(start, stop, dtype=numpy.int64)


def _estimate_density(
    samples: numpy.ndarray,
    grid: numpy.ndarray,
    bandwidth: float,
) -> numpy.ndarray:
    unique_samples, counts = numpy.unique(samples, return_counts=True)
    density = numpy.empty(grid.size, dtype=numpy.float64)
    chunk_size = 4096

    for start in range(0, grid.size, chunk_size):
        stop = min(start + chunk_size, grid.size)
        distances = (
            grid[start:stop, numpy.newaxis] - unique_samples[numpy.newaxis, :]
        ) / bandwidth
        kernels = numpy.exp(-0.5 * numpy.square(distances))
        density[start:stop] = kernels @ counts

    return density / samples.size


def _find_mode_indices(density: numpy.ndarray) -> list[int]:
    modes: list[int] = []
    index = 0

    while index < density.size:
        plateau_end = index
        while (
            plateau_end + 1 < density.size
            and density[plateau_end + 1] == density[index]
        ):
            plateau_end += 1

        left = density[index - 1] if index > 0 else -numpy.inf
        right = (
            density[plateau_end + 1]
            if plateau_end + 1 < density.size
            else -numpy.inf
        )
        if density[index] > left and density[plateau_end] > right:
            modes.append((index + plateau_end) // 2)

        index = plateau_end + 1

    return modes


def _find_cluster_boundaries(
    density: numpy.ndarray,
    mode_indices: Sequence[int],
) -> list[int]:
    boundaries: list[int] = []
    for left_mode, right_mode in zip(mode_indices, mode_indices[1:]):
        between_modes = density[left_mode : right_mode + 1]
        boundaries.append(left_mode + int(numpy.argmin(between_modes)))
    return boundaries


def _cluster_masses(
    samples: numpy.ndarray,
    grid: numpy.ndarray,
    boundary_indices: Sequence[int],
    cluster_count: int,
) -> numpy.ndarray:
    boundary_values = grid[numpy.asarray(boundary_indices, dtype=numpy.int64)]
    assignments = numpy.searchsorted(boundary_values, samples, side="right")
    counts = numpy.bincount(assignments, minlength=cluster_count)
    return counts / samples.size
