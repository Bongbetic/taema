"""Pure budget and headroom calculations for the memory governor."""

import math
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import TypeAlias

from ..core.memory import MIB

MemorySize: TypeAlias = int | None


@dataclass(frozen=True, slots=True)
class BudgetScope:
    """Immutable facts used to assign one active scope its memory share."""

    name: str
    class_name: str | None
    background: bool


@dataclass(frozen=True, slots=True)
class BudgetPlan:
    """Immutable budget result with read-only per-scope assignments."""

    budget_bytes: int
    floor_bytes: int
    infrastructure_bytes: int
    allocatable_bytes: int
    reserved_bytes: int
    background_bytes: int
    reservations: Mapping[str, int]
    shares: Mapping[str, int]


CLASS_RESERVATIONS: Mapping[str, float] = MappingProxyType(
    {"vm": 0.25, "container": 0.10, "app": 0.05}
)
DEFAULT_AVAILABILITY_FLOOR = 512 * MIB
DEFAULT_MIN_HEADROOM = 128 * MIB
DEFAULT_HEADROOM_PERCENT = 10


def budget_bytes(
    total_bytes: MemorySize,
    delegated_max: MemorySize,
    fraction: float = 0.80,
    explicit: MemorySize = None,
) -> int:
    """Return the configured budget ceiling, bounded by RAM and finite delegation."""
    if (
        not isinstance(total_bytes, int)
        or isinstance(total_bytes, bool)
        or total_bytes < 0
    ):
        return 0
    if (
        isinstance(fraction, bool)
        or not isinstance(fraction, (int, float))
        or not math.isfinite(fraction)
        or not 0 <= fraction <= 1
    ):
        return 0
    limits = [math.floor(total_bytes * fraction)]
    if delegated_max is not None:
        if (
            not isinstance(delegated_max, int)
            or isinstance(delegated_max, bool)
            or delegated_max < 0
        ):
            return 0
        limits.append(delegated_max)
    if explicit is not None:
        if not isinstance(explicit, int) or isinstance(explicit, bool) or explicit < 0:
            return 0
        limits.append(explicit)
    return min(limits)


def headroom_bytes(
    current_bytes: MemorySize,
    minimum: int = DEFAULT_MIN_HEADROOM,
    percent: float = DEFAULT_HEADROOM_PERCENT,
) -> MemorySize:
    """Compute required per-scope headroom without allowing invalid values through."""
    if current_bytes is None:
        return None
    values = (current_bytes, minimum)
    if any(
        not isinstance(value, int) or isinstance(value, bool) or value < 0
        for value in values
    ):
        return None
    if (
        isinstance(percent, bool)
        or not isinstance(percent, (int, float))
        or not math.isfinite(percent)
        or not 0 <= percent <= 100
    ):
        return None
    return max(minimum, math.ceil(current_bytes * percent / 100))


def align_up(value: int, page_size: int) -> int:
    """Round a memory protection target upward so kernel page rounding preserves it."""
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
        or not isinstance(page_size, int)
        or isinstance(page_size, bool)
        or page_size <= 0
    ):
        raise ValueError("memory target and page size must be valid integers")
    return ((value + page_size - 1) // page_size) * page_size


def materially_changed(
    current: str | int | None, target: int, fraction: float = 0.05
) -> bool:
    """Whether a finite target differs from the live control by more than 5%."""
    if current == "max":
        return True
    if current is None:
        return True
    try:
        current_bytes = int(current)
    except (TypeError, ValueError):
        return True
    if current_bytes < 0:
        return True
    return abs(current_bytes - target) > max(1, current_bytes * fraction)


def plan(
    budget: int,
    floor: int,
    infrastructure: int,
    scopes: Iterable[BudgetScope],
    reservations: Mapping[str, float] | None = None,
) -> BudgetPlan:
    """Divide the allocatable ceiling into active reservations and background shares.

    Reservation percentages are class-wide budgets and are divided evenly among active
    scopes of each class. Infrastructure use and the availability floor are removed before
    any reservations or background shares are assigned.
    """
    reservations = CLASS_RESERVATIONS if reservations is None else reservations

    def valid(value: object) -> bool:
        return isinstance(value, int) and not isinstance(value, bool) and value >= 0

    if not valid(budget) or not valid(floor) or not valid(infrastructure):
        raise ValueError("budget inputs must be non-negative integers")
    if not isinstance(reservations, Mapping) or any(
        not isinstance(key, str)
        or isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or not 0 <= value <= 1
        for key, value in reservations.items()
    ):
        raise ValueError("class reservations must be fractions from 0 to 1")
    if sum(reservations.values()) > 1:
        raise ValueError("class reservations cannot exceed the budget")

    allocatable = max(0, budget - floor - min(infrastructure, budget))
    active_by_class: dict[str, list[BudgetScope]] = {}
    background: list[BudgetScope] = []
    for scope in scopes:
        if not isinstance(scope, BudgetScope):
            continue
        class_name = scope.class_name
        if scope.background:
            background.append(scope)
        elif class_name is not None and class_name in reservations:
            active_by_class.setdefault(class_name, []).append(scope)

    active_reservations: dict[str, int] = {}
    for class_name, rows in active_by_class.items():
        total = math.floor(allocatable * reservations[class_name])
        each, extra = divmod(total, len(rows))
        for index, scope in enumerate(sorted(rows, key=lambda row: row.name)):
            active_reservations[scope.name] = each + int(index < extra)

    reserved = sum(active_reservations.values())
    background_pool = max(0, allocatable - reserved)
    per_scope, extra = (
        divmod(background_pool, len(background)) if background else (0, 0)
    )
    background_shares = {
        scope.name: per_scope + int(index < extra)
        for index, scope in enumerate(sorted(background, key=lambda row: row.name))
    }
    return BudgetPlan(
        budget_bytes=budget,
        floor_bytes=floor,
        infrastructure_bytes=min(infrastructure, budget),
        allocatable_bytes=allocatable,
        reserved_bytes=reserved,
        background_bytes=background_pool,
        reservations=MappingProxyType(active_reservations),
        shares=MappingProxyType(background_shares),
    )
