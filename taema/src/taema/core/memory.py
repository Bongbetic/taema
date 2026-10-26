"""Read-only memory accounting for the host and delegated cgroup tree."""

import errno
import math
import os
import re
import time
from dataclasses import dataclass

from . import cgroup

SAMPLE_CHANGE = 0.05
SAMPLE_INTERVAL = 10 * 60
MIB = 1024**2
MIN_USEFUL_RECLAIM = 16 * MIB
_SIZE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([kmgt](?:i?b)?|b)?\s*$", re.I)
_SIZE_UNITS = {
    "": 1,
    "b": 1,
    "k": 1024,
    "kb": 1024,
    "kib": 1024,
    "m": 1024**2,
    "mb": 1024**2,
    "mib": 1024**2,
    "g": 1024**3,
    "gb": 1024**3,
    "gib": 1024**3,
    "t": 1024**4,
    "tb": 1024**4,
    "tib": 1024**4,
}


@dataclass(frozen=True, slots=True)
class ScopeMemory:
    """Immutable kernel observations for one cgroup scope."""

    name: str
    class_name: str
    current_bytes: int | None
    peak_bytes: int | None
    peak_source: str
    anon_bytes: int | None
    file_bytes: int | None
    swap_bytes: int | None
    zswap_bytes: int | None
    reclaimable_bytes: int | None
    psi_avg10: float | None
    psi_source: str | None
    feature_sources: tuple[tuple[str, str], ...]

    def as_dict(self):
        """Serialize at the JSON and view boundary."""
        return {
            "name": self.name,
            "class": self.class_name,
            "current_bytes": self.current_bytes,
            "peak_bytes": self.peak_bytes,
            "peak_source": self.peak_source,
            "anon_bytes": self.anon_bytes,
            "file_bytes": self.file_bytes,
            "swap_bytes": self.swap_bytes,
            "zswap_bytes": self.zswap_bytes,
            "reclaimable_bytes": self.reclaimable_bytes,
            "psi_avg10": self.psi_avg10,
            "psi_source": self.psi_source,
            "features": dict(self.feature_sources),
        }


@dataclass(frozen=True, slots=True)
class ReclaimBounds:
    """Shared limits for one page-cache and anonymous reclaim action."""

    maximum_bytes: int
    minimum_headroom_bytes: int
    headroom_percent: float
    minimum_bytes: int = MIN_USEFUL_RECLAIM


@dataclass(frozen=True, slots=True)
class MemorySample:
    """Immutable sample record shared by daemon sampling and SQLite serialization."""

    scope_key: str
    ts: float
    current: int | None
    peak: int | None
    anon: int | None
    file: int | None
    swap: int | None
    zswap: int | None
    psi10: float | None

    @classmethod
    def from_scope(cls, scope, now):
        """Build one persisted sample from a serialized scope observation."""
        return cls(
            scope_key=scope["name"],
            ts=float(now),
            current=scope.get("current_bytes"),
            peak=scope.get("peak_bytes"),
            anon=scope.get("anon_bytes"),
            file=scope.get("file_bytes"),
            swap=scope.get("swap_bytes"),
            zswap=scope.get("zswap_bytes"),
            psi10=scope.get("psi_avg10"),
        )

    @classmethod
    def from_db_row(cls, row):
        """Build the immutable record returned by the SQLite read boundary."""
        return cls(
            scope_key=row["scope_key"],
            ts=float(row.get("ts", 0)),
            current=row.get("current"),
            peak=row.get("peak"),
            anon=row.get("anon"),
            file=row.get("file"),
            swap=row.get("swap"),
            zswap=row.get("zswap"),
            psi10=row.get("psi10"),
        )

    def as_db_row(self):
        """Serialize into SQLite's column names at the storage boundary."""
        return {
            "scope_key": self.scope_key,
            "ts": self.ts,
            "current": self.current,
            "peak": self.peak,
            "anon": self.anon,
            "file": self.file,
            "swap": self.swap,
            "zswap": self.zswap,
            "psi10": self.psi10,
        }

    def change_metrics(self):
        """Return the one canonical metric bundle used by change detection."""
        return (
            self.current,
            self.peak,
            self.anon,
            self.file,
            self.swap,
            self.zswap,
            self.psi10,
        )


def config_enabled(cfg=None):
    """Whether memory collection is enabled by config alone, ignoring TAEMA_MEM."""
    if isinstance(cfg, dict):
        section = cfg.get("mem", {})
        if isinstance(section, dict) and section.get("enabled") is False:
            return False
    return True


def enabled(cfg=None):
    """Whether memory collection is enabled by config and the process environment."""
    if os.environ.get("TAEMA_MEM") == "0":
        return False
    return config_enabled(cfg)


def _read(path):
    try:
        with open(path, encoding="utf-8") as source:
            return source.read()
    except (OSError, UnicodeError):
        return None


def _integer(path):
    value = _read(path)
    if value is None:
        return None
    try:
        number = int(value.split()[0])
    except (ValueError, IndexError):
        return None
    return number if number >= 0 else None


def _stat(path):
    value = _read(path + "/memory.stat")
    if value is None:
        return None
    result = {}
    for line in value.splitlines():
        fields = line.split()
        if len(fields) != 2:
            continue
        try:
            result[fields[0]] = max(0, int(fields[1]))
        except ValueError:
            continue
    return result


def _psi(path, kind="some"):
    value = _read(path)
    if value is None:
        return None
    for line in value.splitlines():
        fields = line.split()
        if not fields or fields[0] != kind:
            continue
        for field in fields[1:]:
            if field.startswith("avg10="):
                try:
                    result = float(field.split("=", 1)[1])
                except ValueError:
                    return None
                return result if result >= 0 else None
    return None


def pressure(path=None):
    """Read the PSI some/full avg10 values from host or cgroup memory pressure."""
    path = path or os.path.join(
        os.environ.get("TAEMA_PROCROOT", "/proc"), "pressure", "memory"
    )
    return {"some_avg10": _psi(path, "some"), "full_avg10": _psi(path, "full")}


def size_bytes(value):
    """Parse an integer or binary size string used by memory governor settings."""
    if isinstance(value, bool):
        raise ValueError("size must be a non-negative number")
    if isinstance(value, (int, float)):
        amount, unit = float(value), ""
    elif isinstance(value, str):
        match = _SIZE.fullmatch(value)
        if match is None:
            raise ValueError("size must look like 512M or 1.5G")
        amount, unit = float(match.group(1)), (match.group(2) or "").lower()
    else:
        raise ValueError("size must be a number or binary size string")
    if not math.isfinite(amount) or amount < 0:
        raise ValueError("size must be finite and non-negative")
    return math.ceil(amount * _SIZE_UNITS[unit])


def page_cache_budget(
    current_bytes,
    anon_bytes,
    reclaimable_bytes,
    bounds,
):
    """Bound file-cache reclaim while retaining anonymous usage plus configured headroom."""
    if not isinstance(bounds, ReclaimBounds):
        return 0
    maximum_bytes = bounds.maximum_bytes
    minimum_headroom_bytes = bounds.minimum_headroom_bytes
    headroom_percent = bounds.headroom_percent
    minimum_bytes = bounds.minimum_bytes
    values = (
        current_bytes,
        anon_bytes,
        reclaimable_bytes,
        maximum_bytes,
        minimum_headroom_bytes,
        minimum_bytes,
    )
    if any(
        not isinstance(value, int) or isinstance(value, bool) or value < 0
        for value in values
    ):
        return 0
    if (
        not isinstance(headroom_percent, (int, float))
        or isinstance(headroom_percent, bool)
        or not math.isfinite(headroom_percent)
        or not 0 <= headroom_percent <= 100
        or anon_bytes > current_bytes
    ):
        return 0
    percent_headroom = math.ceil(current_bytes * headroom_percent / 100)
    headroom = max(minimum_headroom_bytes, percent_headroom)
    above_floor = max(0, current_bytes - anon_bytes - headroom)
    amount = min(reclaimable_bytes, maximum_bytes, above_floor)
    return amount if amount >= minimum_bytes else 0


def anonymous_reclaim_budget(
    current_bytes,
    anon_bytes,
    swap_bytes,
    swap_max_bytes,
    available_swap_bytes,
    bounds,
):
    """Bound anon reclaim by resident headroom, free swap, and the cgroup swap cap."""
    if not isinstance(bounds, ReclaimBounds):
        return 0
    maximum_bytes = bounds.maximum_bytes
    minimum_headroom_bytes = bounds.minimum_headroom_bytes
    headroom_percent = bounds.headroom_percent
    minimum_bytes = bounds.minimum_bytes
    values = (
        current_bytes,
        anon_bytes,
        maximum_bytes,
        minimum_headroom_bytes,
        swap_bytes,
        available_swap_bytes,
        minimum_bytes,
    )
    if any(
        not isinstance(value, int) or isinstance(value, bool) or value < 0
        for value in values
    ):
        return 0
    if swap_max_bytes is not None and (
        not isinstance(swap_max_bytes, int)
        or isinstance(swap_max_bytes, bool)
        or swap_max_bytes < 0
    ):
        return 0
    if (
        not isinstance(headroom_percent, (int, float))
        or isinstance(headroom_percent, bool)
        or not math.isfinite(headroom_percent)
        or not 0 <= headroom_percent <= 100
        or anon_bytes > current_bytes
    ):
        return 0
    headroom = max(
        minimum_headroom_bytes,
        math.ceil(current_bytes * headroom_percent / 100),
    )
    resident_room = max(0, current_bytes - headroom)
    swap_room = (
        max(0, swap_max_bytes - swap_bytes)
        if swap_max_bytes is not None
        else available_swap_bytes
    )
    amount = min(
        anon_bytes,
        maximum_bytes,
        resident_room,
        swap_room,
        available_swap_bytes,
    )
    return amount if amount >= minimum_bytes else 0


def counter_delta(before, after, *, direction):
    """Return a non-negative integer counter delta, or ``None`` if unknown."""
    if direction not in ("increase", "decrease"):
        raise ValueError("counter delta direction must be increase or decrease")
    if any(
        not isinstance(value, int) or isinstance(value, bool) or value < 0
        for value in (before, after)
    ):
        return None
    if direction == "increase":
        return max(0, after - before)
    return max(0, before - after)


def swap_limit(path):
    """Read memory.swap.max as an integer, ``max``, or ``None`` when unknown."""
    value = _read(os.path.join(path, "memory.swap.max"))
    if value is None:
        return None
    value = value.strip()
    if value == "max":
        return value
    try:
        number = int(value)
    except ValueError:
        return None
    return number if number >= 0 else None


def swap_available_bytes(proc_root=None):
    """Return free host swap in bytes, or ``None`` when its capacity is unknown."""
    proc_root = proc_root or os.environ.get("TAEMA_PROCROOT", "/proc")
    text = _read(os.path.join(proc_root, "meminfo"))
    if text is None:
        return None
    values = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 2:
            continue
        try:
            amount = int(fields[1])
        except ValueError:
            continue
        if fields[0].rstrip(":") in ("SwapTotal", "SwapFree"):
            values[fields[0].rstrip(":")] = amount * 1024
    total = values.get("SwapTotal")
    free = values.get("SwapFree")
    if total is None or free is None or total < 0 or free < 0 or free > total:
        return None
    return free


def scope_counters(path):
    """Return current memory and stat counters needed for bounded cache reclaim."""
    current = _integer(os.path.join(path, "memory.current"))
    stats = _stat(path)
    if current is None or stats is None:
        return None
    file_bytes = stats.get("file")
    inactive_file = stats.get("inactive_file")
    if file_bytes is None or inactive_file is None:
        reclaimable = None
    else:
        # shmem is counted in file but is swap-backed. Subtract it conservatively.
        shmem = stats.get("shmem", 0)
        reclaimable = max(0, min(inactive_file, file_bytes - shmem))
    high_events = None
    events = _read(os.path.join(path, "memory.events"))
    if events is not None:
        for line in events.splitlines():
            fields = line.split()
            if len(fields) == 2 and fields[0] == "high":
                try:
                    high_events = max(0, int(fields[1]))
                except ValueError:
                    pass
                break
    return {
        "current_bytes": current,
        "anon_bytes": stats.get("anon"),
        "file_bytes": file_bytes,
        "swap_bytes": _integer(os.path.join(path, "memory.swap.current")),
        "zswap_bytes": _integer(os.path.join(path, "memory.zswap.current")),
        "reclaimable_bytes": reclaimable,
        "workingset_refault_file": stats.get("workingset_refault_file"),
        "pgmajfault": stats.get("pgmajfault"),
        "high_events": high_events,
    }


def _write_control(path, name, value):
    with open(os.path.join(path, name), "w", encoding="ascii") as target:
        target.write(str(value).rstrip() + "\n")


def reclaim_page_cache(path, amount, high_target, pulse_seconds=0.05):
    """Request file-only reclaim, falling back to a short, restored memory.high pulse."""
    if (
        not isinstance(amount, int)
        or isinstance(amount, bool)
        or amount <= 0
        or not isinstance(high_target, int)
        or isinstance(high_target, bool)
        or high_target < 0
    ):
        raise ValueError("page-cache reclaim request is invalid")
    try:
        _write_control(path, "memory.reclaim", "%d swappiness=0" % amount)
        return "memory.reclaim"
    except OSError as error:
        if error.errno == errno.EAGAIN:
            # The kernel may have reclaimed some pages before reporting a shortfall.
            return "memory.reclaim"
        unsupported = {
            errno.ENOENT,
            errno.EINVAL,
            getattr(errno, "EOPNOTSUPP", errno.ENOTSUP),
            errno.ENOTSUP,
            getattr(errno, "ENOSYS", errno.EINVAL),
        }
        if error.errno not in unsupported:
            raise

    high_path = os.path.join(path, "memory.high")
    with open(high_path, encoding="ascii") as source:
        original = source.read().strip()
    if original == "max":
        target = high_target
    else:
        try:
            original_bytes = int(original)
        except ValueError as error:
            raise ValueError("memory.high has an invalid value") from error
        if original_bytes < 0 or original_bytes <= high_target:
            raise OSError(errno.EALREADY, "memory.high already has a tighter limit")
        target = min(original_bytes, high_target)
    page_size = os.sysconf("SC_PAGE_SIZE")
    if not isinstance(page_size, int) or page_size <= 0:
        raise OSError(errno.EINVAL, "system page size is unavailable")
    # memory.high is rounded down by the kernel, so send an aligned value.
    # Rounding upward keeps the pulse at or above the budget floor from the caller.
    target = ((target + page_size - 1) // page_size) * page_size
    if original != "max" and target >= original_bytes:
        raise OSError(errno.EALREADY, "memory.high pulse would not lower the limit")

    # memory.high reclaim may swap anonymous pages. Suppress swap for the pulse,
    # and only when the scope has no existing swap usage and both controls exist.
    try:
        with open(
            os.path.join(path, "memory.swap.current"), encoding="ascii"
        ) as source:
            swap_current = int(source.read().strip())
        with open(os.path.join(path, "memory.swap.max"), encoding="ascii") as source:
            original_swap_max = source.read().strip()
    except (OSError, ValueError) as error:
        raise OSError(
            getattr(errno, "EOPNOTSUPP", errno.ENOTSUP),
            "cannot verify that fallback reclaim will not swap anonymous pages",
        ) from error
    if swap_current != 0:
        raise OSError(errno.EBUSY, "fallback reclaim is unsafe while swap is in use")

    limit_swap = original_swap_max != "0"
    if limit_swap:
        _write_control(path, "memory.swap.max", 0)
    try:
        if limit_swap:
            with open(
                os.path.join(path, "memory.swap.max"), encoding="ascii"
            ) as source:
                if source.read().strip() != "0":
                    raise OSError(
                        errno.EIO, "could not disable swap for fallback reclaim"
                    )
        _write_control(path, "memory.high", target)
        try:
            time.sleep(max(0.0, min(float(pulse_seconds), 0.25)))
        finally:
            with open(high_path, encoding="ascii") as source:
                current = source.read().strip()
            if current == str(target):
                _write_control(path, "memory.high", original)
    finally:
        if limit_swap:
            swap_path = os.path.join(path, "memory.swap.max")
            with open(swap_path, encoding="ascii") as source:
                current_swap_max = source.read().strip()
            if current_swap_max == "0":
                _write_control(path, "memory.swap.max", original_swap_max)
    return "memory.high"


def reclaim_anonymous(path, amount):
    """Ask memory.reclaim to swap anonymous pages without changing zswap policy."""
    if not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0:
        raise ValueError("anonymous reclaim request must be a positive integer")
    try:
        _write_control(path, "memory.reclaim", "%d swappiness=max" % amount)
    except OSError as error:
        if error.errno == errno.EAGAIN:
            # Some pages may have moved before the kernel reported a shortfall.
            return "memory.reclaim"
        raise
    return "memory.reclaim"


def _host(proc_root, system_root, base):
    meminfo = _read(os.path.join(proc_root, "meminfo"))
    values = {}
    if meminfo is not None:
        for line in meminfo.splitlines():
            fields = line.split()
            if len(fields) < 2:
                continue
            try:
                amount = int(fields[1])
            except ValueError:
                continue
            values[fields[0].rstrip(":")] = amount * 1024

    zswap = None
    zswap_source = None
    for relative in (
        "sys/kernel/debug/zswap/pool_total_size",
        "sys/kernel/mm/zswap/pool_total_size",
    ):
        candidate = os.path.join(system_root, relative)
        zswap = _integer(candidate)
        if zswap is not None:
            zswap_source = "host"
            break
    if zswap is None and values.get("Zswap") is not None:
        zswap = values["Zswap"]
        zswap_source = "host"
    if zswap is None:
        zswap = _integer(os.path.join(base, "memory.zswap.current"))
        if zswap is not None:
            zswap_source = "delegated-subtree"

    current = _integer(os.path.join(base, "memory.current"))
    swap_total = values.get("SwapTotal")
    swap_free = values.get("SwapFree")
    swap_used = (
        max(0, swap_total - swap_free)
        if swap_total is not None and swap_free is not None
        else None
    )
    return {
        "total_bytes": values.get("MemTotal"),
        "available_bytes": values.get("MemAvailable"),
        "used_bytes": (
            max(0, values["MemTotal"] - values["MemAvailable"])
            if values.get("MemTotal") is not None
            and values.get("MemAvailable") is not None
            else None
        ),
        "pressure_avg10": _psi(os.path.join(proc_root, "pressure", "memory")),
        "swap_total_bytes": swap_total,
        "swap_free_bytes": swap_free,
        "swap_used_bytes": swap_used,
        "zswap_bytes": zswap,
        "zswap_source": zswap_source,
        "delegated_current_bytes": current,
    }


def _scope(path, key, peak_cache, host_pressure=None):
    if not os.path.isdir(path):
        return None
    current = _integer(os.path.join(path, "memory.current"))
    stat = _stat(path)
    kernel_peak = _integer(os.path.join(path, "memory.peak"))
    peak = kernel_peak
    peak_source = "kernel" if kernel_peak is not None else "unsupported"
    if peak is None:
        if current is not None:
            peak = max(current, peak_cache.get(key, 0))
            peak_cache[key] = peak
            peak_source = "sampled"
    else:
        peak_cache[key] = max(peak_cache.get(key, 0), peak)

    swap = _integer(os.path.join(path, "memory.swap.current"))
    zswap = _integer(os.path.join(path, "memory.zswap.current"))
    psi = _psi(os.path.join(path, "memory.pressure"))
    psi_source = "cgroup" if psi is not None else None
    if psi is None and host_pressure is not None:
        psi = host_pressure
        psi_source = "host"
    if not os.path.isdir(path):
        return None

    file_bytes = stat.get("file") if stat is not None else None
    inactive_file = stat.get("inactive_file") if stat is not None else None
    shmem = stat.get("shmem", 0) if stat is not None else None
    reclaimable = (
        inactive_file
        if inactive_file is not None
        else max(0, file_bytes - shmem)
        if file_bytes is not None and shmem is not None
        else None
    )

    return ScopeMemory(
        name=key,
        class_name=scope_class(key),
        current_bytes=current,
        peak_bytes=peak,
        peak_source=peak_source,
        anon_bytes=stat.get("anon") if stat is not None else None,
        file_bytes=file_bytes,
        swap_bytes=swap,
        zswap_bytes=zswap,
        reclaimable_bytes=reclaimable,
        psi_avg10=psi,
        psi_source=psi_source,
        feature_sources=(
            ("accounting", "supported" if current is not None else "unsupported"),
            ("memory_stat", "supported" if stat is not None else "unsupported"),
            ("peak", peak_source),
            ("pressure", psi_source or "unsupported"),
            ("swap", "supported" if swap is not None else "unsupported"),
            ("zswap", "supported" if zswap is not None else "unsupported"),
        ),
    )


def scope_class(key):
    """Return the broad cgroup class shown in memory reports."""
    first = key.split("/", 1)[0]
    if first in ("shared", "leftover"):
        return first
    for prefix, value in (("app-", "app"), ("scope-", "scope"), ("manager", "manager")):
        if first.startswith(prefix):
            return value
    return first.split("-", 1)[0]


def snapshot(
    base=None,
    cfg=None,
    peak_cache=None,
    proc_root=None,
    system_root=None,
    now=None,
    include_scopes=True,
):
    """Collect a bounded snapshot, tolerating cgroups that exit during the scan.

    include_scopes=False skips the per-scope walk and reports host memory
    only; the human status line uses it because it never shows per-scope
    rows.
    """
    sampled_at = time.time() if now is None else float(now)
    if not enabled(cfg):
        return {
            "schema": "taema.memory.v1",
            "enabled": False,
            "sampled_at": sampled_at,
            "host": None,
            "scopes": [],
            "features": {},
        }

    base = base or cgroup.base()
    proc_root = proc_root or os.environ.get("TAEMA_PROCROOT", "/proc")
    system_root = system_root or os.environ.get("TAEMA_SYSROOT", "/")
    peak_cache = peak_cache if peak_cache is not None else {}
    host = _host(proc_root, system_root, base)
    scopes = []
    alive = set()
    pending = list(reversed(cgroup.subdirs(base))) if include_scopes else []
    while pending:
        path = pending.pop()
        if not os.path.isdir(path):
            continue
        key = cgroup.rel(path)
        try:
            row = _scope(path, key, peak_cache, host.get("pressure_avg10"))
        except OSError:
            row = None
        if row is not None:
            alive.add(key)
            scopes.append(row.as_dict())
        try:
            pending.extend(reversed(cgroup.subdirs(path)))
        except OSError:
            continue
    if include_scopes:
        for key in tuple(peak_cache):
            if key not in alive:
                peak_cache.pop(key, None)

    features = {
        "accounting": "supported"
        if host.get("delegated_current_bytes") is not None
        else "unsupported",
        "peak": "kernel"
        if any(row["peak_source"] == "kernel" for row in scopes)
        else "sampled"
        if scopes
        else "unsupported",
        "pressure": "host" if host.get("pressure_avg10") is not None else "unsupported",
        "swap": "supported"
        if host.get("swap_used_bytes") is not None
        else "unsupported",
        "zswap": host.get("zswap_source") or "unsupported",
    }
    return {
        "schema": "taema.memory.v1",
        "enabled": True,
        "sampled_at": sampled_at,
        "host": host,
        "scopes": scopes,
        "features": features,
    }


def sample_due(previous, current, now):
    """Store the first sample, a >5% metric change, or the ten-minute heartbeat."""
    if previous is None or now - previous.ts >= SAMPLE_INTERVAL:
        return True
    for old, new in zip(previous.change_metrics(), current.change_metrics()):
        if new is None or old is None:
            continue
        difference = abs(new - old)
        if (old == 0 and difference > 0) or (
            old != 0 and difference > abs(old) * SAMPLE_CHANGE
        ):
            return True
    return False


def sample_record(scope, now):
    return MemorySample.from_scope(scope, now)
