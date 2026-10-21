"""Read-only memory accounting for the host and delegated cgroup tree."""

import os
import time
from dataclasses import dataclass

from . import cgroup

SAMPLE_CHANGE = 0.05
SAMPLE_INTERVAL = 10 * 60


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


def enabled(cfg=None):
    """Whether memory collection is enabled by config and the process environment."""
    if os.environ.get("TAEMA_MEM") == "0":
        return False
    if isinstance(cfg, dict):
        section = cfg.get("mem", {})
        if isinstance(section, dict) and section.get("enabled") is False:
            return False
    return True


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


def _psi(path):
    value = _read(path)
    if value is None:
        return None
    for line in value.splitlines():
        fields = line.split()
        if not fields or fields[0] != "some":
            continue
        for field in fields[1:]:
            if field.startswith("avg10="):
                try:
                    result = float(field.split("=", 1)[1])
                except ValueError:
                    return None
                return result if result >= 0 else None
    return None


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
    base=None, cfg=None, peak_cache=None, proc_root=None, system_root=None, now=None
):
    """Collect a bounded snapshot, tolerating cgroups that exit during the scan."""
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
    pending = list(reversed(cgroup.subdirs(base)))
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
