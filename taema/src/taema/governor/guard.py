"""Pressure trigger collection and small, deterministic guard calculations."""

from __future__ import annotations

import math
import os
import re
import select
from dataclasses import dataclass
from typing import Mapping

_PSI_SETTING = re.compile(
    r"^\s*(\d+(?:\.\d+)?)\s*(us|ms|s)?\s*/\s*"
    r"(\d+(?:\.\d+)?)\s*(us|ms|s)\s*$",
    re.IGNORECASE,
)
_UNIT_MICROSECONDS = {"us": 1, "ms": 1000, "s": 1_000_000}
_EARLYOOM_DEFAULT_MEMORY_PERCENT = 10.0
_EARLYOOM_DEFAULT_SWAP_PERCENT = 10.0


@dataclass(frozen=True, slots=True)
class OomHandler:
    """One detected external memory-pressure handler and its visible argv."""

    name: str
    pid: int
    argv: tuple[str, ...]
    options: tuple[tuple[str, str], ...] = ()

    def option(self, name: str) -> str | None:
        return dict(self.options).get(name)


def psi_trigger(metric: str, setting: str) -> tuple[str, int, int]:
    """Convert ``150ms/2s`` into the kernel PSI trigger record."""
    if metric not in ("some", "full") or not isinstance(setting, str):
        raise ValueError("PSI trigger must name some or full and a duration")
    match = _PSI_SETTING.fullmatch(setting)
    if match is None:
        raise ValueError("PSI trigger must look like 150ms/2s")
    amount, amount_unit, window, window_unit = match.groups()
    amount_us = math.ceil(
        float(amount) * _UNIT_MICROSECONDS[(amount_unit or "us").lower()]
    )
    window_us = math.ceil(float(window) * _UNIT_MICROSECONDS[window_unit.lower()])
    # Unprivileged monitors must use a 2-second multiple; the kernel also bounds
    # windows to 10 seconds and rejects thresholds greater than their window.
    if (
        amount_us <= 0
        or window_us < 2_000_000
        or window_us > 10_000_000
        or window_us % 2_000_000
        or amount_us >= window_us
    ):
        raise ValueError("PSI trigger duration is outside the supported range")
    return metric, amount_us, window_us


def psi_threshold_percent(setting: str, metric: str) -> float:
    """Return the equivalent PSI stall percentage for the configured trigger window."""
    _metric, amount, window = psi_trigger(metric, setting)
    return amount * 100.0 / window


def floor_percent(
    setting: object,
    *,
    earlyoom_present: bool,
    earlyoom_memory_percent: float | None,
) -> float:
    """Resolve ``guard.available_floor`` to a percentage of installed memory."""
    if setting != "auto":
        if (
            isinstance(setting, bool)
            or not isinstance(setting, (int, float))
            or not math.isfinite(setting)
            or not 0 <= setting <= 100
        ):
            raise ValueError("available floor must be auto or between 0 and 100")
        return float(setting)
    if not earlyoom_present:
        return 12.0
    baseline = (
        _EARLYOOM_DEFAULT_MEMORY_PERCENT
        if earlyoom_memory_percent is None
        else earlyoom_memory_percent
    )
    if (
        isinstance(baseline, bool)
        or not isinstance(baseline, (int, float))
        or not math.isfinite(baseline)
        or not 0 <= baseline <= 100
    ):
        baseline = _EARLYOOM_DEFAULT_MEMORY_PERCENT
    return min(100.0, float(baseline) + 4.0)


def available_floor_bytes(
    total_bytes: int | None,
    setting: object = "auto",
    *,
    earlyoom_present: bool = False,
    earlyoom_memory_percent: float | None = None,
) -> int | None:
    """Return the configured host-memory floor in bytes, or unknown if RAM is unknown."""
    if (
        not isinstance(total_bytes, int)
        or isinstance(total_bytes, bool)
        or total_bytes <= 0
    ):
        return None
    percent = floor_percent(
        setting,
        earlyoom_present=earlyoom_present,
        earlyoom_memory_percent=earlyoom_memory_percent,
    )
    return math.ceil(total_bytes * percent / 100)


def host_memory(proc_root: str | None = None) -> tuple[int | None, int | None]:
    """Return ``(MemAvailable, MemTotal)`` in bytes from proc meminfo."""
    proc_root = proc_root or os.environ.get("TAEMA_PROCROOT", "/proc")
    try:
        with open(os.path.join(proc_root, "meminfo"), encoding="ascii") as source:
            text = source.read()
    except (OSError, UnicodeError):
        return None, None
    values: dict[str, int] = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 2:
            continue
        try:
            value = int(fields[1])
        except ValueError:
            continue
        if value >= 0 and fields[0].rstrip(":") in ("MemTotal", "MemAvailable"):
            values[fields[0].rstrip(":")] = value * 1024
    return values.get("MemAvailable"), values.get("MemTotal")


def _read_cmdline(proc_root: str, pid: str) -> tuple[str, ...]:
    try:
        with open(os.path.join(proc_root, pid, "cmdline"), "rb") as source:
            raw = source.read()
    except OSError:
        return ()
    return tuple(part.decode("utf-8", "replace") for part in raw.split(b"\0") if part)


def _read_comm(proc_root: str, pid: str) -> str:
    try:
        with open(os.path.join(proc_root, pid, "comm"), encoding="utf-8") as source:
            return source.read().strip()
    except (OSError, UnicodeError):
        return ""


def earlyoom_options(argv: tuple[str, ...]) -> tuple[tuple[str, str], ...]:
    """Read the effective earlyoom flags relevant to pressure coordination."""
    options: dict[str, str] = {}
    index = 1 if argv else 0
    while index < len(argv):
        token = argv[index]
        name = token
        value = ""
        if token.startswith("--") and "=" in token:
            name, value = token.split("=", 1)
        elif token in ("-m", "-M", "-s", "-S", "--prefer", "--avoid"):
            if index + 1 < len(argv):
                index += 1
                value = argv[index]
        elif token.startswith("-m") and len(token) > 2:
            name, value = "-m", token[2:]
        elif token.startswith("-M") and len(token) > 2:
            name, value = "-M", token[2:]
        elif token.startswith("-s") and len(token) > 2:
            name, value = "-s", token[2:]
        if name in ("-m", "-M", "-s", "-S", "--prefer", "--avoid") and value:
            options[name] = value
        index += 1
    return tuple(sorted(options.items()))


def _first_percent(value: str | None, default: float) -> float:
    if not isinstance(value, str):
        return default
    try:
        result = float(value.split(",", 1)[0])
    except ValueError:
        return default
    return result if math.isfinite(result) and 0 <= result <= 100 else default


def earlyoom_memory_percent(handler: OomHandler, total_bytes: int | None) -> float:
    """Return earlyoom's effective memory threshold, including its documented defaults."""
    size_kib = handler.option("-M")
    if size_kib is not None and total_bytes:
        try:
            return min(
                100.0,
                max(0.0, int(size_kib.split(",", 1)[0]) * 1024 * 100 / total_bytes),
            )
        except ValueError:
            pass
    return _first_percent(handler.option("-m"), _EARLYOOM_DEFAULT_MEMORY_PERCENT)


def _handler_name(proc_root: str, pid: str, argv: tuple[str, ...]) -> str | None:
    comm = _read_comm(proc_root, pid).lower()
    executable = os.path.basename(argv[0]).lower() if argv else ""
    for name in ("earlyoom", "nohang", "systemd-oomd"):
        if comm == name or executable == name:
            return name
    return None


def detect_oom_handlers(
    proc_root: str | None = None,
) -> dict[str, tuple[OomHandler, ...]]:
    """Find running earlyoom, nohang, and systemd-oomd processes without spawning tools."""
    proc_root = proc_root or os.environ.get("TAEMA_PROCROOT", "/proc")
    result: dict[str, list[OomHandler]] = {
        "earlyoom": [],
        "nohang": [],
        "systemd-oomd": [],
    }
    try:
        pids = sorted(
            (entry for entry in os.listdir(proc_root) if entry.isdecimal()),
            key=int,
        )
    except OSError:
        return {name: () for name in result}
    for pid_text in pids:
        argv = _read_cmdline(proc_root, pid_text)
        name = _handler_name(proc_root, pid_text, argv)
        if name is None:
            continue
        options = earlyoom_options(argv) if name == "earlyoom" else ()
        result[name].append(OomHandler(name, int(pid_text), argv, options))
    return {name: tuple(items) for name, items in result.items()}


def display_earlyoom(handler: OomHandler) -> str:
    """Render supported earlyoom thresholds and regex settings in a compact stable form."""
    values = dict(handler.options)
    memory = values.get("-m", "10 (default)")
    swap = values.get("-s", "10 (default)")
    parts = ["-m %s%%" % memory.split(",", 1)[0], "-s %s%%" % swap.split(",", 1)[0]]
    for flag in ("--prefer", "--avoid"):
        if flag in values:
            parts.append("%s %s" % (flag, values[flag]))
    return " ".join(parts)


class PsiTriggerMonitor:
    """Own PSI trigger fds and surface ready metric names through an epoll fd."""

    def __init__(self, epoll=None):
        self._epoll = select.epoll() if epoll is None else epoll
        self._fds: dict[int, str] = {}

    def fileno(self) -> int:
        return self._epoll.fileno()

    @property
    def metrics(self) -> tuple[str, ...]:
        return tuple(self._fds.values())

    def watch_fd(self, metric: str, fd: int, events: int | None = None) -> None:
        """Register a trigger fd; tests may inject a pipe read end as a fake PSI source."""
        flags = (
            select.EPOLLPRI
            | select.EPOLLIN
            | select.EPOLLERR
            | getattr(select, "EPOLLET", 0)
            if events is None
            else events
        )
        self._epoll.register(fd, flags)
        self._fds[fd] = metric

    def open_triggers(self, path: str, settings: Mapping[str, str]) -> list[str]:
        """Open one writable PSI fd per configured trigger, recording unavailable metrics."""
        failures = []
        for metric, setting in settings.items():
            fd = None
            try:
                trigger, amount, window = psi_trigger(metric, setting)
                fd = os.open(
                    path,
                    os.O_RDWR | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0),
                )
                payload = ("%s %d %d\0" % (trigger, amount, window)).encode("ascii")
                if os.write(fd, payload) != len(payload):
                    raise OSError("incomplete PSI trigger write")
                self.watch_fd(metric, fd)
            except (OSError, ValueError) as error:
                failures.append("%s: %s" % (metric, error))
                if fd is not None:
                    os.close(fd)
        return failures

    def poll(self) -> list[str]:
        """Return each metric whose trigger fired since the prior call."""
        ready = []
        for fd, _events in self._epoll.poll(0):
            metric = self._fds.get(fd)
            if metric is not None:
                ready.append(metric)
        return ready

    def close(self) -> None:
        for fd in tuple(self._fds):
            try:
                self._epoll.unregister(fd)
            except OSError:
                pass
            try:
                os.close(fd)
            except OSError:
                pass
            self._fds.pop(fd, None)
        self._epoll.close()
