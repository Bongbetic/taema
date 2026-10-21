"""Unprivileged oom_score_adj reads and raises for managed process scopes."""

import os

from . import process

MIN_SCORE = -1000
MAX_SCORE = 1000


def _path(pid):
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 1:
        raise ValueError("invalid process id")
    return "%s/%d/oom_score_adj" % (process.PROC, pid)


def read_score(pid):
    """Return a validated kernel OOM score adjustment for one process."""
    with open(_path(pid), encoding="ascii") as source:
        raw = source.read().strip()
    digits = raw[1:] if raw.startswith("-") else raw
    if not digits or not digits.isdecimal():
        raise ValueError("invalid oom_score_adj value")
    value = int(raw)
    if not MIN_SCORE <= value <= MAX_SCORE:
        raise ValueError("oom_score_adj is out of range")
    return value


def write_score(pid, value, expected_start=None, original=None):
    """Raise a process's OOM score; callers must never lower an existing score."""
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not MIN_SCORE <= value <= MAX_SCORE
    ):
        raise ValueError("invalid oom_score_adj value")
    current = read_score(pid)
    if expected_start is not None and process.starttime(pid) != expected_start:
        raise ValueError("process identity changed before oom_score_adj write")
    if original is not None and current != original:
        raise ValueError("oom_score_adj changed before priority write")
    if value < current:
        raise ValueError("refusing to lower oom_score_adj")
    fd = os.open(
        _path(pid),
        os.O_WRONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        current = read_score(pid)
        if expected_start is not None and process.starttime(pid) != expected_start:
            raise ValueError("process identity changed before oom_score_adj write")
        if original is not None and current != original:
            raise ValueError("oom_score_adj changed before priority write")
        if value < current:
            raise ValueError("refusing to lower oom_score_adj")
        data = (str(value) + "\n").encode("ascii")
        if os.write(fd, data) != len(data):
            raise OSError("incomplete oom_score_adj write")
    finally:
        os.close(fd)
