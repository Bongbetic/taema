"""Shared parsers for human-entered sizes, durations, and local times."""

from datetime import date, datetime, time, timedelta
import math
import re

_SIZE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([kmgt](?:i?b)?|b)?\s*$", re.IGNORECASE)
_DURATION_PART = re.compile(r"(\d+(?:\.\d+)?)\s*(ms|s|m|h|d|w)", re.IGNORECASE)
_DURATION_UNITS = {
    "ms": 0.001,
    "s": 1,
    "m": 60,
    "h": 3600,
    "d": 86400,
    "w": 604800,
}
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


def parse_size(value):
    """Parse bytes or a binary unit such as ``512M`` or ``1.5G`` into bytes."""
    if isinstance(value, (int, float)):
        amount, unit = float(value), ""
    elif isinstance(value, str):
        match = _SIZE.fullmatch(value)
        if match is None:
            raise ValueError("size must look like 512M or 1.5G")
        amount, unit = float(match.group(1)), (match.group(2) or "").lower()
    else:
        raise ValueError("size must be a number or a unit such as 512M")
    if not math.isfinite(amount) or amount < 0:
        raise ValueError("size must be a finite non-negative value")
    return math.ceil(amount * _SIZE_UNITS[unit])


def parse_duration(value):
    """Parse seconds or a compound duration such as ``90s``, ``2h30m``, or ``7d``."""
    if isinstance(value, (int, float)):
        seconds = float(value)
    elif isinstance(value, str):
        text = value.strip().lower()
        if not text:
            raise ValueError("duration cannot be empty")
        try:
            seconds = float(text)
        except ValueError:
            seconds = 0.0
            offset = 0
            parts = list(_DURATION_PART.finditer(text))
            if not parts:
                raise ValueError("duration must look like 90s or 2h30m") from None
            for part in parts:
                if part.start() != offset:
                    raise ValueError("duration must look like 90s or 2h30m")
                seconds += float(part.group(1)) * _DURATION_UNITS[part.group(2)]
                offset = part.end()
            if offset != len(text):
                raise ValueError("duration must look like 90s or 2h30m")
    else:
        raise ValueError("duration must be a number or a unit such as 90s")
    if not math.isfinite(seconds) or seconds < 0:
        raise ValueError("duration must be a finite non-negative value")
    return seconds


def parse_time(value, now=None):
    """Parse a local date/time into an aware datetime.

    ``yesterday`` means local midnight yesterday. ``HH:MM`` means its most recent
    local occurrence, which is useful for ``--since`` filters that cross midnight.
    ISO dates and datetimes are also accepted.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValueError("time cannot be empty")
    current = now or datetime.now().astimezone()
    if current.tzinfo is None:
        current = current.astimezone()
    text = value.strip().lower()
    if text == "yesterday":
        return datetime.combine(current.date() - timedelta(days=1), time.min).replace(
            tzinfo=current.tzinfo
        )
    if re.fullmatch(r"\d{1,2}:\d{2}", text):
        try:
            clock = time.fromisoformat(text)
        except ValueError:
            raise ValueError("time must look like yesterday or 09:00") from None
        result = datetime.combine(current.date(), clock).replace(tzinfo=current.tzinfo)
        if result > current:
            result -= timedelta(days=1)
        return result
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        try:
            parsed_date = date.fromisoformat(text)
        except ValueError:
            raise ValueError(
                "time must look like yesterday, 09:00, or an ISO date"
            ) from None
        return datetime.combine(parsed_date, time.min).replace(tzinfo=current.tzinfo)
    return parsed.replace(tzinfo=current.tzinfo) if parsed.tzinfo is None else parsed
