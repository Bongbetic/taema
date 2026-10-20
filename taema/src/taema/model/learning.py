"""Pure pair learning decisions, separated from persistence and process control."""

from __future__ import annotations

import math
from collections.abc import Mapping
from typing import Literal

DAY = 86400.0
SILENT_KILLS = 5
SILENT_DAYS = 3
SILENT_RATIO = 0.9
SILENT_KEEP_FREE_DAYS = 30 * DAY
SILENT_MIN_AGE = DAY
BURN_IN_DAYS = 7
BURN_IN_CLOSES = 20
SELF_AUTHORITY_SUCCESSES = 3

Action = Literal["ask", "stop", "keep"]


def _number(record: Mapping[str, object], key: str, default: float = 0.0) -> float:
    value = record.get(key)
    if (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
    ):
        return float(value)
    return default


def _text(record: Mapping[str, object], key: str) -> str | None:
    value = record.get(key)
    return value if isinstance(value, str) else None


def decide_pair(
    pair: Mapping[str, object] | None,
    now: float,
    *,
    authority: str = "learned",
    allow_self_authority: bool = False,
    silent_kills: int = SILENT_KILLS,
    silent_days: int = SILENT_DAYS,
    silent_ratio: float = SILENT_RATIO,
    burn_in_days: float = BURN_IN_DAYS,
    burn_in_closes: int = BURN_IN_CLOSES,
) -> tuple[Action, float, str]:
    """Return a deterministic decision for one pair without reading or mutating state."""
    if not pair:
        return "ask", 0.0, "no evidence"

    suspended_until = _number(pair, "suspended_until")
    if suspended_until > now:
        return (
            "ask",
            0.0,
            "suspended after regret until day +%d"
            % int((suspended_until - now) // DAY + 1),
        )

    explicit_stop = _number(pair, "ex_stop")
    explicit_keep = _number(pair, "ex_keep")
    inferred_stop = _number(pair, "stop")
    inferred_keep = _number(pair, "keep") + _number(pair, "regret_keep")
    self_stop = _number(pair, "self_stop")
    self_authority = authority == "aggressive" and allow_self_authority
    stop = inferred_stop + (self_stop if self_authority else 0.0)
    keep = inferred_keep

    if explicit_stop or explicit_keep:
        last = _text(pair, "ex_last") or (
            "stop" if explicit_stop >= explicit_keep else "keep"
        )
        if last == "stop" and keep < explicit_stop:
            return (
                "stop",
                1.0,
                "answered stop (weight %.0f), contrary %.2f" % (explicit_stop, keep),
            )
        if last == "keep" and stop < explicit_keep:
            return (
                "keep",
                1.0,
                "answered keep (weight %.0f), contrary %.2f" % (explicit_keep, stop),
            )
        return "ask", 0.0, "answer overturned by contrary evidence"

    if _number(pair, "launches") and not _number(pair, "kills"):
        return "keep", 0.5, "launcher pattern: survivors are what the job started"

    total = stop + keep
    ratio = stop / total if total else 0.0
    confidence_total = inferred_stop + self_stop + keep
    confidence = (
        (inferred_stop + self_stop) / confidence_total if confidence_total else 0.0
    )
    kills = _number(pair, "inferred_kills", _number(pair, "kills"))
    raw_days = pair.get("days", ())
    observed_days = []
    if isinstance(raw_days, (list, tuple)):
        observed_days = list(dict.fromkeys(day for day in raw_days if type(day) is int))
    distinct_days = len(observed_days)
    first_seen = _number(pair, "first_seen", now)
    closes = _number(pair, "closes")
    burn_in = now - first_seen >= burn_in_days * DAY or closes >= burn_in_closes
    last_keep = _number(pair, "last_keep")
    quiet = not keep and now - last_keep > SILENT_KEEP_FREE_DAYS
    old = now - first_seen > SILENT_MIN_AGE

    if (
        kills >= silent_kills
        and distinct_days >= silent_days
        and ratio >= silent_ratio
        and quiet
        and old
        and burn_in
    ):
        return (
            "stop",
            confidence,
            "silent: %.0f kills on %d days, ratio %.2f" % (kills, distinct_days, ratio),
        )

    if (
        self_authority
        and self_stop >= SELF_AUTHORITY_SUCCESSES * 0.5
        and self_stop > keep
    ):
        return (
            "stop",
            confidence,
            "self-authority: %d successful automatic stops" % int(self_stop / 0.5),
        )

    if keep > stop and keep >= 1:
        return "keep", keep / total, "keep evidence %.2f vs stop %.2f" % (keep, stop)

    return (
        "ask",
        confidence,
        "kills %.2f/%d, days %d/%d, ratio %.2f, quiet %s, old %s, burn-in %s"
        % (kills, silent_kills, distinct_days, silent_days, ratio, quiet, old, burn_in),
    )
