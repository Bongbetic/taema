"""Pure pair learning decisions, separated from persistence and process control."""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass
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


@dataclass(frozen=True, slots=True)
class PairEvidence:
    """Validated immutable evidence consumed by the pair learning decision."""

    ex_stop: float = 0.0
    ex_keep: float = 0.0
    ex_last: str | None = None
    stop: float = 0.0
    keep: float = 0.0
    regret_keep: float = 0.0
    self_stop: float = 0.0
    suspended_until: float = 0.0
    launches: float = 0.0
    inferred_kills: float = 0.0
    kills: float = 0.0
    days: tuple[int, ...] = ()
    first_seen: float = 0.0
    closes: float = 0.0
    last_keep: float = 0.0

    @classmethod
    def from_record(
        cls, record: Mapping[str, object] | None, now: float
    ) -> PairEvidence:
        """Copy persisted data into a validated immutable decision input."""
        record = record if isinstance(record, Mapping) else {}
        raw_days = record.get("days", ())
        days = (
            tuple(dict.fromkeys(day for day in raw_days if type(day) is int))
            if isinstance(raw_days, (list, tuple))
            else ()
        )
        last = record.get("ex_last")
        return cls(
            ex_stop=_number(record, "ex_stop"),
            ex_keep=_number(record, "ex_keep"),
            ex_last=last if isinstance(last, str) else None,
            stop=_number(record, "stop"),
            keep=_number(record, "keep"),
            regret_keep=_number(record, "regret_keep"),
            self_stop=_number(record, "self_stop"),
            suspended_until=_number(record, "suspended_until"),
            launches=_number(record, "launches"),
            inferred_kills=_number(record, "inferred_kills", _number(record, "kills")),
            kills=_number(record, "kills"),
            days=days,
            first_seen=_number(record, "first_seen", now),
            closes=_number(record, "closes"),
            last_keep=_number(record, "last_keep"),
        )


def decide_pair(
    pair: PairEvidence | None,
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
    """Return a deterministic decision from one immutable pair evidence snapshot."""
    if not pair:
        return "ask", 0.0, "no evidence"

    if pair.suspended_until > now:
        return (
            "ask",
            0.0,
            "suspended after regret until day +%d"
            % int((pair.suspended_until - now) // DAY + 1),
        )

    explicit_stop = pair.ex_stop
    explicit_keep = pair.ex_keep
    inferred_stop = pair.stop
    inferred_keep = pair.keep + pair.regret_keep
    self_stop = pair.self_stop
    self_authority = authority == "aggressive" and allow_self_authority
    stop = inferred_stop + (self_stop if self_authority else 0.0)
    keep = inferred_keep

    if explicit_stop or explicit_keep:
        last = pair.ex_last or ("stop" if explicit_stop >= explicit_keep else "keep")
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

    if pair.launches and not pair.kills:
        return "keep", 0.5, "launcher pattern: survivors are what the job started"

    total = stop + keep
    ratio = stop / total if total else 0.0
    confidence_total = inferred_stop + self_stop + keep
    confidence = (
        (inferred_stop + self_stop) / confidence_total if confidence_total else 0.0
    )
    kills = pair.inferred_kills
    distinct_days = len(pair.days)
    burn_in = (
        now - pair.first_seen >= burn_in_days * DAY or pair.closes >= burn_in_closes
    )
    quiet = not keep and now - pair.last_keep > SILENT_KEEP_FREE_DAYS
    old = now - pair.first_seen > SILENT_MIN_AGE

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
