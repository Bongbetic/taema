"""One authorization ladder for every lifecycle trigger (issue #5, spec #1 Implementation Decisions 2).

Every daemon path that moves, stops, or adopts -- owner exit, unit adoption, auto adoption, GUI and
job survivor containment, GC candidate selection, GC stops, empty-leaf removal, session end -- plus
the manual ``taema kill`` asks :func:`authorize` instead of checking the mode itself: it takes the
trigger, the mode, and the known facts, and returns act, would-act, or keep, with a reason.

The ladder evaluates five slots, in spec order (``SLOTS``):

1. ``hard_safety`` -- never root/other users/protected/self, dependencies, PID reuse. No trigger
   carries hard-safety facts in 0.2.1 (engine.stop/plan_stop still revalidate at actuation), so
   the slot passes through.
2. ``veto`` -- no veto exists in 0.2.1; issue #10 plugs it in here.
3. ``hold`` -- no hold/snooze exists yet; later M0 tickets plug it in here.
4. ``mode_capability`` -- per-trigger, per-mode **table** (``_CAPABILITY``, with two fact rules for
   the auto-mode special cases). This is the one table the M0 tickets edit instead of scattered
   call sites: e.g. issue #11 flips ``OWNER_EXIT``'s ``adopt`` cell from ``would`` to ``act``.
5. ``authority`` -- pair/signature/unit authority. It can only *deny* an otherwise allowed action
   (0.2.1 rule: a unit with ``kill.survive_logout`` survives session end in every mode) and it
   stamps the ``authority`` an ``act`` must use: ``unit`` (engine.stop under unit rules), ``pair``
   (every member re-checked through engine.auto_stop_ok at actuation), ``manual`` (explicit CLI
   stop) or ``mode`` (capability alone; moves and empty-leaf removal).

Verdicts: ``act`` (perform the action), ``would`` (the mode declines; the caller records exactly
the would-action 0.2.1 logged), ``keep`` (nothing happens; the caller records its keep as before).
A deny in slots 1-3 short-circuits to ``keep``; a deny in slot 5 overrides ``act``/``would``.
``Decision.slot`` names the last slot whose vote stood; ``Decision.reason`` always explains the
outcome. Unknown triggers or modes raise ``ValueError`` (a programming error, not a runtime fact).

Member-level pair authority (auto_stop_ok, the explicit-answer SIGKILL rule) stays where it runs
today -- at actuation inside engine/daemon -- and is re-checked there after the ladder says ``act``;
the authority slot is the trigger-level home for it as the M0 tickets land.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Final, Literal

__all__ = [
    "ACT", "WOULD_ACT", "KEEP", "SLOTS", "MODES", "Facts", "Decision", "authorize",
    "OWNER_EXIT", "UNIT_ADOPT", "AUTO_ADOPT", "GUI_CLOSE", "JOB_SURVIVORS", "LEFTOVER_LEAVES",
    "GC_STOP", "GC_REMOVE_EMPTY", "SESSION_END", "MANUAL_STOP",
]

Mode = Literal["observe", "adopt", "enforce", "auto"]
Verdict = Literal["act", "would", "keep"]
Authority = Literal["", "mode", "unit", "pair", "manual"]
Slot = Literal["hard_safety", "veto", "hold", "mode_capability", "authority"]
Vote = Literal["pass", "deny"]
Trigger = Literal["owner_exit", "unit_adopt", "auto_adopt", "gui_close", "job_survivors",
                  "leftover_leaves", "gc_stop", "gc_remove_empty", "session_end", "manual_stop"]
SlotFn = Callable[[str, str, "Facts"], tuple[Vote, str]]

# verdicts
ACT: Final[Verdict] = "act"
WOULD_ACT: Final[Verdict] = "would"
KEEP: Final[Verdict] = "keep"

# slots, in spec order (spec #1, Implementation Decisions 2)
HARD_SAFETY: Final[Slot] = "hard_safety"
VETO: Final[Slot] = "veto"
HOLD: Final[Slot] = "hold"
MODE_CAPABILITY: Final[Slot] = "mode_capability"
AUTHORITY: Final[Slot] = "authority"
SLOTS: Final[tuple[Slot, ...]] = (HARD_SAFETY, VETO, HOLD, MODE_CAPABILITY, AUTHORITY)

MODES: Final[tuple[Mode, ...]] = ("observe", "adopt", "enforce", "auto")

# triggers: every lifecycle decision point, named after the daemon/CLI path that asks for them
OWNER_EXIT: Final[Trigger] = "owner_exit"            # Daemon.stop_leaf (owner bound scope)
UNIT_ADOPT: Final[Trigger] = "unit_adopt"            # Daemon.adopt_pass (unit/carve move ops)
AUTO_ADOPT: Final[Trigger] = "auto_adopt"            # Daemon.adopt_pass -> auto_adopt
GUI_CLOSE: Final[Trigger] = "gui_close"              # Daemon.after_observe -> gui_close
JOB_SURVIVORS: Final[Trigger] = "job_survivors"      # Daemon.decide_job (standalone + survivors)
LEFTOVER_LEAVES: Final[Trigger] = "leftover_leaves"  # gc_candidates(auto=) and end_session's list
GC_STOP: Final[Trigger] = "gc_stop"                  # Daemon.gc_pass, per non-empty candidate
GC_REMOVE_EMPTY: Final[Trigger] = "gc_remove_empty"  # Daemon._gc_empty / sync / remove_leaf
SESSION_END: Final[Trigger] = "session_end"          # Daemon.end_session
MANUAL_STOP: Final[Trigger] = "manual_stop"          # cli.cmd_kill (`taema kill`)

# authority values an `act` carries to its actuation
AUTHORITY_MODE: Final[Authority] = "mode"
AUTHORITY_UNIT: Final[Authority] = "unit"
AUTHORITY_PAIR: Final[Authority] = "pair"
AUTHORITY_MANUAL: Final[Authority] = "manual"

# a capability cell: (verdict, authority for an act, reason)
_Cell = tuple[Verdict, Authority, str]


@dataclass(frozen=True)
class Facts:
    """Known facts the slots may consult. Defaults are "not applicable", which passes through.

    scope: the cgroup leaf/rel the trigger targets (inputs for future veto/hold matching).
    leftover: target sits under leftover/* (GC stop candidates).
    shared: target is the shared/ helper tree (session end).
    unit_survive_logout: the target's unit sets kill.survive_logout (session end).
    """

    scope: str = ""
    leftover: bool = False
    shared: bool = False
    unit_survive_logout: bool = False


@dataclass(frozen=True)
class Decision:
    """The ladder's answer: act / would-act / keep, why, which slot decided, and authority."""

    verdict: Verdict
    slot: Slot
    reason: str
    authority: Authority = ""


# ---- slot 4: mode capability (the one table the M0 tickets edit) -------------------------------

_CAPABILITY: Final[dict[str, dict[str, _Cell]]] = {
    OWNER_EXIT: {
        "observe": (WOULD_ACT, "", "owner exit: observe only logs would_stop"),
        "adopt": (WOULD_ACT, "", "owner exit: adopt suppresses owner-bound stops (0.2.1)"),
        "enforce": (ACT, AUTHORITY_UNIT, "owner exit: enforce stops the bound scope"),
        "auto": (ACT, AUTHORITY_UNIT, "owner exit: an owner-bound scope is the user's own request"),
    },
    UNIT_ADOPT: {
        "observe": (WOULD_ACT, "", "unit adopt: observe only logs adopt_would"),
        "adopt": (ACT, AUTHORITY_MODE, "unit adopt: adopt moves unit-matched processes"),
        "enforce": (ACT, AUTHORITY_MODE, "unit adopt: enforce moves unit-matched processes"),
        "auto": (ACT, AUTHORITY_MODE, "unit adopt: auto moves unit-matched processes"),
    },
    AUTO_ADOPT: {
        "observe": (WOULD_ACT, "", "app adopt: observe only logs adopt_would"),
        "adopt": (ACT, AUTHORITY_MODE, "app adopt: adopt moves every eligible app root"),
        "enforce": (ACT, AUTHORITY_MODE, "app adopt: enforce moves every eligible app root"),
        "auto": (ACT, AUTHORITY_MODE, "auto adopt: every eligible app root gets its own scope"),
    },
    GUI_CLOSE: {
        "observe": (KEEP, "", "gui close: only auto contains GUI survivors (0.2.1)"),
        "adopt": (KEEP, "", "gui close: only auto contains GUI survivors (0.2.1)"),
        "enforce": (KEEP, "", "gui close: only auto contains GUI survivors (0.2.1)"),
        "auto": (ACT, AUTHORITY_MODE, "gui close: auto moves survivors to leftover/<owner>-<id>"),
    },
    JOB_SURVIVORS: {
        "observe": (KEEP, "", "job survivors: only auto acts on closed-job survivors (0.2.1)"),
        "adopt": (KEEP, "", "job survivors: only auto acts on closed-job survivors (0.2.1)"),
        "enforce": (KEEP, "", "job survivors: only auto acts on closed-job survivors (0.2.1)"),
        "auto": (ACT, AUTHORITY_MODE,
                 "job survivors: auto adopts standalone and stops decided survivors"),
    },
    LEFTOVER_LEAVES: {
        "observe": (KEEP, "", "leftover leaves: only auto treats leftover/* as scopes (0.2.1)"),
        "adopt": (KEEP, "", "leftover leaves: only auto treats leftover/* as scopes (0.2.1)"),
        "enforce": (KEEP, "", "leftover leaves: only auto treats leftover/* as scopes (0.2.1)"),
        "auto": (ACT, AUTHORITY_MODE,
                 "leftover leaves: auto GCs and session-ends leftover/* individually"),
    },
    GC_STOP: {
        "observe": (WOULD_ACT, "", "gc stop: observe only logs gc_would_stop"),
        "adopt": (WOULD_ACT, "", "gc stop: adopt only logs gc_would_stop (0.2.1)"),
        "enforce": (ACT, AUTHORITY_UNIT, "gc stop: enforce stops idle candidates"),
        "auto": (WOULD_ACT, "", "gc stop: auto stops only leftover/* candidates (0.2.1)"),
    },
    GC_REMOVE_EMPTY: {
        "observe": (WOULD_ACT, "", "empty leaf: observe only logs gc_would_remove_empty"),
        "adopt": (ACT, AUTHORITY_MODE, "empty leaf: adopt removes unused scopes"),
        "enforce": (ACT, AUTHORITY_MODE, "empty leaf: enforce removes unused scopes"),
        "auto": (ACT, AUTHORITY_MODE, "empty leaf: auto removes unused scopes"),
    },
    SESSION_END: {
        "observe": (WOULD_ACT, "", "session end: observe only logs would_stop"),
        "adopt": (WOULD_ACT, "", "session end: adopt only logs would_stop (0.2.1)"),
        "enforce": (ACT, AUTHORITY_UNIT, "session end: enforce stops every scope"),
        "auto": (ACT, AUTHORITY_PAIR, "session end: auto stops scopes each pair authorises"),
    },
    MANUAL_STOP: {
        "observe": (ACT, AUTHORITY_MANUAL, "explicit taema kill: a user request acts in every mode"),
        "adopt": (ACT, AUTHORITY_MANUAL, "explicit taema kill: a user request acts in every mode"),
        "enforce": (ACT, AUTHORITY_MANUAL, "explicit taema kill: a user request acts in every mode"),
        "auto": (ACT, AUTHORITY_MANUAL, "explicit taema kill: a user request acts in every mode"),
    },
}


def _capability(trigger: str, mode: str, facts: Facts) -> tuple[Verdict, Authority, str]:
    """Slot 4: fact rules first, then the per-trigger, per-mode table above."""
    if trigger == GC_STOP and mode == "auto":
        if facts.leftover:
            return ACT, AUTHORITY_PAIR, "gc stop: auto stops leftover/* under pair/idle authority"
        return WOULD_ACT, "", "gc stop: auto stops only leftover/* candidates (0.2.1)"
    if trigger == SESSION_END and mode == "auto" and facts.shared:
        return KEEP, "", "session end: shared/ is never stopped in auto"
    row = _CAPABILITY.get(trigger)
    if row is None or mode not in row:
        raise ValueError("unknown trigger or mode: %r / %r" % (trigger, mode))
    verdict, authority, reason = row[mode]
    return verdict, authority, reason


# ---- slots 1-3: blocking, pass through in 0.2.1 -------------------------------------------------

def _hard_safety(_trigger: str, _mode: str, _facts: Facts) -> tuple[Vote, str]:
    """Slot 1: hard safety/dependencies (never root/other users/protected/self, revalidated at
    actuation by engine.stop/plan_stop). No trigger supplies hard-safety facts in 0.2.1."""
    return "pass", ""


def _veto(_trigger: str, _mode: str, _facts: Facts) -> tuple[Vote, str]:
    """Slot 2: vetoes (do-not-kill/dnk/never). None exist in 0.2.1; issue #10 plugs in here."""
    return "pass", ""


def _hold(_trigger: str, _mode: str, _facts: Facts) -> tuple[Vote, str]:
    """Slot 3: holds and timed snoozes. None exist in 0.2.1; later M0 tickets plug in here."""
    return "pass", ""


# ---- slot 5: pair/signature/unit authority ------------------------------------------------------

def _authority(trigger: str, _mode: str, facts: Facts) -> tuple[Vote, str]:
    """Slot 5: trigger-level authority. Only unit kill.survive_logout denies in 0.2.1 (session
    end); per-member pair authority is re-checked at actuation after an `act` verdict."""
    if trigger == SESSION_END and facts.unit_survive_logout:
        return "deny", "unit authority: unit sets kill.survive_logout"
    return "pass", ""


def authorize(trigger: str, mode: str, facts: Facts | None = None) -> Decision:
    """Run the authorization ladder for one lifecycle trigger.

    Evaluates the five slots of `SLOTS` in order and returns the Decision (act/would/keep, the
    deciding slot, a reason, and the authority an `act` must use). Raises ValueError for an
    unknown trigger or mode.
    """
    f = facts if facts is not None else Facts()
    # slot pairs resolved per call: the order is visible here and patchable in tests;
    # the first three names mirror SLOTS[:3] and only ever deny or pass through
    blocking: tuple[tuple[Slot, SlotFn], ...] = (
        (HARD_SAFETY, _hard_safety),
        (VETO, _veto),
        (HOLD, _hold),
    )
    for name, fn in blocking:
        vote, why = fn(trigger, mode, f)
        if vote == "deny":
            return Decision(KEEP, name, why)
    verdict, authority, why = _capability(trigger, mode, f)
    if verdict == KEEP:
        return Decision(KEEP, MODE_CAPABILITY, why)
    vote, deny_reason = _authority(trigger, mode, f)
    if vote == "deny":
        return Decision(KEEP, AUTHORITY, deny_reason)
    return Decision(verdict, MODE_CAPABILITY, why, authority)
