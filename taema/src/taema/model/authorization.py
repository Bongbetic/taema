"""One authorization ladder for every lifecycle trigger (issue #5, spec #1 Implementation Decisions 2).

Every daemon path that moves, stops, or adopts -- owner exit, unit adoption, auto adoption, GUI and
job survivor containment, GC candidate selection, GC stops, empty-leaf removal, session end -- plus
the manual ``taema kill`` asks :func:`authorize` instead of checking the mode itself: it takes the
trigger, the mode, and the known facts, and returns act, would-act, or keep, with a reason.

The ladder evaluates five slots, in spec order (``SLOTS``):

1. ``hard_safety`` -- never root/other users/protected/self, dependencies, PID reuse. Read-only
   explanation callers may supply a resolved blocker; engine.stop/plan_stop still revalidate at
   actuation.
2. ``veto`` -- a user-created veto blocks matching stop targets in every mode.
3. ``hold`` -- a global hold, scope hold, or active snooze blocks stop and reclaim actions.
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
today -- at actuation inside engine/daemon -- and is re-checked there after the ladder says ``act``.
Read-only pair explanations supply the selected pair result to the same trigger-level authority
slot.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Final, Literal

__all__ = [
    "ACT",
    "WOULD_ACT",
    "KEEP",
    "SLOTS",
    "MODES",
    "Facts",
    "Decision",
    "authorize",
    "OWNER_EXIT",
    "UNIT_ADOPT",
    "AUTO_ADOPT",
    "GUI_CLOSE",
    "JOB_SURVIVORS",
    "LEFTOVER_LEAVES",
    "GC_STOP",
    "GC_REMOVE_EMPTY",
    "SESSION_END",
    "MANUAL_STOP",
    "RECLAIM",
    "MANUAL_RECLAIM",
    "QOS",
    "FREEZE",
    "MANUAL_FREEZE",
]

Mode = Literal["observe", "adopt", "enforce", "auto"]
Verdict = Literal["act", "would", "keep"]
Authority = Literal["", "mode", "unit", "pair", "manual"]
Slot = Literal["hard_safety", "veto", "hold", "mode_capability", "authority"]
Vote = Literal["pass", "deny"]
Trigger = Literal[
    "owner_exit",
    "unit_adopt",
    "auto_adopt",
    "gui_close",
    "job_survivors",
    "leftover_leaves",
    "gc_stop",
    "gc_remove_empty",
    "session_end",
    "manual_stop",
    "reclaim",
    "manual_reclaim",
    "qos",
    "freeze",
    "manual_freeze",
]
GovernorAction = Literal[
    "adopt", "budget", "contain", "deprioritize", "freeze", "reclaim", "remove", "stop"
]
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
OWNER_EXIT: Final[Trigger] = "owner_exit"  # Daemon.stop_leaf (owner bound scope)
UNIT_ADOPT: Final[Trigger] = "unit_adopt"  # Daemon.adopt_pass (unit/carve move ops)
AUTO_ADOPT: Final[Trigger] = "auto_adopt"  # Daemon.adopt_pass -> auto_adopt
GUI_CLOSE: Final[Trigger] = "gui_close"  # Daemon.after_observe -> gui_close
JOB_SURVIVORS: Final[Trigger] = (
    "job_survivors"  # Daemon.decide_job (standalone + survivors)
)
LEFTOVER_LEAVES: Final[Trigger] = (
    "leftover_leaves"  # gc_candidates(auto=) and end_session's list
)
GC_STOP: Final[Trigger] = "gc_stop"  # Daemon.gc_pass, per non-empty candidate
GC_REMOVE_EMPTY: Final[Trigger] = (
    "gc_remove_empty"  # Daemon._gc_empty / sync / remove_leaf
)
SESSION_END: Final[Trigger] = "session_end"  # Daemon.end_session
MANUAL_STOP: Final[Trigger] = "manual_stop"  # cli.cmd_kill (`taema kill`)
RECLAIM: Final[Trigger] = "reclaim"  # daemon memory governor
MANUAL_RECLAIM: Final[Trigger] = "manual_reclaim"  # explicit memory CLI action
QOS: Final[Trigger] = "qos"  # Daemon.qos_pass, reversible priority changes
FREEZE: Final[Trigger] = "freeze"  # idle leftover quarantine
MANUAL_FREEZE: Final[Trigger] = "manual_freeze"  # explicit CLI freeze

# Every lifecycle trigger declares its governor action. New actions such as reclaim must be
# classified here so the hold-slot contract test proves that the ladder blocks them.
TRIGGER_ACTIONS: Final[dict[str, GovernorAction]] = {
    OWNER_EXIT: "stop",
    UNIT_ADOPT: "adopt",
    AUTO_ADOPT: "adopt",
    GUI_CLOSE: "contain",
    JOB_SURVIVORS: "stop",
    LEFTOVER_LEAVES: "stop",
    GC_STOP: "stop",
    GC_REMOVE_EMPTY: "remove",
    SESSION_END: "stop",
    MANUAL_STOP: "stop",
    RECLAIM: "reclaim",
    MANUAL_RECLAIM: "reclaim",
    QOS: "deprioritize",
    FREEZE: "freeze",
    MANUAL_FREEZE: "freeze",
}
HOLD_BLOCKED_ACTIONS: Final[frozenset[GovernorAction]] = frozenset(
    ("freeze", "stop", "reclaim")
)
VETO_BLOCKED_ACTIONS: Final[frozenset[GovernorAction]] = frozenset(
    ("budget", "deprioritize", "freeze", "reclaim", "stop")
)

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

    scope: the cgroup leaf/rel the trigger targets.
    vetoed: the matching user veto, already resolved from the store and observed members.
    leftover: target sits under leftover/* (GC stop candidates).
    shared: target is the shared/ helper tree (session end).
    unit_survive_logout: the target's unit sets kill.survive_logout (session end).
    hard_safety and pair_action: resolved facts supplied by read-only explanation callers.
    """

    scope: str = ""
    leftover: bool = False
    shared: bool = False
    unit_survive_logout: bool = False
    vetoed: str = ""
    veto_source: str = ""
    veto_target: str = ""
    unit_veto: str = ""
    held: str = ""
    suppress_stops: bool = False
    hard_safety: str = ""
    force_veto: bool = False
    pair_action: str = ""
    pair_reason: str = ""
    pair_explicit: bool = False
    learn_authority: str = "learned"


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
        "adopt": (
            ACT,
            AUTHORITY_UNIT,
            "owner exit: adopt honors explicit owner binding",
        ),
        "enforce": (ACT, AUTHORITY_UNIT, "owner exit: enforce stops the bound scope"),
        "auto": (
            ACT,
            AUTHORITY_UNIT,
            "owner exit: an owner-bound scope is the user's own request",
        ),
    },
    UNIT_ADOPT: {
        "observe": (WOULD_ACT, "", "unit adopt: observe only logs adopt_would"),
        "adopt": (
            ACT,
            AUTHORITY_MODE,
            "unit adopt: adopt moves unit-matched processes",
        ),
        "enforce": (
            ACT,
            AUTHORITY_MODE,
            "unit adopt: enforce moves unit-matched processes",
        ),
        "auto": (ACT, AUTHORITY_MODE, "unit adopt: auto moves unit-matched processes"),
    },
    AUTO_ADOPT: {
        "observe": (WOULD_ACT, "", "app adopt: observe only logs adopt_would"),
        "adopt": (
            ACT,
            AUTHORITY_MODE,
            "app adopt: adopt moves every eligible app root",
        ),
        "enforce": (
            ACT,
            AUTHORITY_MODE,
            "app adopt: enforce moves every eligible app root",
        ),
        "auto": (
            ACT,
            AUTHORITY_MODE,
            "auto adopt: every eligible app root gets its own scope",
        ),
    },
    GUI_CLOSE: {
        "observe": (
            WOULD_ACT,
            "",
            "gui close: observe logs survivors it would contain",
        ),
        "adopt": (
            ACT,
            AUTHORITY_MODE,
            "gui close: adopt contains survivors in leftover/<owner>-<id>",
        ),
        "enforce": (
            ACT,
            AUTHORITY_MODE,
            "gui close: enforce contains survivors in leftover/<owner>-<id>",
        ),
        "auto": (
            ACT,
            AUTHORITY_MODE,
            "gui close: auto contains survivors in leftover/<owner>-<id>",
        ),
    },
    JOB_SURVIVORS: {
        "observe": (
            KEEP,
            "",
            "job survivors: only auto acts on closed-job survivors (0.2.1)",
        ),
        "adopt": (
            KEEP,
            "",
            "job survivors: only auto acts on closed-job survivors (0.2.1)",
        ),
        "enforce": (
            KEEP,
            "",
            "job survivors: only auto acts on closed-job survivors (0.2.1)",
        ),
        "auto": (
            ACT,
            AUTHORITY_MODE,
            "job survivors: auto adopts standalone and stops decided survivors",
        ),
    },
    LEFTOVER_LEAVES: {
        "observe": (
            KEEP,
            "",
            "leftover leaves: only auto treats leftover/* as scopes (0.2.1)",
        ),
        "adopt": (
            ACT,
            AUTHORITY_MODE,
            "leftover leaves: adopt checks answered pairs individually",
        ),
        "enforce": (
            KEEP,
            "",
            "leftover leaves: only auto treats leftover/* as scopes (0.2.1)",
        ),
        "auto": (
            ACT,
            AUTHORITY_MODE,
            "leftover leaves: auto GCs and session-ends leftover/* individually",
        ),
    },
    GC_STOP: {
        "observe": (WOULD_ACT, "", "gc stop: observe only logs gc_would_stop"),
        "adopt": (WOULD_ACT, "", "gc stop: adopt only logs gc_would_stop (0.2.1)"),
        "enforce": (ACT, AUTHORITY_UNIT, "gc stop: enforce stops idle candidates"),
        "auto": (
            ACT,
            AUTHORITY_MODE,
            "gc stop: auto collects eligible idle shared/unit scopes",
        ),
    },
    GC_REMOVE_EMPTY: {
        "observe": (
            WOULD_ACT,
            "",
            "empty leaf: observe only logs gc_would_remove_empty",
        ),
        "adopt": (ACT, AUTHORITY_MODE, "empty leaf: adopt removes unused scopes"),
        "enforce": (ACT, AUTHORITY_MODE, "empty leaf: enforce removes unused scopes"),
        "auto": (ACT, AUTHORITY_MODE, "empty leaf: auto removes unused scopes"),
    },
    SESSION_END: {
        "observe": (WOULD_ACT, "", "session end: observe only logs would_stop"),
        "adopt": (WOULD_ACT, "", "session end: adopt only logs would_stop (0.2.1)"),
        "enforce": (ACT, AUTHORITY_UNIT, "session end: enforce stops every scope"),
        "auto": (
            ACT,
            AUTHORITY_PAIR,
            "session end: auto stops scopes each pair authorises",
        ),
    },
    MANUAL_STOP: {
        "observe": (
            ACT,
            AUTHORITY_MANUAL,
            "explicit taema kill: a user request acts in every mode",
        ),
        "adopt": (
            ACT,
            AUTHORITY_MANUAL,
            "explicit taema kill: a user request acts in every mode",
        ),
        "enforce": (
            ACT,
            AUTHORITY_MANUAL,
            "explicit taema kill: a user request acts in every mode",
        ),
        "auto": (
            ACT,
            AUTHORITY_MANUAL,
            "explicit taema kill: a user request acts in every mode",
        ),
    },
    RECLAIM: {
        "observe": (WOULD_ACT, "", "reclaim: observe records planned actions only"),
        "adopt": (ACT, AUTHORITY_MODE, "reclaim: adopt reclaims page cache only"),
        "enforce": (ACT, AUTHORITY_MODE, "reclaim: enforce reclaims eligible cache"),
        "auto": (ACT, AUTHORITY_MODE, "reclaim: auto reclaims eligible cache"),
    },
    MANUAL_RECLAIM: {
        "observe": (ACT, AUTHORITY_MANUAL, "manual reclaim: explicit user request"),
        "adopt": (ACT, AUTHORITY_MANUAL, "manual reclaim: explicit user request"),
        "enforce": (ACT, AUTHORITY_MANUAL, "manual reclaim: explicit user request"),
        "auto": (ACT, AUTHORITY_MANUAL, "manual reclaim: explicit user request"),
    },
    QOS: {
        "observe": (WOULD_ACT, "", "qos: observe records priority changes only"),
        "adopt": (ACT, AUTHORITY_MODE, "qos: adopt applies reversible priorities"),
        "enforce": (ACT, AUTHORITY_MODE, "qos: enforce applies reversible priorities"),
        "auto": (ACT, AUTHORITY_MODE, "qos: auto applies reversible priorities"),
    },
    FREEZE: {
        "observe": (KEEP, "", "freeze: observe never freezes scopes"),
        "adopt": (ACT, AUTHORITY_MODE, "freeze: adopt requires freeze.adopt"),
        "enforce": (ACT, AUTHORITY_MODE, "freeze: enforce freezes eligible leftovers"),
        "auto": (ACT, AUTHORITY_MODE, "freeze: auto freezes eligible leftovers"),
    },
    MANUAL_FREEZE: {
        "observe": (ACT, AUTHORITY_MANUAL, "manual freeze: explicit user request"),
        "adopt": (ACT, AUTHORITY_MANUAL, "manual freeze: explicit user request"),
        "enforce": (ACT, AUTHORITY_MANUAL, "manual freeze: explicit user request"),
        "auto": (ACT, AUTHORITY_MANUAL, "manual freeze: explicit user request"),
    },
}


def _capability(
    trigger: str, mode: str, facts: Facts
) -> tuple[Verdict, Authority, str]:
    """Slot 4: fact rules first, then the per-trigger, per-mode table above."""
    if (
        trigger == JOB_SURVIVORS
        and mode in ("adopt", "auto")
        and facts.pair_action == "stop"
    ):
        return ACT, AUTHORITY_PAIR, "job survivors: adopt stops an authorized pair"
    if trigger == GC_STOP and mode == "adopt" and facts.leftover:
        if facts.pair_action == "expiry":
            return ACT, AUTHORITY_MODE, "gc stop: configured leftover expiry elapsed"
        if facts.pair_action == "stop":
            return (
                ACT,
                AUTHORITY_PAIR,
                "gc stop: adopt stops an authorized leftover pair",
            )
        if facts.pair_action:
            return KEEP, "", "gc stop: adopt leaves an unauthorized pair in review"
    if trigger == SESSION_END and mode == "adopt" and facts.leftover:
        if facts.pair_action == "stop":
            return (
                ACT,
                AUTHORITY_PAIR,
                "session end: adopt stops an authorized leftover pair",
            )
        if facts.pair_action:
            return KEEP, "", "session end: adopt leaves an unauthorized pair"
    if trigger == GC_STOP and mode == "auto":
        if facts.leftover:
            if facts.pair_action == "expiry":
                return (
                    ACT,
                    AUTHORITY_MODE,
                    "gc stop: configured leftover expiry elapsed",
                )
            return (
                ACT,
                AUTHORITY_PAIR,
                "gc stop: auto stops leftover/* under pair/idle authority",
            )
        return (
            ACT,
            AUTHORITY_MODE,
            "gc stop: auto collects eligible idle shared/unit scopes",
        )
    if trigger == SESSION_END and mode == "auto" and facts.shared:
        return KEEP, "", "session end: shared/ is never stopped in auto"
    row = _CAPABILITY.get(trigger)
    if row is None or mode not in row:
        raise ValueError("unknown trigger or mode: %r / %r" % (trigger, mode))
    verdict, authority, reason = row[mode]
    return verdict, authority, reason


# ---- slots 1-3: blocking, pass through in 0.2.1 -------------------------------------------------


def _hard_safety(_trigger: str, _mode: str, facts: Facts) -> tuple[Vote, str]:
    """Slot 1: hard safety/dependencies (never root/other users/protected/self, revalidated at
    actuation by engine.stop/plan_stop). Read-only explain callers can supply a resolved blocker."""
    if facts.hard_safety:
        return "deny", facts.hard_safety
    return "pass", ""


def _veto(trigger: str, _mode: str, facts: Facts) -> tuple[Vote, str]:
    """Slot 2: a veto blocks any stop, freeze, reclaim, or budget action."""
    if TRIGGER_ACTIONS.get(trigger) in VETO_BLOCKED_ACTIONS and facts.unit_veto:
        return "deny", "unit veto: " + facts.unit_veto
    if (
        TRIGGER_ACTIONS.get(trigger) in VETO_BLOCKED_ACTIONS
        and facts.vetoed
        and not (trigger == MANUAL_RECLAIM and facts.force_veto)
    ):
        return "deny", "vetoed: " + facts.vetoed
    return "pass", ""


def _hold(trigger: str, _mode: str, facts: Facts) -> tuple[Vote, str]:
    """Slot 3: a hold denies every stop/reclaim trigger declared in TRIGGER_ACTIONS."""
    action = TRIGGER_ACTIONS.get(trigger)  # unknown triggers still fail in _capability
    if action in HOLD_BLOCKED_ACTIONS and facts.held:
        return "deny", "held: " + facts.held
    return "pass", ""


# ---- slot 5: pair/signature/unit authority ------------------------------------------------------


def _authority(trigger: str, mode: str, facts: Facts) -> tuple[Vote, str]:
    """Slot 5: trigger-level authority. Unit and resolved pair rules can deny; each member's
    pair authority is still re-checked at actuation after an `act` verdict."""
    if trigger == SESSION_END and facts.unit_survive_logout:
        return "deny", "unit authority: unit sets kill.survive_logout"
    if (
        mode in ("adopt", "auto")
        and trigger in (GC_STOP, JOB_SURVIVORS, SESSION_END)
        and facts.pair_action
        and facts.pair_action != "expiry"
    ):
        if facts.pair_action != "stop":
            return (
                "deny",
                facts.pair_reason or "pair authority: pair does not authorize stop",
            )
        if facts.learn_authority == "answered" and not facts.pair_explicit:
            return "deny", "pair authority: this mode requires an explicit stop answer"
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
    if (
        f.suppress_stops
        and trigger != MANUAL_STOP
        and TRIGGER_ACTIONS.get(trigger) == "stop"
    ):
        return Decision(
            KEEP, MODE_CAPABILITY, "quiet profile suppresses automatic stops"
        )
    verdict, authority, why = _capability(trigger, mode, f)
    if verdict == KEEP:
        return Decision(KEEP, MODE_CAPABILITY, why)
    vote, deny_reason = _authority(trigger, mode, f)
    if vote == "deny":
        return Decision(KEEP, AUTHORITY, deny_reason)
    return Decision(verdict, MODE_CAPABILITY, why, authority)
