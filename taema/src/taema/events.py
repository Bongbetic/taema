"""Audit-event view models shared by the daemon and read-only CLI."""

TOPICS = ("status", "scope", "review", "decision", "memory", "guard", "profile")

_STATUS = {
    "daemon_start",
    "daemon_stop",
    "socket_bound",
    "store_busy",
    "store_recovered",
    "error",
    "config_invalid",
    "config_reloaded",
    "mode_changed",
    "profile_changed",
}
_REVIEW = {"review_created", "review_expired", "gc_review_created"}
_GUARD = {
    "action_held",
    "authorization_refused",
    "hold",
    "snooze",
    "unit_vetoed",
    "veto",
    "veto_added",
    "veto_expired",
    "veto_override",
    "veto_removed",
    "veto_refused",
    "vetoed",
}
_DECISION = {
    "answer",
    "answer_refused",
    "auto_stop",
    "auto_stop_refused",
    "refusal",
    "stop",
    "stop_refused",
    "undo",
    "undo_refused",
}
_MEMORY = {
    "answer",
    "forget",
    "keep",
    "kill",
    "launcher_learned",
    "mute",
    "regret",
    "standalone",
    "teach",
}
_SCOPE = {
    "adopt_would",
    "attach",
    "attach_delegated",
    "attach_refused",
    "containment",
    "gc_incomplete",
    "gc_kept",
    "gc_refused",
    "gc_removed_empty",
    "gc_skip",
    "gc_stopped",
    "gc_would_remove_empty",
    "owner_watch",
    "owner_watch_full",
    "stop_error",
    "stopped",
    "thaw",
    "thaw_failed",
    "would_attribute",
    "would_contain",
    "would_stop",
}


def event_topics(event):
    """Return stable view topics for a stored audit event."""
    name = event.get("event")
    data = event.get("data")
    data = data if isinstance(data, dict) else {}
    topics = set()
    if name in _STATUS:
        topics.add("status")
    if name in _REVIEW or (isinstance(name, str) and "review" in name):
        topics.add("review")
    if name in _GUARD:
        topics.add("guard")
    if name in _DECISION or event.get("decision_id") is not None:
        topics.add("decision")
    if name in _MEMORY:
        topics.add("memory")
    if name in _SCOPE or "scope" in data:
        topics.add("scope")
    if name in ("config_invalid", "config_reloaded", "mode_changed", "profile_changed"):
        topics.add("profile")
    if not topics:
        topics.add("status")
    return tuple(topic for topic in TOPICS if topic in topics)


def view_event(event):
    """Add topic labels without changing the durable audit record."""
    return {
        "seq": event.get("seq", 0),
        "ts": event.get("ts", 0),
        "event": event.get("event", "unknown"),
        "decision_id": event.get("decision_id"),
        "topics": list(event_topics(event)),
        "data": event.get("data") if isinstance(event.get("data"), dict) else {},
    }


def event_line(event):
    """Render one plain, single-line event for watch and the default events view."""
    data = event.get("data")
    data = data if isinstance(data, dict) else {}
    fields = [str(event.get("seq", "?")), str(event.get("event", "unknown"))]
    for key in ("scope", "owner", "why", "reason"):
        value = data.get(key)
        if value is not None and str(value).strip():
            fields.append(" ".join(str(value).split()))
    return " ".join(fields)
