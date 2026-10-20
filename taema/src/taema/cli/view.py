"""Shared, schema-tagged CLI view models and terminal renderers."""

import json
import os


def record(name, values):
    return {"schema": "taema.%s.v1" % name, **values}


def snapshot(kind, status=None, scopes=(), scope_count=None):
    """Build the stable snapshot consumed by status, ls, and future live surfaces."""
    scopes = list(scopes)
    return record(
        "view",
        {
            "kind": kind,
            "status": status,
            "scopes": scopes,
            "scope_count": len(scopes) if scope_count is None else scope_count,
        },
    )


def emit(model, args, human, jsonl_records=None):
    """Write one view as human text, stable JSON, or schema-tagged JSONL."""
    if getattr(args, "json", False):
        print(json.dumps(model, ensure_ascii=False, indent=2, sort_keys=True))
    elif getattr(args, "jsonl", False):
        records = jsonl_records if jsonl_records is not None else [model]
        for item in records:
            print(
                json.dumps(
                    item, ensure_ascii=False, sort_keys=True, separators=(",", ":")
                )
            )
    else:
        print(human, end="" if human.endswith("\n") else "\n")


def color_enabled(args, stream):
    if getattr(args, "plain", False) or getattr(args, "no_color", False):
        return False
    if os.environ.get("NO_COLOR") not in (None, ""):
        return False
    forced = os.environ.get("CLICOLOR_FORCE")
    if forced not in (None, "", "0"):
        return True
    try:
        return bool(stream.isatty())
    except (AttributeError, OSError):
        return False


def terminal_width(args):
    if getattr(args, "wide", False):
        return 0
    try:
        return os.get_terminal_size(1).columns
    except OSError:
        return 80


def _styled(value, code, enabled):
    return "\033[%sm%s\033[0m" % (code, value) if enabled else value


def _clip(value, width, wide=False):
    value = str(value)
    if wide or width <= 0 or len(value) <= width:
        return value
    if width == 1:
        return "…"
    return value[: width - 1] + "…"


def render_scopes(scopes, args):
    if not scopes:
        return "no scopes\n"
    width = getattr(args, "_width", 80)
    wide = getattr(args, "wide", False)
    color = getattr(args, "_color", False)
    name_width = 28 if wide or width <= 0 else max(12, min(28, width - 39))
    fixed = name_width + 4 + 2 + 8 + 1 + 6 + 2
    command_width = 80 if wide or width <= 0 else max(8, width - fixed)
    header = "%s %4s  %8s %6s  %s" % (
        "%-*s" % (name_width, "name"),
        "procs",
        "MEM",
        "PSI",
        "comms",
    )
    lines = [_styled(header, "1", color)]
    for scope in scopes:
        depth = scope["depth"]
        indent = "  " * depth
        row_name = _clip(scope["name"], max(1, name_width - len(indent)), wide)
        commands = ",".join(scope["commands"])
        commands = _clip(commands, command_width, wide)
        memory = scope["memory_bytes"]
        memory_text = "-" if memory is None else _format_memory(memory)
        pressure = scope["psi_avg10"]
        pressure_text = "-" if pressure is None else "%.2f" % pressure
        lines.append(
            "%s%-*s %4d  %8s %6s  %s"
            % (
                indent,
                max(1, name_width - len(indent)),
                row_name,
                scope["processes"],
                memory_text,
                pressure_text,
                commands,
            )
        )
    return "\n".join(lines) + "\n"


def _format_memory(value):
    amount = float(value)
    for unit in ("B", "K", "M", "G", "T"):
        if amount < 1024 or unit == "T":
            return "%d" % amount if unit == "B" else "%.1f%s" % (amount, unit)
        amount /= 1024.0


def _format_duration(seconds):
    seconds = max(0, int(seconds))
    parts = []
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        amount, seconds = divmod(seconds, size)
        if amount:
            parts.append("%d%s" % (amount, unit))
    if seconds or not parts:
        parts.append("%ds" % seconds)
    return " ".join(parts)


def render_status(model, args, summary=False):
    status = model["status"] or {}
    details = status.get("details") or {}
    width = getattr(args, "_width", 80)
    color = getattr(args, "_color", False)
    daemon = status.get("daemon", "unavailable")
    lines = [
        _styled("tæma status", "1", color),
        "daemon: %s" % daemon,
        "mode: %s" % status.get("mode", "unknown"),
        "profile: %s (%s)"
        % (
            status.get("profile", "auto"),
            status.get("profile_reason", "unknown"),
        ),
        "scopes: %d" % model.get("scope_count", len(model["scopes"])),
        "reviews: %s" % details.get("reviews", "unknown"),
        "feedback_invalid: %s" % status.get("feedback_invalid", 0),
    ]
    hold_state = status.get("hold_state") or {}
    hold_parts = []
    if hold_state.get("global"):
        hold_parts.append("global")
    hold_parts.extend("scope " + scope for scope in hold_state.get("scopes", []))
    remaining = hold_state.get("snooze_remaining_s", 0)
    if remaining:
        hold_parts.append("snooze " + _format_duration(remaining))
    if hold_parts:
        lines.append("hold: %s" % ", ".join(hold_parts))
    elif status.get("hold"):
        lines.append("hold: %s" % status["hold"])
    if status.get("config_error"):
        lines.append("config error: %s" % status["config_error"])
    latest = details.get("latest_decision")
    if latest:
        lines.append(
            "latest decision: %s"
            % _clip(
                json.dumps(latest, ensure_ascii=False, sort_keys=True),
                max(12, width - 18),
            )
        )
    if summary:
        return "\n".join(lines[:7]) + "\n"
    if status.get("config"):
        lines.append(
            "config: %s" % (", ".join(status["config"]) or "built-in defaults")
        )
    if details:
        for name in ("uptime_s", "pending_questions", "lineage", "recovery"):
            if name in details:
                lines.append(
                    "%s: %s"
                    % (
                        name,
                        json.dumps(details[name], ensure_ascii=False, sort_keys=True),
                    )
                )
        owners = details.get("owners")
        if owners:
            lines.append(
                "owners: %s" % json.dumps(owners, ensure_ascii=False, sort_keys=True)
            )
        pairs = details.get("pairs") or []
        if pairs:
            lines.append("pairs:")
            for pair in pairs:
                lines.append(
                    "  %-20s %-20s %-10s confidence=%.2f stop=%.2f keep=%.2f closes=%d %s"
                    % (
                        _clip(pair.get("owner", ""), 20),
                        _clip(pair.get("leftover", ""), 20),
                        pair.get("action", ""),
                        pair.get("confidence", 0.0),
                        pair.get("stop", 0.0),
                        pair.get("keep", 0.0),
                        pair.get("closes", 0),
                        _clip(pair.get("why", ""), max(8, width - 91)),
                    )
                )
        auto = details.get("auto")
        if auto:
            lines.append(
                "auto: %d auto-adopted scopes, %d leftover leaves"
                % (auto.get("auto_adopted_scopes", 0), auto.get("leftover_leaves", 0))
            )
            for stop in auto.get("auto_stops", [])[-5:]:
                lines.append(
                    "auto stop %-24s %s [%s]"
                    % (
                        _clip(stop.get("scope", ""), 24),
                        _clip(stop.get("why", ""), max(8, width - 60)),
                        _clip(", ".join(stop.get("pairs", [])), 32),
                    )
                )
    return "\n".join(lines) + "\n"


def render_reviews(reviews):
    if not reviews:
        return "open reviews: 0\n"
    import time

    lines = ["open reviews: %d" % len(reviews)]
    for item in reviews:
        age = max(0, int(time.time() - item.get("created", time.time())))
        if item.get("kind") == "legacy-invalid":
            lines.append(
                "review #%s legacy owner=%s survivor=%s previous=%s age=%ds"
                % (
                    item.get("id", "?"),
                    item.get("owner", "?"),
                    (item.get("survivors") or ["?"])[0],
                    item.get("answer", "?"),
                    age,
                )
            )
            continue
        if item.get("kind") == "scope":
            lines.append(
                "review #%s scope=%s reason=%s age=%ds"
                % (
                    item.get("id", "?"),
                    item.get("scope", "?"),
                    item.get("reason", "GC candidate"),
                    age,
                )
            )
            continue
        owner = item.get("owner") or "?"
        survivors = ", ".join(item.get("survivors") or []) or "none"
        lines.append(
            "review #%s owner=%s survivors=%s age=%ds"
            % (item.get("id", "?"), owner, survivors, age)
        )
    return "\n".join(lines) + "\n"
