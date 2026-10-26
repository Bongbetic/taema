"""Shared, schema-tagged CLI view models and terminal renderers."""

import json
import os


def record(name, values):
    return {"schema": "taema.%s.v1" % name, **values}


def snapshot(kind, status=None, scopes=(), scope_count=None, memory=None):
    """Build the stable snapshot consumed by status, ls, and future live surfaces."""
    scopes = list(scopes)
    model = record(
        "view",
        {
            "kind": kind,
            "status": status,
            "scopes": scopes,
            "scope_count": len(scopes) if scope_count is None else scope_count,
        },
    )
    if memory is not None:
        model["memory"] = memory
    return model


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


def top_model(previous, current, interval_s, hz, details):
    """CPU-sorted rows from two snapshots. details maps pid to scope/user/mem."""
    rows = []
    span = max(interval_s * hz, 1)
    total = details.get("__total__", 0) or 0
    for pid, proc in current.items():
        old = previous.get(pid)
        before = old.cpu if old is not None else proc.cpu
        cpu = max(0.0, (proc.cpu - before)) * 100.0 / span
        info = details.get(pid, {})
        mem = info.get("mem", 0)
        rows.append(
            {
                "pid": pid,
                "scope": info.get("scope", "?"),
                "user": info.get("user", "?"),
                "cpu": cpu,
                "mem_pct": (100.0 * mem / total) if total else 0.0,
                "mem": mem,
                "threads": info.get("threads", 0),
                "state": proc.state,
                "window": info.get("window", ""),
                "cmd": info.get("cmd", ""),
            }
        )
    rows.sort(key=lambda row: (-row["cpu"], -row["mem"], -row["pid"]))
    return rows


def render_top(model, args):
    """Fixed-column top table that fits the terminal width."""
    width = getattr(args, "_width", 80)
    wide = getattr(args, "wide", False)
    lines = [_clip("PID SCOPE   USER %CPU %MEM RSS  THR S W CMD", width, wide)]
    for row in model:
        cmd_width = 0 if wide or width <= 0 else max(1, width - 41)
        lines.append(
            _clip(
                "%-3d %-7s %-4s %5.1f %4.1f %-4s %-3d %s %s %s"
                % (
                    row["pid"],
                    _clip(row["scope"], 7, wide),
                    _clip(row["user"], 4, wide),
                    row["cpu"],
                    row["mem_pct"],
                    _clip(_format_memory(row["mem"]), 4, wide),
                    row["threads"],
                    row["state"],
                    row.get("window", ""),
                    _clip(row["cmd"], cmd_width, wide),
                ),
                width,
                wide,
            )
        )
    return "\n".join(lines) + "\n"


def tree_model(table, scope_of, windows=None):
    """Process trees grouped by scope. Returns [(scope, [(pid, depth, node)])]."""
    window_pids = windows if isinstance(windows, dict) else {}
    kids = {}
    for pid, proc in table.rows.items():
        kids.setdefault(proc.ppid, []).append(pid)
    for pids in kids.values():
        pids.sort()
    zombies = {pid for pid, proc in table.rows.items() if proc.state == "Z"}
    reaped = {}
    for pid in table.rows:
        count = sum(1 for kid in kids.get(pid, []) if kid in zombies)
        if count:
            reaped[pid] = count
    groups = {}
    for pid in table.rows:
        groups.setdefault(scope_of(pid), []).append(pid)
    model = []
    for scope in sorted(groups):
        members = set(groups[scope])
        roots = sorted(pid for pid in members if table.rows[pid].ppid not in members)
        nodes = []
        stack = [(pid, 0, True) for pid in reversed(roots)]
        while stack:
            pid, depth, _last = stack.pop()
            marker = window_pids.get(str(pid))
            nodes.append(
                {
                    "pid": pid,
                    "depth": depth,
                    "state": table.rows[pid].state,
                    "zombies": reaped.get(pid, 0),
                    "window": (
                        "F"
                        if isinstance(marker, dict) and marker.get("focused")
                        else "w"
                        if marker is not None
                        else ""
                    ),
                }
            )
            young = [kid for kid in kids.get(pid, []) if kid in members]
            for kid in reversed(young):
                stack.append((kid, depth + 1, True))
        model.append((scope, nodes))
    return model


def render_tree(model, args):
    """Scope-grouped process trees with zombie reapers marked."""
    width = getattr(args, "_width", 80)
    wide = getattr(args, "wide", False)
    limit = 0 if wide or width <= 0 else width
    lines = []
    for scope, nodes in model:
        lines.append(_clip(scope, limit, wide))
        for index, node in enumerate(nodes):
            depth = node["depth"]
            if depth == 0:
                prefix = "└─ "
            else:
                siblings_after = any(
                    other["depth"] == depth
                    for other in nodes[index + 1 :]
                    if other["depth"] <= depth
                )
                branch = "├─ " if siblings_after else "└─ "
                prefix = "   " * depth + branch
            text = "%s%d" % (prefix, node["pid"])
            if depth > 0:
                text += " %s" % node["state"]
            if node.get("window") == "F":
                text += " ◉"
            elif node.get("window"):
                text += " ●"
            if node["zombies"]:
                text += " (reaps %d zombie%s)" % (
                    node["zombies"],
                    "s" if node["zombies"] != 1 else "",
                )
            lines.append(_clip(text, limit, wide))
    return "\n".join(lines) + "\n"


def render_scopes(scopes, args):
    if not scopes:
        return "no scopes\n"
    width = getattr(args, "_width", 80)
    wide = getattr(args, "wide", False)
    color = getattr(args, "_color", False)
    name_width = 28 if wide or width <= 0 else max(12, min(28, width - 39))
    fixed = name_width + 4 + 2 + 8 + 1 + 6 + 1 + 2 + 2
    command_width = 80 if wide or width <= 0 else max(8, width - fixed)
    header = "%s %4s  %8s %6s %2s  %s" % (
        "%-*s" % (name_width, "name"),
        "procs",
        "MEM",
        "PSI",
        "W",
        "comms",
    )
    lines = [_styled(header, "1", color)]
    for scope in scopes:
        depth = scope["depth"]
        indent = "  " * depth
        row_name = (
            scope["name"]
            + (" ↓" if scope.get("deprioritized") else "")
            + (" ❄" if scope.get("frozen") else "")
        )
        row_name = _clip(row_name, max(1, name_width - len(indent)), wide)
        commands = ",".join(scope["commands"])
        commands = _clip(commands, command_width, wide)
        memory = scope["memory_bytes"]
        memory_text = "-" if memory is None else _format_memory(memory)
        pressure = scope["psi_avg10"]
        pressure_text = "-" if pressure is None else "%.2f" % pressure
        windows = scope.get("windows")
        if isinstance(windows, dict) and windows.get("count"):
            window_text = "F" if windows.get("focused") else "%d" % windows["count"]
        else:
            window_text = ""
        lines.append(
            "%s%-*s %4d  %8s %6s %2s  %s"
            % (
                indent,
                max(1, name_width - len(indent)),
                row_name,
                scope["processes"],
                memory_text,
                pressure_text,
                window_text,
                commands,
            )
        )
    return "\n".join(lines) + "\n"


def render_dash(model, args):
    """Deterministic dashboard text shared by --once and the live screen."""
    width = getattr(args, "_width", 80)
    wide = getattr(args, "wide", False)
    learned = model.get("learned") or {}
    pairs = learned.get("pairs") or []
    signatures = learned.get("signatures") or []
    apps = learned.get("apps") or []
    host = (model.get("memory") or {}).get("host") or {}
    budget = model.get("budget")
    if budget is None:
        budget_text = "unavailable"
    elif budget.get("enabled"):
        budget_text = "ceiling %s" % _format_memory(budget.get("budget_bytes") or 0)
    else:
        budget_text = "disabled"
    lines = ["scopes (%d)" % len(model.get("scopes") or [])]
    for row in model.get("scopes") or []:
        memory = row.get("memory_bytes")
        text = "  %s procs=%s mem=%s" % (
            row.get("name", "?"),
            row.get("procs", row.get("processes", 0)),
            "-" if memory is None else _format_memory(memory),
        )
        if row.get("frozen"):
            text += " frozen"
        lines.append(text)
    lines.append(
        "learned apps=%d pairs=%d signatures=%d"
        % (len(apps), len(pairs), len(signatures))
    )
    for pair in pairs[:5]:
        lines.append(
            "  pair %s -> %s %s"
            % (
                pair.get("owner", "?"),
                pair.get("leftover", "?"),
                pair.get("decision", pair.get("action", "ask")),
            )
        )
    for signature in signatures[:5]:
        lines.append(
            "  signature %s %s"
            % (signature.get("id", "?"), signature.get("decision", "ask"))
        )
    lines.append("memory")
    lines.append(
        "  host total %s  budget %s"
        % (_format_memory(host.get("total_bytes") or 0), budget_text)
    )
    reviews = model.get("reviews") or []
    lines.append("reviews (%d)" % len(reviews))
    for review in reviews[:5]:
        lines.append(
            "  #%s owner=%s" % (review.get("id", "?"), review.get("owner", "?"))
        )
    lines.append("events")
    for item in model.get("events") or []:
        parts = ["#%s" % item.get("seq", "?"), str(item.get("event", "unknown"))]
        scope = item.get("scope") or (item.get("data") or {}).get("scope", "")
        if scope:
            parts.append(str(scope))
        lines.append("  " + " ".join(parts))
    return "\n".join(_clip(line, width, wide) for line in lines) + "\n"


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
        "authority: %s (%s)"
        % (
            status.get("authority", "unknown"),
            status.get("authority_source", "unknown"),
        ),
        "profile: %s (%s)"
        % (
            status.get("profile", "auto"),
            status.get("profile_reason", "unknown"),
        ),
        "scopes: %d" % model.get("scope_count", len(model["scopes"])),
        "reviews: %s" % details.get("reviews", "unknown"),
        "feedback_invalid: %s" % status.get("feedback_invalid", 0),
    ]
    muted = details.get("muted")
    if muted:
        lines.append("muted: %s" % ", ".join(sorted(muted)))
    agents = details.get("agents")
    if isinstance(agents, dict):
        if not agents:
            lines.append("agent: none registered")
        for session in sorted(agents):
            info = agents[session] or {}
            lines.append(
                "agent: %s (session %s, pid %s)"
                % (info.get("state", "?"), session, info.get("pid", "?"))
            )
    guard = status.get("guard") or details.get("guard") or {}
    if guard.get("active") is True:
        lines.append(
            "guard: ACTIVE (%s; %s reclaimed)"
            % (
                guard.get("trigger") or "pressure",
                _format_memory(guard.get("bytes_freed", 0)),
            )
        )
    elif guard.get("last_trigger"):
        lines.append(
            "guard: inactive; last %s, %s reclaimed"
            % (
                guard.get("last_trigger"),
                _format_memory(guard.get("last_bytes_freed", 0)),
            )
        )
    memory = model.get("memory") or {}
    host = memory.get("host") or {}
    if memory.get("enabled") and host:
        lines.append(
            "memory: %s available / %s total; pressure %s%%; swap %s; zswap %s"
            % (
                _format_memory(host.get("available_bytes"))
                if host.get("available_bytes") is not None
                else "unknown",
                _format_memory(host.get("total_bytes"))
                if host.get("total_bytes") is not None
                else "unknown",
                "-"
                if host.get("pressure_avg10") is None
                else "%.2f" % host["pressure_avg10"],
                _format_memory(host.get("swap_used_bytes"))
                if host.get("swap_used_bytes") is not None
                else "unknown",
                _format_memory(host.get("zswap_bytes"))
                if host.get("zswap_bytes") is not None
                else "unknown",
            )
        )
    elif memory and not memory.get("enabled"):
        lines.append("memory: disabled")
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
        return "\n".join(lines[:9]) + "\n"
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
                        "%s%s"
                        % (
                            pair.get("action", ""),
                            " (signature)" if pair.get("inherited") else "",
                        ),
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

    def age_text(seconds):
        seconds = max(0, int(seconds))
        if seconds >= 86400:
            return "%dd" % (seconds // 86400)
        if seconds >= 3600:
            return "%dh" % (seconds // 3600)
        if seconds >= 60:
            return "%dm" % (seconds // 60)
        return "%ds" % seconds

    def memory_text(value):
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            return "?"
        if value >= 1024 * 1024 * 1024:
            return "%.1fG" % (value / (1024 * 1024 * 1024))
        return "%dM" % round(value / (1024 * 1024))

    lines = [] if len(reviews) == 1 else ["open reviews: %d" % len(reviews)]
    for item in reviews:
        age = item.get("age")
        if age is None:
            import time

            age = max(0, int(time.time() - item.get("created", time.time())))
        if item.get("kind") == "legacy-invalid":
            lines.append(
                "review #%s legacy owner=%s survivor=%s previous=%s age=%s"
                % (
                    item.get("id", "?"),
                    item.get("owner", "?"),
                    (item.get("survivors") or ["?"])[0],
                    item.get("answer", "?"),
                    age_text(age),
                )
            )
            continue
        if item.get("kind") == "provenance-candidate":
            candidates = (
                ", ".join(
                    candidate.get("label", candidate.get("key", "?"))
                    for candidate in item.get("candidates", [])
                )
                or "none"
            )
            lines.append(
                "review #%s provenance scope=%s survivors=%s candidates=%s reason=%s age=%s"
                % (
                    item.get("id", "?"),
                    item.get("scope", "?"),
                    ", ".join(item.get("survivors") or []) or "none",
                    candidates,
                    item.get("reason", "owner is ambiguous"),
                    age_text(age),
                )
            )
            continue
        if item.get("kind") == "scope":
            lines.append(
                "review #%s scope=%s reason=%s age=%s"
                % (
                    item.get("id", "?"),
                    item.get("scope", "?"),
                    item.get("reason", "GC candidate"),
                    age_text(age),
                )
            )
            continue
        owner = item.get("owner") or "?"
        survivors = ", ".join(item.get("survivors") or []) or "none"
        signature = item.get("signature") or {}
        signature_id = signature.get("id") or item.get("sig") or "?"
        answer = signature.get("ex_last") or item.get("answer") or "no"
        provenance = item.get("provenance") or "unknown"
        lines.append(
            "review #%s owner=%s survivors=%s closes=%s mem=%s age=%s"
            % (
                item.get("id", "?"),
                owner,
                survivors,
                item.get("closes", 0),
                memory_text(item.get("mem")),
                age_text(age),
            )
        )
        lines.append(
            "  ↳ provenance: %s; sig %s; answered? %s"
            % (provenance, str(signature_id)[:16], answer)
        )
        lines.append(
            "  [1] stop on close  [2] keep  [3] standalone  [4] never  [Enter] later"
        )
    return "\n".join(lines) + "\n"


def render_explanation(target, explanation):
    """Render the same structured explanation used by JSON consumers."""
    identity = explanation.get("identity") or {}
    scope = explanation.get("scope") or {}
    decision = explanation.get("current_decision") or {}
    protected = explanation.get("protected") or {}
    hold = explanation.get("hold") or {}
    lines = ["explain: %s" % target]
    if identity:
        lines.append(
            "identity: %s (%s; %s)"
            % (
                identity.get("key", "unknown"),
                identity.get("display", "unknown"),
                "validated" if identity.get("validated") else "unvalidated",
            )
        )
        if identity.get("reason"):
            lines.append("identity reason: %s" % identity["reason"])
    else:
        lines.append("identity: unknown")
    lines.append(
        "scope: %s (%s)"
        % (
            (scope.get("name") or "unknown")
            + (" ↓" if scope.get("deprioritized") else "")
            + (" ❄" if scope.get("frozen") else ""),
            "live" if scope.get("live") else "not verified live",
        )
    )
    confidence = decision.get("confidence")
    confidence_text = "" if confidence is None else " confidence=%.2f" % confidence
    lines.append(
        "decision: %s%s — %s"
        % (
            decision.get("action", "unknown"),
            confidence_text,
            decision.get("reason") or "reason unknown",
        )
    )
    lines.append("authority: %s" % explanation.get("authority_source", "unknown"))
    learn_authority = explanation.get("learn_authority") or {}
    if learn_authority:
        lines.append(
            "effective authority: %s (%s)"
            % (
                learn_authority.get("value", "unknown"),
                learn_authority.get("source", "unknown"),
            )
        )
    provenance = explanation.get("provenance") or {}
    chain = provenance.get("chain") or []
    if chain:
        lines.append("provenance: %s" % (provenance.get("chain_text") or "unknown"))
        for item in chain:
            relation = item.get("relation") or {}
            if not relation:
                continue
            evidence = relation.get("evidence_counts") or {}
            evidence_text = (
                ", ".join("%s=%s" % (name, evidence[name]) for name in sorted(evidence))
                or "no retained evidence"
            )
            confidence = relation.get("confidence")
            confidence_text = "unknown" if confidence is None else "%.2f" % confidence
            lines.append(
                "  provenance evidence: %s ← %s (%s; confidence=%s)"
                % (
                    item.get("display") or item.get("app", "unknown"),
                    relation.get("parent_display") or relation.get("parent", "unknown"),
                    evidence_text,
                    confidence_text,
                )
            )
    lines.append(
        "protection: %s%s"
        % (
            "blocked" if protected.get("blocked") else "not blocked",
            ": " + protected["reason"] if protected.get("reason") else "",
        )
    )
    lines.append("hold: %s" % (hold.get("reason") if hold.get("active") else "none"))
    vetoes = explanation.get("vetoes") or []
    lines.append(
        "vetoes: %s"
        % (
            ", ".join(
                "%s %s" % (item.get("kind"), item.get("value")) for item in vetoes[:5]
            )
            + (" (+%d more)" % (len(vetoes) - 5) if len(vetoes) > 5 else "")
            if vetoes
            else "none"
        )
    )
    learning = explanation.get("learning") or {}
    if "owner" in learning and "leftover" in learning:
        lines.append(
            "learned pair: %s -> %s (%s; %s)"
            % (
                learning["owner"],
                learning["leftover"],
                decision.get("action", "unknown"),
                explanation.get("authority_source", "unknown"),
            )
        )
    elif "default_action" in learning:
        lines.append(
            "learning: default=%s; pairs=%d; standalone=%s"
            % (
                learning.get("default_action", "unknown"),
                len(learning.get("pairs") or []),
                learning.get("standalone", "unknown"),
            )
        )
    elif "kind" in learning:
        lines.append(
            "recorded context: kind=%s; mode=%s; authority=%s"
            % (
                learning.get("kind", "unknown"),
                learning.get("mode", "unknown"),
                learning.get("authority", "unknown"),
            )
        )
    elif learning:
        lines.append("learning: recorded data")
    else:
        lines.append("learning: unknown")
    signatures = learning.get("signatures") or []
    for item in signatures[:5]:
        lines.append(
            "signature: owner=%s id=%s answer=%s closes=%d stop_ok=%d respawn=%d veto=%d probation=%d"
            % (
                item.get("owner", "?"),
                item.get("id", "?"),
                item.get("answer", "none"),
                item.get("closes", 0),
                item.get("stop_ok", 0),
                item.get("respawn", 0),
                item.get("veto", 0),
                item.get("probation", 0),
            )
        )
    if len(signatures) > 5:
        lines.append("signature: (+%d more)" % (len(signatures) - 5))
    outcomes = explanation.get("mode_outcomes") or {}
    lines.append("authorization (%s):" % outcomes.get("trigger", "unknown"))
    for item in outcomes.get("modes", []):
        lines.append(
            "  %-7s %-5s %-16s %s"
            % (
                item.get("mode", "?"),
                item.get("verdict", "?"),
                item.get("slot", ""),
                item.get("reason", ""),
            )
        )
    plan = explanation.get("plan") or []
    for item in plan[:8]:
        lines.append(
            "plan: %-5s pid=%s %s — %s"
            % (
                item.get("action", "?"),
                item.get("pid", "?"),
                item.get("comm", ""),
                item.get("why", ""),
            )
        )
    if len(plan) > 8:
        lines.append("plan: %d more members in --json" % (len(plan) - 8))
    for item in explanation.get("unknown") or []:
        lines.append(
            "unknown %s: %s" % (item.get("fact", "fact"), item.get("reason", ""))
        )
    return "\n".join(lines) + "\n"
