"""`taema` command line. scoperun / scopekill / scopels are thin aliases (see bin/)."""

from contextlib import nullcontext
from datetime import datetime as _datetime
from datetime import time as _local_time
from datetime import timedelta as _timedelta
from itertools import count
import json
import os
import sys
import time


class _LazyModule:
    """Load a command dependency on first use instead of during CLI import."""

    def __init__(self, name, module):
        self._global_name = name
        self._name = module
        self._module = None

    def __getattr__(self, name):
        if self._module is None:
            module = __import__(self._name, fromlist=(name,))
            object.__setattr__(self, "_module", module)
            globals()[self._global_name] = module
        return getattr(self._module, name)

    def __setattr__(self, name, value):
        if name.startswith("_"):
            object.__setattr__(self, name, value)
            return
        if self._module is None:
            getattr(self, name)
        setattr(self._module, name, value)

    def __delattr__(self, name):
        if name.startswith("_"):
            object.__delattr__(self, name)
            return
        if self._module is None:
            getattr(self, name)
        delattr(self._module, name)


authorization = _LazyModule("authorization", "taema.model.authorization")
cgroup = _LazyModule("cgroup", "taema.core.cgroup")
inspect = _LazyModule("inspect", "taema.core.process")
lineage = _LazyModule("lineage", "taema.core.lineage")
engine = _LazyModule("engine", "taema.governor.engine")
knowledge = _LazyModule("knowledge", "taema.store.knowledge")
policy = _LazyModule("policy", "taema.config.policy")

_REQUEST_IDS = count(1)


def _load(args=None):
    cfg = policy.load_config(path=getattr(args, "config", None))
    socket_override = getattr(args, "socket", None)
    if socket_override:
        socket_override = policy.expand(socket_override)
        cfg["paths"]["socket"] = socket_override
        cfg["paths"]["socket_fallback"] = socket_override
    store = knowledge.Store(
        policy.state_dir(cfg),
        cfg.get("seeds"),
        read_only=True,
        deny=policy.owner_deny(cfg),
        mode=cfg.get("mode", "observe"),
        learn=cfg.get("learn"),
    )
    return cfg, store, policy.load_units(cfg)


def _load_events(args=None):
    """Load only the read-only state needed by events and watch."""
    cfg = policy.load_config(path=getattr(args, "config", None))
    socket_override = getattr(args, "socket", None)
    if socket_override:
        socket_override = policy.expand(socket_override)
        cfg["paths"]["socket"] = socket_override
        cfg["paths"]["socket_fallback"] = socket_override
    store = knowledge.Store(
        policy.state_dir(cfg),
        cfg.get("seeds"),
        read_only=True,
        deny=policy.owner_deny(cfg),
        mode=cfg.get("mode", "observe"),
        learn=cfg.get("learn"),
    )
    return cfg, store


def _load_status(args=None):
    """Load the light status path, opening the store only when persisted state exists."""
    cfg = policy.load_config(path=getattr(args, "config", None))
    socket_override = getattr(args, "socket", None)
    if socket_override:
        socket_override = policy.expand(socket_override)
        cfg["paths"]["socket"] = socket_override
        cfg["paths"]["socket_fallback"] = socket_override
    state_dir = policy.expand(cfg["paths"]["state_dir"])
    try:
        has_state = bool(os.listdir(state_dir))
    except OSError:
        has_state = False
    store = None
    if has_state and not getattr(args, "_fast", False):
        store = _status_store(cfg)
    return cfg, store


def _status_store(cfg, pending_only=False):
    state_dir = policy.expand(cfg["paths"]["state_dir"])
    if pending_only:
        feedback = os.path.join(state_dir, "feedback.jsonl")
        if not any(os.path.exists(path) for path in (feedback, feedback + ".replay")):
            return None
    else:
        try:
            if not os.listdir(state_dir):
                return None
        except OSError:
            return None
    return knowledge.Store(
        state_dir,
        cfg.get("seeds"),
        read_only=True,
        deny=policy.owner_deny(cfg),
        mode=cfg.get("mode", "observe"),
        learn=cfg.get("learn"),
    )


def sock_paths(cfg):
    """[primary, fallback]. The daemon binds the first whose directory exists (the fallback at
    boot, before login creates /run/user/<uid>); clients try both."""
    primary = cfg["paths"]["socket"]
    fallback = policy.expand(cfg["paths"]["socket_fallback"])
    return [primary, fallback]


def sock_path(cfg):
    primary, fallback = sock_paths(cfg)
    return primary if os.path.isdir(os.path.dirname(primary)) else fallback


def ask(cfg, msg, timeout=3.0):
    """One JSON request to the daemon. Returns the reply dict, or None when it is not running."""
    import socket

    if not isinstance(msg, dict) or not isinstance(msg.get("cmd"), str):
        return {"error": "invalid request", "code": "invalid_request"}
    identifier = next(_REQUEST_IDS)
    envelope = {
        "v": 2,
        "id": identifier,
        "cmd": msg["cmd"],
        "args": {key: value for key, value in msg.items() if key != "cmd"},
    }
    for path in sock_paths(cfg):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect(path)
            s.sendall((json.dumps(envelope) + "\n").encode())
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
            reply = json.loads(buf) if buf else None
            if isinstance(reply, dict) and reply.get("v") == 2:
                response_id = reply.get("id")
                if (
                    not isinstance(response_id, int)
                    or isinstance(response_id, bool)
                    or response_id != identifier
                ):
                    return {"error": "response id mismatch", "code": "protocol_error"}
                if reply.get("ok") is True:
                    return reply.get("result")
                error = reply.get("error")
                if isinstance(error, dict):
                    return {
                        "error": error.get("message", "request failed"),
                        "code": error.get("code", "operation_failed"),
                    }
                return {"error": "invalid error reply", "code": "protocol_error"}
            return reply
        except (OSError, ValueError):
            continue
        finally:
            s.close()
    return None


def subscribe(cfg, topics, since_seq):
    """Yield v2 subscription results until the daemon closes the stream."""
    import socket

    identifier = next(_REQUEST_IDS)
    envelope = {
        "v": 2,
        "id": identifier,
        "cmd": "subscribe",
        "args": {"topics": list(topics), "since_seq": since_seq},
    }
    connection = None
    for path in sock_paths(cfg):
        candidate = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        candidate.settimeout(3.0)
        try:
            candidate.connect(path)
            candidate.sendall((json.dumps(envelope) + "\n").encode())
        except OSError:
            candidate.close()
            continue
        candidate.settimeout(None)
        connection = candidate
        break
    if connection is None:
        yield {"error": "daemon unavailable", "code": "daemon_unavailable"}
        return

    with connection:
        buffer = b""
        while True:
            chunk = connection.recv(65536)
            if not chunk:
                return
            buffer += chunk
            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                try:
                    reply = json.loads(line)
                except (UnicodeDecodeError, ValueError):
                    yield {"error": "invalid stream reply", "code": "protocol_error"}
                    return
                if not isinstance(reply, dict) or reply.get("id") != identifier:
                    yield {"error": "response id mismatch", "code": "protocol_error"}
                    return
                if reply.get("ok") is True and isinstance(reply.get("result"), dict):
                    yield reply["result"]
                    continue
                error = reply.get("error")
                if isinstance(error, dict):
                    yield {
                        "error": error.get("message", "request failed"),
                        "code": error.get("code", "operation_failed"),
                    }
                else:
                    yield {"error": "invalid stream reply", "code": "protocol_error"}
                return


def feedback(cfg, store, op, key):
    """Send feedback to the daemon or queue a uniquely identified v2 operation."""
    how, reply = feedback_action(cfg, store, op, key=key)
    return how if reply and reply.get("ok") else "refused"


def feedback_action(cfg, store, op, **fields):
    """Send a versioned policy action to the daemon or append it for offline replay."""
    import uuid

    msg = {"v": 2, "id": uuid.uuid4().hex, "op": op, **fields}
    reply = ask(cfg, {"cmd": "feedback", **msg})
    if reply is not None:
        return "daemon", reply
    fd = os.open(store.feedback_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a") as f:
        f.write(json.dumps(msg) + "\n")
    if op in ("hold", "snooze"):
        store.sync_runtime_hold(reason=fields.get("reason"))
    return "queued", {"ok": True, "queued": True}


def veto_target(target, store=None, for_removal=False):
    """Resolve an explicit SCOPE, APP, or current PID into a stable veto target."""
    if not isinstance(target, str) or not target:
        raise ValueError("target is empty")
    kind, value = None, target
    for prefix in ("scope:", "app:", "pid:"):
        if target.startswith(prefix):
            kind, value = prefix[:-1], target[len(prefix) :]
            break
    if not value:
        raise ValueError("target is empty")
    if kind == "pid" or (kind is None and value.isdigit()):
        if not value.isdigit():
            raise ValueError("pid must be a number")
        pid = int(value)
        if for_removal and store is not None:
            existing = next(
                (
                    v
                    for v in store._active_vetoes()
                    if v.get("kind") == "pid" and v.get("value") == str(pid)
                ),
                None,
            )
            if existing:
                return store._target(existing)
        start = inspect.starttime(pid)
        if pid <= 1 or start is None or inspect.uid_of(pid) != os.getuid():
            raise ValueError("pid is gone or not yours")
        return {"kind": "pid", "value": str(pid), "start": start}
    if kind == "scope":
        path = cgroup.resolve(value)
        if path:
            value = cgroup.rel(path)
        elif not cgroup.valid_rel(value):
            raise ValueError("bad scope name")
        return {"kind": "scope", "value": value, "start": None}
    if kind == "app":
        return {"kind": "app", "value": value, "start": None}
    path = cgroup.resolve(value)
    if path:
        return {"kind": "scope", "value": cgroup.rel(path), "start": None}
    if store is not None:
        found = next(
            (v for v in store._active_vetoes() if v.get("value") == value), None
        )
        if found:
            return store._target(found)
    return {"kind": "app", "value": value, "start": None}


def veto_label(target):
    label = "%s %s" % (target["kind"], target["value"])
    if target["kind"] == "pid" and target.get("start") is not None:
        label += " (starttime %s)" % target["start"]
    return label


def die(msg, code=1, hint=None, suggestion=None):
    print("taema: " + msg, file=sys.stderr)
    if hint is None:
        if code == 4:
            hint = "Inspect the target's safety state before changing policy."
        elif code == 3:
            hint = "Start or check the taema daemon, then retry the command."
        elif code == 2:
            hint = "List current targets with `taema ls` and choose one exactly."
        else:
            hint = "Check the arguments and run `taema COMMAND --help` for usage."
    if suggestion is None:
        import difflib
        import re

        target = re.search(r"no scope (.+)", msg)
        suggestion = "Run `taema --help` to see related commands."
        if target:
            try:
                base = cgroup.base()
                candidates = []
                pending = list(cgroup.subdirs(base)) if os.path.isdir(base) else []
                while pending:
                    path = pending.pop()
                    candidates.append(cgroup.rel(path))
                    pending.extend(cgroup.subdirs(path))
                close = difflib.get_close_matches(
                    target.group(1), candidates, n=1, cutoff=0.55
                )
                if close:
                    suggestion = "Did you mean `%s`?" % close[0]
                else:
                    suggestion = "List available scopes with `taema ls`."
            except OSError:
                suggestion = "List available scopes with `taema ls`."
    print("hint: " + hint, file=sys.stderr)
    print("suggestion: " + suggestion, file=sys.stderr)
    return code


def _choose_target(query, candidates, pick=False, label=None):
    from . import targets

    try:
        if query is None:
            selected = targets.select_candidates(
                label or "target", candidates, pick=pick
            )
        else:
            selected = targets.select_target(query, candidates, pick=pick)
    except targets.TargetNotFound:
        if not candidates:
            return die("no %s candidates are available" % (label or "target"), 2)
        return die(
            "no target matches %r" % query,
            2,
            hint="Choose a live scope, app key, pid, or desktop id.",
            suggestion="Try one of: %s"
            % ", ".join(item.label for item in candidates[:5]),
        )
    except targets.TargetAmbiguous as error:
        return die(
            "target %r is ambiguous: %s"
            % (error.query, ", ".join(item.label for item in error.candidates)),
            2,
            hint="Choose one candidate, or run the command in a terminal to pick it.",
            suggestion="Use a kind prefix such as `scope:`, `app:`, `pid:`, or `desktop:`.",
        )
    except targets.TargetError as error:
        return die(
            str(error),
            1,
            hint="Install fzf or retry without `--pick`.",
            suggestion="Use the numbered picker in a terminal.",
        )
    if selected is None:
        return die(
            "target selection cancelled", 1, hint="Choose a listed target to continue."
        )
    return selected


def _target_candidates(query=None, store=None):
    from . import targets

    candidates = targets.live_targets()
    if store is not None:
        live_apps = {item.value for item in candidates if item.kind == "app"}
        candidates.extend(
            item
            for item in targets.known_app_targets(store)
            if item.value not in live_apps
        )
    value = query.split(":", 1)[1] if isinstance(query, str) and ":" in query else query
    prefix = query.split(":", 1)[0] if isinstance(query, str) and ":" in query else None
    if (
        prefix == "app"
        and value
        and not any(item.kind == "app" and item.value == value for item in candidates)
    ):
        candidates.append(targets.Target("app", value, "app:" + value, app_key=value))
    if isinstance(value, str) and value.isdigit() and prefix in (None, "pid"):
        try:
            candidate = targets.process_target(value)
        except targets.TargetNotFound:
            pass
        else:
            if not any(
                item.kind == "pid" and item.value == candidate.value
                for item in candidates
            ):
                candidates.append(candidate)
    return candidates


def _target_scope_path(target):
    """Revalidate a selected target's scope and protect against pid reuse or movement."""
    if not target.scope:
        die("pid %s is not inside a managed scope" % target.value, 2)
        return None
    path = cgroup.resolve(target.scope)
    if not path:
        die("scope %s disappeared; resolve the target again" % target.scope, 2)
        return None
    if target.pid is not None:
        if inspect.starttime(target.pid) != target.start:
            die("pid %s changed since target selection" % target.pid, 2)
            return None
        current = cgroup.proc_cgroup(target.pid)
        if not current or not cgroup.is_prefix(path, current):
            die("pid %s moved since target selection" % target.pid, 2)
            return None
    return path


def _confirm_bulk(action, rows, args):
    print("plan: %s affects %d targets" % (action, len(rows)))
    for row in rows:
        print("  %s" % row)
    if getattr(args, "yes", False):
        return True
    if not sys.stdin.isatty():
        print("hint: rerun with --yes to approve this plan", file=sys.stderr)
        return False
    try:
        answer = input("Proceed? [y/N] ").strip().lower()
    except (EOFError, OSError):
        return False
    return answer in ("y", "yes")


# ---- run ----------------------------------------------------------------------------------


def _sudo_denied(msg):
    """True when the helper call failed because sudo refused (no taema group), not the helper itself."""
    m = msg.lower()
    return (
        "sudo" in m
        or "permission denied" in m
        or "password is required" in m
        or "not allowed" in m
    )


def cmd_run(a):
    cfg, store, units = _load(a)
    name = a.name
    if not cgroup.valid_rel(name) or "/" in name or len(name) > 32:
        return die("bad name (use a-z 0-9 _ -, max 32)")
    base = cgroup.base()
    if not os.path.isdir(base):
        return die(
            "%s missing; is the taema service running and are you in the taema group? (sv status taema)"
            % base
        )
    leaf = "%s/scope-%s" % (base, name)
    if os.path.isdir(leaf) and cgroup.tree_procs(leaf) and not a.join:
        return die("scope %s already has processes (use --join to add)" % name)
    owner = os.getpid() if a.bind else a.owner
    if owner and inspect.uid_of(owner) == -1:
        return die("owner pid %d is gone; not starting scope-%s" % (owner, name))
    if getattr(a, "dry_run", False):
        print("dry run: create scope-%s and attach %s" % (name, " ".join(a.cmd)))
        return 0
    os.makedirs(leaf, exist_ok=True)
    # register before attaching: the daemon must be watching when this process enters the scope
    reply = (
        ask(cfg, {"cmd": "register", "scope": "scope-" + name, "owner": owner})
        if owner
        else None
    )
    if reply is not None and "error" in reply:
        try:
            os.rmdir(leaf)
        except OSError:
            pass
        return die("register failed: %s" % reply["error"])
    try:
        trace = (
            store.decision_context(
                "containment",
                scope="scope-" + name,
                owner=owner,
                authority="user",
                mode=cfg["mode"],
                why="attach the launched process to its requested scope",
            )
            if store is not None
            else nullcontext()
        )
        with trace:
            try:
                engine.helper_attach(cfg, os.getpid(), name)
                if store is not None:
                    store.log(
                        event="containment", scope="scope-" + name, pids=[os.getpid()]
                    )
            except engine.Refused as e:
                if store is not None:
                    store.log(event="attach_refused", scope="scope-" + name, why=str(e))
                if not _sudo_denied(str(e)):
                    raise
                # no taema group in this shell yet: the daemon has it and attaches us
                r = ask(
                    cfg,
                    {
                        "cmd": "attach",
                        "scope": "scope-" + name,
                        "pids": [os.getpid()],
                    },
                )
                if not (r and r.get("ok")):
                    raise engine.Refused(
                        "%s (daemon: %s)" % (e, (r or {}).get("error", "not running"))
                    )
                if store is not None:
                    store.log(
                        event="attach_delegated",
                        scope="scope-" + name,
                        pids=[os.getpid()],
                    )
    except engine.Refused as e:
        try:
            os.rmdir(leaf)
        except OSError:
            pass
        return die("attach failed: %s" % e)
    if owner and reply is None:
        print(
            "taema: daemon not running; no owner watch for scope-%s" % name,
            file=sys.stderr,
        )
    elif reply is None:
        print(
            "taema: daemon not running; scope-%s is not auto-managed" % name,
            file=sys.stderr,
        )
    os.execvp(a.cmd[0], a.cmd)


# ---- kill ---------------------------------------------------------------------------------


def cmd_kill(a):
    if getattr(a, "do_not_kill", False):
        return die("kill and --do-not-kill cannot be combined", 2)
    cfg, store, units = _load(a)
    from . import targets

    query = getattr(a, "name", None)
    candidates = _target_candidates(query)
    if query is None:
        candidates = targets.leftover_targets(candidates)
        selected = _choose_target(
            None, candidates, pick=getattr(a, "pick", False), label="leftover scope"
        )
    else:
        selected = _choose_target(query, candidates, pick=getattr(a, "pick", False))
    if not isinstance(selected, targets.Target):
        return selected
    path = _target_scope_path(selected)
    if path is None:
        return 2
    veto = engine.veto_for_scope(store, path)
    scope = cgroup.rel(path)
    facts = authorization.Facts(
        scope=scope,
        vetoed=veto_label(veto) if veto else "",
        held=store.hold_reason(scope),
    )
    dec = authorization.authorize(authorization.MANUAL_STOP, cfg["mode"], facts)
    if dec.verdict != authorization.ACT:
        with store.decision_context(
            "refusal",
            scope=cgroup.rel(path),
            authority=("veto" if dec.slot == authorization.VETO else dec.slot),
            mode=cfg["mode"],
            why=dec.reason,
        ):
            if dec.slot == authorization.VETO:
                store.log(
                    event="vetoed",
                    trigger=authorization.MANUAL_STOP,
                    scope=cgroup.rel(path),
                    target=dec.reason,
                )
            else:
                store.log(
                    event="kill_refused",
                    trigger=authorization.MANUAL_STOP,
                    scope=cgroup.rel(path),
                )
        if dec.slot in (authorization.VETO, authorization.HOLD):
            return die(dec.reason, 4)
        return die("kill not allowed: %s" % dec.reason)
    leaf_name = os.path.basename(path)
    unit = engine.unit_for_leaf(units, leaf_name)
    with store.decision_context(
        "stop",
        scope=cgroup.rel(path),
        authority=dec.authority or "manual",
        mode=cfg["mode"],
        why=dec.reason,
    ):
        try:
            rep = engine.stop(
                path,
                cfg,
                store,
                unit,
                timeout=a.timeout,
                force=a.force,
                hard=a.hard,
                keep=[x for x in (a.keep or "").split(",") if x],
                dry_run=a.dry_run,
                hook=policy.hook_for(cfg, leaf_name),
                decision_authority=dec.authority or "manual",
                decision_why=dec.reason,
            )
        except engine.Refused as e:
            store.log(event="refusal", scope=cgroup.rel(path), why=str(e))
            if isinstance(e, engine.Vetoed) or "protect" in str(e).lower():
                return die(str(e), 4)
            return die(str(e))
    for d in rep["decisions"]:
        print(
            "%-5s %7d %-18s %s"
            % (d["action"], d["pid"], d["comm"][:18], d["why"][:110])
        )
    if a.force:
        for key in {d["key"] for d in rep["decisions"] if d["action"] == "kill"}:
            feedback(cfg, store, "kill", key)
    if a.dry_run:
        print("dry run: nothing changed")
        return 0
    if rep["removed"]:
        print("scope %s stopped" % rep["scope"])
        return 0
    print(
        "scope %s kept: %s (pids %s)"
        % (rep["scope"], rep.get("error", "busy"), rep["left"]),
        file=sys.stderr,
    )
    return 1


# ---- ls / explain / keep / forget ---------------------------------------------------------


def _fmt_mem(n):
    """Human-readable byte count (1.5G, 512); '-' when the fact is unknown."""
    if n is None:
        return "-"
    x = float(n)
    for u in ("B", "K", "M", "G", "T"):
        if x < 1024 or u == "T":
            return "%d" % x if u == "B" else "%.1f%s" % (x, u)
        x /= 1024.0


def _fmt_psi(v):
    """memory pressure 'some avg10' with two decimals; '-' when the fact is unknown."""
    return "-" if v is None else "%.2f" % v


def _walk(path, depth, out):
    pids = cgroup.procs(path)
    comms = []
    for p in pids:
        c = inspect.comm(p)
        if c and c not in comms:
            comms.append(c)
    out.append(
        {
            "depth": depth,
            "name": os.path.basename(path) if depth else cgroup.rel(path),
            "processes": len(pids),
            "memory_bytes": cgroup.memory_current(path),
            "psi_avg10": cgroup.memory_psi(path),
            "commands": sorted(comms),
        }
    )
    for d in sorted(cgroup.subdirs(path)):
        _walk(d, depth + 1, out)


def _count_scopes(base):
    pending = list(cgroup.subdirs(base))
    count_scopes = 0
    while pending:
        path = pending.pop()
        count_scopes += 1
        pending.extend(cgroup.subdirs(path))
    return count_scopes


def cmd_ls(a):
    from . import view

    base = cgroup.base()
    if not os.path.isdir(base):
        model = view.snapshot("ls", scopes=())
        view.emit(model, a, "scope tree unavailable: %s\n" % base)
        return 3
    rows = []
    for d in sorted(cgroup.subdirs(base)):
        _walk(d, 0, rows)
    model = view.snapshot("ls", scopes=rows)
    records = [view.record("scope", row) for row in rows]
    view.emit(model, a, view.render_scopes(rows, a), records)
    return 0


def _why_identity(key, cfg, store, live=None):
    if not key:
        return None
    if live is not None:
        return {
            "key": key,
            "display": live.display,
            "kind": live.kind,
            "validated": bool(live.validated),
            "reason": live.reason or "",
        }
    persisted = store.app_identity(key) or {}
    invalid = policy.bad_owner(key, policy.owner_deny(cfg))
    return {
        "key": key,
        "display": persisted.get("display") or key,
        "kind": persisted.get("kind") or key.split(":", 1)[0],
        "validated": invalid is None,
        "reason": invalid or "",
    }


def _why_outcomes(trigger, facts, cfg):
    if not trigger:
        return {"trigger": "unknown", "modes": []}
    from dataclasses import replace

    modes = []
    for mode in authorization.MODES:
        mode_cfg = dict(cfg)
        mode_cfg["mode"] = mode
        effective = policy.effective_authority(mode_cfg)
        decision = authorization.authorize(
            trigger,
            mode,
            replace(facts, learn_authority=effective["value"]),
        )
        modes.append(
            {
                "mode": mode,
                "verdict": decision.verdict,
                "slot": decision.slot,
                "authority": decision.authority,
                "reason": decision.reason,
            }
        )
    return {
        "trigger": trigger,
        "modes": modes,
    }


def _why_report(
    cfg,
    store,
    *,
    key=None,
    live_identity=None,
    target_scope=None,
    scope_live=False,
    provenance=None,
    members=(),
    trigger="",
    facts=None,
    action="unknown",
    confidence=None,
    reason="",
    authority_source="unknown",
    learning=None,
    plan=(),
    protected_reason="",
    extra_unknown=(),
):
    unknown = list(extra_unknown)
    identity = _why_identity(key, cfg, store, live_identity)
    stored_provenance = None
    if key:
        reader = getattr(store, "provenance_chain", None)
        stored_provenance = reader(key) if reader else store.latest_app_instance(key)
    if provenance is None:
        provenance = stored_provenance or {}
    elif stored_provenance:
        provenance = {**stored_provenance, **provenance}
        if "chain" not in provenance:
            provenance["chain"] = stored_provenance.get("chain", [])
        if "chain_text" not in provenance:
            provenance["chain_text"] = stored_provenance.get("chain_text", "")
    if identity is None and not any(item.get("fact") == "identity" for item in unknown):
        unknown.append(
            {
                "fact": "identity",
                "reason": "no single application identity is available",
            }
        )
    if key and not provenance:
        unknown.append(
            {"fact": "provenance", "reason": "no process instance has been recorded"}
        )
    if target_scope and not scope_live:
        unknown.append(
            {"fact": "scope", "reason": "stored scope was not verified as live"}
        )
    elif not target_scope:
        unknown.append({"fact": "scope", "reason": "target has no known managed scope"})
    if not trigger:
        unknown.append(
            {
                "fact": "mode_outcomes",
                "reason": "the retained decision does not identify a lifecycle trigger",
            }
        )
    if confidence is None:
        unknown.append(
            {
                "fact": "confidence",
                "reason": "this decision source does not provide a normalized confidence value",
            }
        )
    hold = store.hold_reason(target_scope if scope_live else None)
    vetoes = store.matching_vetoes(
        scope=target_scope if scope_live else None, members=members
    )
    return {
        "identity": identity,
        "scope": {"name": target_scope or "", "live": bool(scope_live)},
        "provenance": provenance or {},
        "current_decision": {
            "action": action,
            "confidence": confidence,
            "reason": reason,
        },
        "authority_source": authority_source or "unknown",
        "learn_authority": policy.effective_authority(cfg),
        "vetoes": vetoes,
        "hold": {"active": bool(hold), "reason": hold},
        "protected": {"blocked": bool(protected_reason), "reason": protected_reason},
        "mode_outcomes": _why_outcomes(trigger, facts or authorization.Facts(), cfg),
        "learning": learning or {},
        "plan": list(plan),
        "unknown": unknown,
    }


def _why_pair_authority(store, key):
    owners = store.owners_of(key, limit=1)
    if not owners:
        return "ask", "pair authority: no owner decision is recorded"
    return store.pair_decision(owners[0], key)[0], store.pair_decision(owners[0], key)[
        2
    ]


def _why_pair_report(owner, leftover, cfg, store):
    action, confidence, reason = store.pair_decision(owner, leftover)
    pair_key = store.pkey(owner, leftover)
    pair = store.data.get("pairs", {}).get(pair_key, {})
    source = pair.get("ex_source") or pair.get("source")
    if not source:
        if action == "standalone":
            source = "standalone"
        elif action == "invalid":
            source = "owner validation"
        elif pair:
            source = "learned pair evidence"
        else:
            source = "no stored pair authority"
    facts = authorization.Facts(
        leftover=True,
        pair_action=action,
        pair_reason=reason,
        pair_explicit=store.explicit_stop((action, confidence, reason)),
        suppress_stops=bool(cfg.get("_profile_suppress_stops")),
    )
    members = ({"apps": [owner]}, {"apps": [leftover]})
    explanation = _why_report(
        cfg,
        store,
        key=owner,
        members=members,
        trigger=authorization.GC_STOP,
        facts=facts,
        action=action,
        confidence=confidence,
        reason=reason,
        authority_source=source,
        learning={
            "owner": owner,
            "leftover": leftover,
            "pair": pair,
            "owner_learning": store.explain(owner),
            "signatures": list(
                {
                    item["id"]: item
                    for item in store.signature_summaries(owner)
                    + store.signature_summaries(leftover)
                }.values()
            ),
        },
    )
    return explanation


def cmd_explain(a):
    from . import targets, view

    cfg, store, units = _load(a)
    target_query = getattr(a, "target", None)
    pair = getattr(a, "pair", None)
    if pair and target_query:
        return die("choose either a target or --pair", 2)

    if pair:
        owner, leftover = pair
        explanation = _why_pair_report(owner, leftover, cfg, store)
        label = "pair:%s -> %s" % (owner, leftover)
    elif not target_query:
        latest = store.latest_decision()
        if latest:
            current = {
                "action": latest.get("outcome") or latest.get("kind") or "recorded",
                "confidence": None,
                "reason": latest.get("why") or "recorded decision",
            }
            key = latest.get("key") or latest.get("owner")
            explanation = _why_report(
                cfg,
                store,
                key=key,
                target_scope=latest.get("scope"),
                scope_live=False,
                provenance={},
                action=current["action"],
                reason=current["reason"],
                authority_source=latest.get("authority") or "recorded decision",
                learning=latest,
                extra_unknown=(
                    {
                        "fact": "trigger",
                        "reason": "the retained decision has no trigger field",
                    },
                ),
            )
        else:
            explanation = _why_report(
                cfg,
                store,
                action="unknown",
                reason="no decision has been recorded",
                extra_unknown=(
                    {
                        "fact": "latest_decision",
                        "reason": "the decision ledger is empty",
                    },
                ),
            )
        label = "latest decision"
    else:
        candidates = _target_candidates(target_query, store)
        matches = targets.matching_targets(target_query, candidates)
        explicit_kind = target_query.split(":", 1)[0] if ":" in target_query else None
        if not matches and (
            explicit_kind in ("scope", "app", "pid", "desktop")
            or target_query.isdigit()
        ):
            return die("no target matches %r" % target_query, 2)
        if matches:
            selected = _choose_target(
                target_query, candidates, pick=getattr(a, "pick", False)
            )
            if not isinstance(selected, targets.Target):
                return selected
        else:
            selected = None

        if selected is None:
            info = store.explain(target_query)
            action, reason = info.get("default_action", "unknown"), info.get("why", "")
            explanation = _why_report(
                cfg,
                store,
                key=target_query,
                action=action,
                confidence=None,
                reason=reason,
                authority_source="learned default",
                learning=info,
            )
            label = target_query
        elif selected.kind == "scope":
            path = _target_scope_path(selected)
            if path is None:
                return 2
            scope = cgroup.rel(path)
            unit = engine.unit_for_leaf(units, os.path.basename(path))
            plan = engine.plan_stop(path, cfg, store, unit)
            members = []
            for item in plan:
                member = {"pid": item["pid"], "apps": [item["key"]]}
                start = inspect.starttime(item["pid"])
                if start is not None:
                    member["start"] = start
                members.append(member)
            vetoes = store.matching_vetoes(scope=scope, members=members)
            hold = store.hold_reason(scope)
            protected_rows = [item for item in plan if item["action"] == "skip"]
            protected_reason = "; ".join(
                "%s: %s" % (item["pid"], item["why"]) for item in protected_rows
            )
            leftover = scope.startswith("leftover/")
            pair_actions = [
                _why_pair_authority(store, item["key"])
                for item in plan
                if leftover and item.get("key")
            ]
            pair_action, pair_reason = "", ""
            if pair_actions:
                denied = next(
                    (item for item in pair_actions if item[0] != "stop"), None
                )
                pair_action, pair_reason = denied or (
                    "stop",
                    "all member pairs authorize stop",
                )
            elif leftover:
                pair_action, pair_reason = (
                    "ask",
                    "pair authority: no member pair is available to authorize this scope",
                )
            facts = authorization.Facts(
                scope=scope,
                leftover=leftover,
                vetoed=("%s %s" % (vetoes[0]["kind"], vetoes[0]["value"]))
                if vetoes
                else "",
                held=hold,
                pair_action=pair_action,
                pair_reason=pair_reason,
                suppress_stops=bool(cfg.get("_profile_suppress_stops")),
            )
            kill_count = sum(item["action"] == "kill" for item in plan)
            action = "stop" if kill_count else "keep"
            reason = "%d of %d members eligible to stop" % (kill_count, len(plan))
            explanation = _why_report(
                cfg,
                store,
                target_scope=scope,
                scope_live=True,
                members=members,
                trigger=authorization.GC_STOP,
                facts=facts,
                action=action,
                reason=reason,
                authority_source="authorization ladder",
                plan=plan,
                protected_reason=protected_reason,
                extra_unknown=(
                    {
                        "fact": "identity",
                        "reason": "scope contains multiple process identities",
                    },
                ),
            )
            label = target_query
        elif selected.kind == "pid":
            pid = selected.pid
            if pid is None or inspect.starttime(pid) != selected.start:
                return die("pid target changed; resolve it again", 2)
            live_identity = policy.app_identity(pid, units=units)
            key = live_identity.key
            scope = ""
            if selected.scope:
                scope_path = _target_scope_path(selected)
                if scope_path is None:
                    return 2
                scope = cgroup.rel(scope_path)
            protected_reason = policy.protected_reason(pid, cfg) or ""
            info = store.explain(key)
            member = {"pid": pid, "start": selected.start, "apps": [key]}
            members = [member]
            leftover = scope.startswith("leftover/")
            trigger = authorization.GC_STOP if leftover else authorization.GUI_CLOSE
            pair_action, pair_reason = (
                _why_pair_authority(store, key) if leftover else ("", "")
            )
            vetoes = store.matching_vetoes(
                scope=scope if scope else None, members=members
            )
            hold = store.hold_reason(scope if scope else None)
            facts = authorization.Facts(
                scope=scope,
                leftover=leftover,
                vetoed=("%s %s" % (vetoes[0]["kind"], vetoes[0]["value"]))
                if vetoes
                else "",
                held=hold,
                hard_safety=protected_reason,
                pair_action=pair_action,
                pair_reason=pair_reason,
                suppress_stops=bool(cfg.get("_profile_suppress_stops")),
            )
            provenance = {
                "pid": pid,
                "start": selected.start,
                "scope": scope,
                "comm": inspect.comm(pid),
                "cgroup": cgroup.proc_cgroup(pid) or "",
            }
            explanation = _why_report(
                cfg,
                store,
                key=key,
                live_identity=live_identity,
                target_scope=scope,
                scope_live=bool(scope),
                provenance=provenance,
                members=members,
                trigger=trigger,
                facts=facts,
                action=info.get("default_action", "unknown"),
                reason=info.get("why", ""),
                authority_source="learned default",
                learning=info,
                protected_reason=protected_reason,
            )
            label = target_query
        else:
            key = selected.app_key or selected.value
            info = store.explain(key)
            persisted = store.latest_app_instance(key) or {}
            scope = selected.scope or persisted.get("scope") or ""
            live_scope = bool(selected.scope and cgroup.resolve(selected.scope))
            live_identity = None
            members = [{"apps": [key]}]
            protected_reasons = []
            for process_target in candidates:
                if process_target.kind != "pid" or process_target.app_key != key:
                    continue
                member = {
                    "pid": process_target.pid,
                    "apps": [key],
                    "start": process_target.start,
                }
                members.append(member)
                if process_target.pid is not None:
                    reason = policy.protected_reason(process_target.pid, cfg)
                    if reason:
                        protected_reasons.append(
                            "%s: %s" % (process_target.pid, reason)
                        )
            leftover = scope.startswith("leftover/")
            trigger = authorization.GC_STOP if leftover else authorization.GUI_CLOSE
            pair_action, pair_reason = (
                _why_pair_authority(store, key) if leftover else ("", "")
            )
            vetoes = store.matching_vetoes(
                scope=scope if live_scope else None, members=members
            )
            hold = store.hold_reason(scope if live_scope else None)
            facts = authorization.Facts(
                scope=scope,
                leftover=leftover,
                vetoed=("%s %s" % (vetoes[0]["kind"], vetoes[0]["value"]))
                if vetoes
                else "",
                held=hold,
                hard_safety=(
                    protected_reasons[0]
                    if protected_reasons and len(members) == 2
                    else ""
                ),
                pair_action=pair_action,
                pair_reason=pair_reason,
                suppress_stops=bool(cfg.get("_profile_suppress_stops")),
            )
            explanation = _why_report(
                cfg,
                store,
                key=key,
                live_identity=live_identity,
                target_scope=scope,
                scope_live=live_scope,
                members=members,
                trigger=trigger,
                facts=facts,
                action=info.get("default_action", "unknown"),
                confidence=None,
                reason=info.get("why", ""),
                authority_source="learned default",
                learning=info,
                provenance=persisted,
                protected_reason="; ".join(protected_reasons),
            )
            if selected.kind == "desktop":
                explanation["learning"]["desktop_id"] = selected.value
            label = target_query

    model = view.record("explain", {"target": label, "explanation": explanation})
    view.emit(model, a, view.render_explanation(label, explanation))
    return 0


def cmd_keep(a):
    cfg, store, units = _load(a)
    pair = getattr(a, "pair", None)
    if pair:
        if getattr(a, "exe", None):
            return die("use either an executable or --pair OWNER LEFTOVER", 2)
        owner, leftover = pair
        if getattr(a, "dry_run", False):
            print("dry run: remember keep for %s > %s" % (owner, leftover))
            return 0
        how, reply = feedback_action(
            cfg,
            store,
            "teach",
            owner=owner,
            leftovers=[leftover],
            choice="keep",
        )
        if not reply or not reply.get("ok"):
            return die((reply or {}).get("error", "could not teach pair"))
        print("%s > %s: keep (%s)" % (owner, leftover, how))
        return 0
    if not getattr(a, "exe", None):
        return die("keep requires an executable or --pair OWNER LEFTOVER", 2)
    from . import targets

    key = a.exe
    candidates = _target_candidates(a.exe, store)
    matches = targets.matching_targets(a.exe, candidates)
    if matches:
        selected = _choose_target(a.exe, candidates, pick=getattr(a, "pick", False))
        if not isinstance(selected, targets.Target):
            return selected
        if selected.kind not in ("app", "desktop"):
            return die("keep requires an app key or desktop id", 2)
        key = selected.app_key or selected.value
    elif a.exe.startswith("desktop:"):
        return die("no live desktop id matches %r" % a.exe, 2)
    if getattr(a, "dry_run", False):
        print("dry run: remember keep for %s" % key)
        return 0
    how = feedback(cfg, store, "keep", key)
    store.bump(key, "user_keep", 3.0)  # local view only: read-only store, never saved
    print("%s: %s (%s)" % (key, store.default_action(key)[0], how))
    return 0


def cmd_do_not_kill(a):
    cfg, store, _units = _load(a)
    if a.target:
        from . import targets

        candidates = _target_candidates(a.target, store)
        matches = targets.matching_targets(a.target, candidates)
        if matches:
            selected = _choose_target(
                a.target, candidates, pick=getattr(a, "pick", False)
            )
            if not isinstance(selected, targets.Target):
                return selected
            try:
                if selected.kind == "scope":
                    vetoes = [{"kind": "scope", "value": selected.value, "start": None}]
                elif selected.kind == "pid":
                    if (
                        selected.pid is None
                        or inspect.starttime(selected.pid) != selected.start
                    ):
                        return die(
                            "pid %s changed since target selection" % selected.value, 2
                        )
                    vetoes = [
                        {
                            "kind": "pid",
                            "value": selected.value,
                            "start": selected.start,
                        }
                    ]
                else:
                    value = selected.app_key or selected.value
                    vetoes = [{"kind": "app", "value": value, "start": None}]
            except ValueError as e:
                return die(str(e))
        else:
            if a.target.startswith("desktop:"):
                return die("no live desktop id matches %r" % a.target, 2)
            try:
                vetoes = [veto_target(a.target, store)]
            except ValueError as e:
                return die(str(e))
    else:
        action = store.auto_action()
        if not action:
            return die("no automatic stop to veto", 2)
        apps = action.get("apps") or [
            pair[1]
            for pair in action.get("pairs", [])
            if isinstance(pair, list) and len(pair) == 2
        ]
        vetoes = (
            [
                {"kind": "app", "value": app, "start": None}
                for app in dict.fromkeys(apps)
            ]
            if apps
            else [{"kind": "scope", "value": action["scope"], "start": None}]
        )
    if getattr(a, "dry_run", False):
        for target in vetoes:
            print("dry run: veto %s" % veto_label(target))
        return 0
    if len(vetoes) > 1 and not _confirm_bulk(
        "veto", [veto_label(target) for target in vetoes], a
    ):
        return 1
    for target in vetoes:
        how, reply = feedback_action(cfg, store, "veto", target=target)
        if not reply or not reply.get("ok"):
            return die(reply.get("error", "could not add veto"))
        print("vetoed %s (%s)" % (veto_label(target), how))
    return 0


def cmd_undo(a):
    cfg, store, _units = _load(a)
    action = store.auto_action()
    if not action:
        return die("no automatic stop to undo", 2)
    target_id = action.get("decision_id") or action["id"]
    if getattr(a, "dry_run", False):
        print("dry run: undo automatic stop %s" % target_id)
        return 0
    how, reply = feedback_action(cfg, store, "undo", action_id=str(target_id))
    if not reply or not reply.get("ok"):
        return die(reply.get("error", "could not undo automatic stop"))
    targets = reply.get("targets") or [
        {"kind": "app", "value": app} for app in action.get("apps", [])
    ]
    print(
        "undo: %s; vetoed %s"
        % (
            action.get("scope", "automatic stop"),
            ", ".join(veto_label(t) for t in targets) or "the stopped scope",
        )
    )
    return 0


def _cmd_hold(a, held):
    cfg, store, _units = _load(a)
    scope = None
    target = getattr(a, "target", None)
    if target:
        from . import targets

        selected = _choose_target(
            target,
            _target_candidates(target, store),
            pick=getattr(a, "pick", False),
        )
        if not isinstance(selected, targets.Target):
            return selected
        scope = selected.scope or (selected.value if selected.kind == "scope" else None)
        if not scope:
            return die("target is not inside a managed scope", 2)
    action = "hold" if held else "resume"
    reason = getattr(a, "reason", "") or "user requested %s for %s" % (
        action,
        scope or "all actions",
    )
    if len(reason) > 256:
        return die("reason must be at most 256 characters", 2)
    if getattr(a, "dry_run", False):
        print("dry run: %s taema actions for %s" % (action, scope or "all scopes"))
        return 0
    fields = {"held": held, "reason": reason}
    if scope is not None:
        fields["scope"] = scope
    how, reply = feedback_action(cfg, store, "hold", **fields)
    if not reply or not reply.get("ok"):
        return die(reply.get("error", "could not %s taema actions" % action))
    print("%s taema actions for %s (%s)" % (action, scope or "all scopes", how))
    return 0


def cmd_hold(a):
    return _cmd_hold(a, True)


def cmd_resume(a):
    return _cmd_hold(a, False)


def _snooze_deadline(values):
    text = " ".join(values).strip()
    if text.lower().startswith("until "):
        clock_text = text[6:].strip()
        try:
            clock = _local_time.fromisoformat(clock_text)
        except ValueError:
            raise ValueError("snooze time must look like `until 18:00`") from None
        if len(clock_text) != 5 or clock.second or clock.microsecond:
            raise ValueError("snooze time must look like `until 18:00`")
        now = _datetime.now().astimezone()
        deadline = _datetime.combine(now.date(), clock, tzinfo=now.tzinfo)
        if deadline <= now:
            deadline += _timedelta(days=1)
        return deadline.timestamp()
    from .inputs import parse_duration

    seconds = parse_duration(text)
    if seconds <= 0:
        raise ValueError("snooze duration must be greater than zero")
    return time.time() + seconds


def cmd_snooze(a):
    cfg, store, _units = _load(a)
    try:
        until = _snooze_deadline(a.when)
    except ValueError as error:
        return die(str(error))
    if getattr(a, "dry_run", False):
        print("dry run: snooze all taema actions until %s" % until)
        return 0
    display_until = (
        _datetime.fromtimestamp(until).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    )
    reason = "user snoozed actions until %s" % display_until
    how, reply = feedback_action(cfg, store, "snooze", until=until, reason=reason)
    if not reply or not reply.get("ok"):
        return die(reply.get("error", "could not snooze taema actions"))
    print("snoozed all taema actions until %s (%s)" % (display_until, how))
    return 0


def cmd_forget(a):
    cfg, store, units = _load(a)
    if getattr(a, "veto", False):
        from . import targets

        candidates = _target_candidates(a.exe, store)
        matches = targets.matching_targets(a.exe, candidates)
        if matches:
            selected = _choose_target(a.exe, candidates, pick=getattr(a, "pick", False))
            if not isinstance(selected, targets.Target):
                return selected
            if selected.kind == "scope":
                target = {"kind": "scope", "value": selected.value, "start": None}
            elif selected.kind == "pid":
                if (
                    selected.pid is None
                    or inspect.starttime(selected.pid) != selected.start
                ):
                    return die(
                        "pid %s changed since target selection" % selected.value, 2
                    )
                target = {
                    "kind": "pid",
                    "value": selected.value,
                    "start": selected.start,
                }
            else:
                target = {
                    "kind": "app",
                    "value": selected.app_key or selected.value,
                    "start": None,
                }
        else:
            if a.exe.startswith("desktop:"):
                return die("no live desktop id matches %r" % a.exe, 2)
            try:
                target = veto_target(a.exe, store, for_removal=True)
            except ValueError as e:
                return die(str(e))
        existed = any(
            v.get("kind") == target["kind"]
            and v.get("value") == str(target["value"])
            and (target.get("start") is None or v.get("start") == target.get("start"))
            for v in store._active_vetoes()
        )
        if getattr(a, "dry_run", False):
            print("dry run: remove veto for %s" % veto_label(target))
            return 0
        how, reply = feedback_action(cfg, store, "unveto", target=target)
        if not reply or not reply.get("ok"):
            return die(reply.get("error", "could not remove veto"))
        removed = reply.get("removed", []) or existed
        print(
            "forgot veto for %s (%s)" % (veto_label(target), how)
            if removed
            else "no veto for %s (%s)" % (veto_label(target), how)
        )
        return 0
    if getattr(a, "dry_run", False):
        print("dry run: forget %s" % a.exe)
        return 0
    known = store.forget(a.exe)
    feedback(cfg, store, "forget", a.exe)
    print("forgot %s" % a.exe if known else "nothing learned for %s" % a.exe)
    return 0


# ---- status / gc / adopt / daemon ---------------------------------------------------------


def print_pairs(pairs):
    """Pair table: what each (owner, leftover) pair would do and how sure taema is."""
    if not pairs:
        print("pairs: none learned yet")
        return
    print(
        "%-22s %-22s %-10s %5s %5s %5s %6s  %s"
        % ("owner", "leftover", "action", "conf", "stop", "keep", "closes", "why")
    )
    for r in pairs:
        print(
            "%-22s %-22s %-10s %5.2f %5.2f %5.2f %6d  %s"
            % (
                lineage.clean(r["owner"], 22),
                lineage.clean(r["leftover"], 22),
                r["action"],
                r["confidence"],
                r["stop"],
                r["keep"],
                r["closes"],
                lineage.clean(r["why"], 60),
            )
        )


def print_auto(auto):
    """Auto mode: scopes it created, leftover leaves, and the last auto stops with their reason."""
    import time

    print(
        "auto: %d auto-adopted scopes, %d leftover leaves"
        % (auto.get("auto_adopted_scopes", 0), auto.get("leftover_leaves", 0))
    )
    stops = auto.get("auto_stops", [])
    if not stops:
        print("auto stops: none yet")
    for s in stops[-5:]:
        print(
            "auto stop %s %-24s %s  [%s]"
            % (
                time.strftime("%m-%d %H:%M", time.localtime(s.get("ts", 0))),
                lineage.clean(s.get("scope", ""), 24),
                lineage.clean(s.get("why", ""), 70),
                lineage.clean(", ".join(s.get("pairs", [])), 60),
            )
        )


def cmd_status(a):
    from . import view

    client_config_error = None
    try:
        cfg, store = _load_status(a)
    except (ValueError, OSError) as error:
        from .. import doctor

        client_config_error = str(error)
        cfg = doctor.fallback_config()
        socket_override = getattr(a, "socket", None)
        if socket_override:
            cfg["paths"]["socket"] = policy.expand(socket_override)
            cfg["paths"]["socket_fallback"] = cfg["paths"]["socket"]
        store = None
    reply = ask(cfg, {"cmd": "status"})
    empty_hold_state = {
        "global": False,
        "scopes": [],
        "snooze_until": None,
        "snooze_remaining_s": 0,
        "reason": "",
    }
    if store is None:
        store = _status_store(cfg, pending_only=reply is not None)
    if reply is None:
        effective_authority = policy.effective_authority(cfg)
        invalid = int(store.data.get("feedback_invalid", 0)) if store else 0
        hold = store.hold_reason() if store else ""
        hold_state = store.hold_status() if store else empty_hold_state
        status = {
            "daemon": "unavailable",
            "mode": cfg["mode"],
            "authority": effective_authority["value"],
            "authority_source": effective_authority["source"],
            "profile": cfg.get("_profile_name", "auto"),
            "profile_reason": cfg.get("_profile_reason", "automatic profile selection"),
            "feedback_invalid": invalid
            + (store.pending_feedback_invalid() if store else 0),
            "hold": hold or "",
            "hold_state": hold_state,
            "config": list(cfg["_sources"]),
            "config_error": client_config_error,
            "details": {
                "reviews": len(store.open_reviews()) if store else 0,
                "latest_decision": store.latest_decision() if store else None,
            },
        }
        result = 3
    else:
        reply["feedback_invalid"] = int(
            reply.get(
                "feedback_invalid",
                store.data.get("feedback_invalid", 0) if store else 0,
            )
        ) + (store.pending_feedback_invalid() if store else 0)
        reply["hold"] = store.hold_reason() if store else reply.get("hold", "")
        reply["hold_state"] = (
            store.hold_status() if store else reply.get("hold_state", empty_hold_state)
        )
        status = {
            "daemon": "running",
            "mode": reply.get("mode", cfg["mode"]),
            "authority": reply.get(
                "authority", policy.effective_authority(cfg)["value"]
            ),
            "authority_source": reply.get(
                "authority_source", policy.effective_authority(cfg)["source"]
            ),
            "profile": reply.get("profile", cfg.get("_profile_name", "auto")),
            "profile_reason": reply.get(
                "profile_reason",
                cfg.get("_profile_reason", "automatic profile selection"),
            ),
            "feedback_invalid": int(reply["feedback_invalid"]),
            "hold": reply["hold"] or "",
            "hold_state": reply["hold_state"],
            "config": list(reply.get("config", cfg["_sources"])),
            "config_error": reply.get("config_error") or client_config_error,
            "details": reply,
        }
        result = 0
    base = cgroup.base()
    if os.path.isdir(base):
        if getattr(a, "json", False) or getattr(a, "jsonl", False):
            scopes = []
            for path in sorted(cgroup.subdirs(base)):
                _walk(path, 0, scopes)
            scope_count = len(scopes)
        else:
            scopes = []
            scope_count = _count_scopes(base)
    else:
        scopes = []
        scope_count = 0
    model = view.snapshot("status", status, scopes, scope_count=scope_count)
    records = [view.record("status", {"status": status})]
    records.extend(view.record("scope", row) for row in scopes)
    view.emit(
        model,
        a,
        view.render_status(model, a, summary=bool(getattr(a, "_summary", False))),
        records,
    )
    return result


def cmd_doctor(a):
    """Ask the daemon for diagnostics, then run the same checks locally if it is down."""
    from .. import doctor
    from . import view

    config_error = None
    try:
        cfg = policy.load_config(path=getattr(a, "config", None))
    except Exception as error:
        config_error = error
        try:
            cfg = policy.load_config()
        except Exception:
            cfg = doctor.fallback_config()

    report = ask(cfg, {"cmd": "doctor"}) if config_error is None else None
    if not isinstance(report, dict) or not isinstance(report.get("checks"), list):
        store = None
        units = None
        units_error = None
        store_error = None
        if config_error is None:
            try:
                store = knowledge.Store(
                    policy.expand(cfg["paths"]["state_dir"]),
                    cfg.get("seeds"),
                    read_only=True,
                    deny=policy.owner_deny(cfg),
                    mode=cfg.get("mode", "observe"),
                    learn=cfg.get("learn"),
                )
            except Exception as error:
                store_error = error
            try:
                units = policy.load_units(cfg)
            except Exception as error:
                units_error = error
        report = doctor.diagnose(
            cfg,
            store,
            units,
            config_error=config_error,
            units_error=units_error,
            store_error=store_error,
        )
    view.emit(report, a, doctor.render(report))
    return 1 if report.get("status") == "fail" else 0


def _config_error(error):
    print("taema: %s" % error, file=sys.stderr)
    return 1


def _reload_after_config(cfg, reason="configuration change"):
    reply = ask(cfg, {"cmd": "reload", "reason": reason})
    if reply is None:
        print(
            "saved; daemon is unavailable and will load this configuration at startup"
        )
        return 0
    if not isinstance(reply, dict) or not reply.get("reloaded"):
        error = (
            reply.get("config_error") or reply.get("error")
            if isinstance(reply, dict)
            else "invalid reply"
        )
        print("configuration saved, but daemon reload failed: %s" % error)
        return 1
    print("configuration saved and reloaded")
    return 0


def cmd_config_show(a):
    from ..config import management

    try:
        cfg = policy.load_config(path=getattr(a, "config", None))
        rendered = management.effective_toml(cfg)
        if getattr(a, "sources", False):
            rendered += "\n".join(management.source_lines(cfg)) + "\n"
        print(rendered, end="")
        return 0
    except Exception as error:
        return _config_error(error)


def cmd_config_get(a):
    from ..config import management

    try:
        value = management.get_value(a.key, getattr(a, "config", None))
        print(management.format_value(value))
        return 0
    except Exception as error:
        return _config_error(error)


def cmd_config_set(a):
    from ..config import management

    try:
        management.set_value(a.key, a.value)
        cfg = policy.load_config()
    except Exception as error:
        return _config_error(error)
    return _reload_after_config(cfg, "taema config set")


def cmd_config_unset(a):
    from ..config import management

    try:
        management.unset_value(a.key)
        cfg = policy.load_config()
    except Exception as error:
        return _config_error(error)
    return _reload_after_config(cfg, "taema config unset")


def cmd_config_edit(a):
    from ..config import management

    try:
        management.edit_managed()
        cfg = policy.load_config()
    except Exception as error:
        return _config_error(error)
    return _reload_after_config(cfg, "taema config edit")


def cmd_config_diff(a):
    from ..config import management

    try:
        rendered = management.diff_text()
    except Exception as error:
        return _config_error(error)
    print(rendered or "no configuration differences")
    return 0


def cmd_reload(a):
    try:
        cfg = policy.load_config(path=getattr(a, "config", None))
    except Exception as error:
        return _config_error(error)
    reply = ask(cfg, {"cmd": "reload", "reason": "taema reload command"})
    if reply is None:
        print("taema: daemon is unavailable", file=sys.stderr)
        return 3
    if not isinstance(reply, dict) or not reply.get("reloaded"):
        daemon_error = (
            reply.get("config_error") or reply.get("error")
            if isinstance(reply, dict)
            else "invalid daemon reply"
        )
        return _config_error(daemon_error)
    print("configuration and units reloaded")
    return 0


def _capability_changes(old_mode, new_mode):
    from .. import authorization

    changes = []
    for trigger in authorization.TRIGGER_ACTIONS:
        before = authorization.authorize(trigger, old_mode)
        after = authorization.authorize(trigger, new_mode)
        before_value = before.verdict
        after_value = after.verdict
        if before.authority:
            before_value += "/" + before.authority
        if after.authority:
            after_value += "/" + after.authority
        if before_value != after_value:
            changes.append("  %s: %s -> %s" % (trigger, before_value, after_value))
    return changes


def cmd_mode(a):
    from ..config import management

    try:
        if os.environ.get("TAEMA_CONFIG"):
            raise ValueError(
                "TAEMA_CONFIG overrides mode changes in the managed drop-in"
            )
        old_cfg = policy.load_config()
        if a.mode not in policy.MODES:
            raise ValueError("mode must be one of %s" % (policy.MODES,))
        management.set_value("profile.runtime_mode", management.format_value(a.mode))
        cfg = policy.load_config()
    except Exception as error:
        return _config_error(error)
    result = _reload_after_config(cfg, "taema mode command")
    if result:
        return result
    print("mode: %s -> %s" % (old_cfg["mode"], cfg["mode"]))
    changes = _capability_changes(old_cfg["mode"], cfg["mode"])
    print("capability matrix changes:")
    print("\n".join(changes) if changes else "  no lifecycle capability changes")
    if cfg.get("_profile_suppress_stops"):
        print("active quiet profile continues to suppress automatic stops")
    return 0


def cmd_profile(a):
    from ..config import management

    try:
        if os.environ.get("TAEMA_CONFIG"):
            raise ValueError(
                "TAEMA_CONFIG overrides profile changes in the managed drop-in"
            )
        old_cfg = policy.load_config()
        profile_name = a.name
        profile_table = old_cfg.get("profile", {})
        if profile_name != "auto" and not isinstance(
            profile_table.get(profile_name), dict
        ):
            raise ValueError(
                "unknown profile %r; available profiles: %s"
                % (
                    profile_name,
                    ", ".join(
                        sorted(
                            key
                            for key, value in profile_table.items()
                            if key != "auto" and isinstance(value, dict)
                        )
                    ),
                )
            )
        management.set_value("profile.active", management.format_value(profile_name))
        cfg = policy.load_config()
    except Exception as error:
        return _config_error(error)
    reason = (
        "automatic profile selection requested"
        if profile_name == "auto"
        else "selected manually with taema profile"
    )
    result = _reload_after_config(cfg, reason)
    if result:
        return result
    print(
        "profile: %s -> %s (%s)"
        % (old_cfg.get("_profile_name", "auto"), profile_name, reason)
    )
    if profile_name == "quiet":
        print("quiet suppresses automatic stops and notifications")
    elif profile_name == "server":
        print(
            "server disables desktop agent, window-close, launch-wrap, and notifications"
        )
    elif profile_name == "battery":
        print("battery reduces wakeups and shortens the configured freeze delay")
    elif profile_name == "game":
        print(
            "game protects gamescope and Steam processes, with notifications disabled"
        )
    return 0


def cmd_review(a):
    from . import view

    cfg, store, _units = _load(a)
    reviews = sorted(
        store.review_details(store.open_reviews()),
        key=lambda item: (item.get("created", 0), str(item.get("id", ""))),
    )
    if getattr(a, "interactive", False):
        if getattr(a, "json", False) or getattr(a, "jsonl", False):
            return die("--interactive cannot be combined with JSON output", 2)
        if not sys.stdin.isatty():
            return die("interactive review needs a terminal", 2)
        return _interactive_reviews(a, cfg, store, reviews)
    model = view.record("reviews", {"reviews": reviews})
    records = [view.record("review", {"review": item}) for item in reviews]
    view.emit(model, a, view.render_reviews(reviews), records)
    return 0


def _review_choice(value):
    return {
        "1": "stop",
        "2": "keep",
        "3": "standalone",
        "4": "never",
    }.get(value, value)


def _parse_review_id(value):
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if not isinstance(value, str):
        return None
    try:
        if value.startswith("r-"):
            return int(value[2:], 16)
        return int(value.lstrip("#"), 10)
    except ValueError:
        return None


def cmd_answer(a):
    cfg, store, _units = _load(a)
    identifier = _parse_review_id(a.id)
    if not identifier or identifier < 1:
        return die("review id must be a positive number or r-hex id", 2)
    choice = _review_choice(a.choice)
    if choice not in knowledge.CHOICES:
        return die("choice must be stop, keep, standalone, or never", 2)
    how, reply = feedback_action(
        cfg,
        store,
        "review_answer",
        review_id=identifier,
        choice=choice,
        **({"owner": a.owner} if getattr(a, "owner", None) else {}),
    )
    if not reply or not reply.get("ok"):
        return die(
            (reply or {}).get("error", "review is missing, expired, or not answerable")
        )
    print("review #%s answered %s (%s)" % (identifier, choice, how))
    return 0


def cmd_teach(a):
    cfg, store, _units = _load(a)
    how, reply = feedback_action(
        cfg,
        store,
        "teach",
        owner=a.owner,
        leftovers=[a.leftover],
        choice=a.choice,
    )
    if not reply or not reply.get("ok"):
        return die((reply or {}).get("error", "could not teach relationship"))
    print("%s > %s: %s (%s)" % (a.owner, a.leftover, a.choice, how))
    return 0


def _interactive_reviews(args, cfg, store, reviews):
    if not reviews:
        print("open reviews: 0")
        return 0
    for review in reviews:
        identifier = review.get("id")
        owner = review.get("owner")
        candidates = [
            item.get("key")
            for item in review.get("candidates", [])
            if isinstance(item, dict) and isinstance(item.get("key"), str)
        ]
        if not owner and len(candidates) == 1:
            owner = candidates[0]
        if not owner and candidates:
            print("review #%s candidates: %s" % (identifier, ", ".join(candidates)))
            try:
                owner = input("Owner key (Enter to leave): ").strip() or None
            except (EOFError, OSError):
                return 0
            if owner not in candidates:
                print("review #%s left pending (choose one listed owner)" % identifier)
                continue
        from . import view

        print(view.render_reviews([review]), end="")
        if review.get("kind") == "scope":
            continue
        if review.get("shown"):
            print("already shown; answer with `taema answer %s CHOICE`" % identifier)
            continue
        pairs = [
            (owner, key)
            for key in review.get("survivors", [])
            if isinstance(owner, str)
        ]
        if not pairs or not all(
            store.can_ask(pair, signature=review.get("sig")) for pair in pairs
        ):
            print("review #%s left pending (question limit reached)" % identifier)
            continue
        fields = {"review_id": identifier}
        if owner and owner != review.get("owner"):
            fields["owner"] = owner
        how, reply = feedback_action(cfg, store, "review_shown", **fields)
        if not reply or not reply.get("ok"):
            print(
                "review #%s left pending (%s)"
                % (identifier, (reply or {}).get("error", "rate limited"))
            )
            continue
        try:
            value = (
                input("Choice [1 stop, 2 keep, 3 standalone, 4 never, Enter later]: ")
                .strip()
                .lower()
            )
        except (EOFError, OSError):
            return 0
        if not value:
            continue
        choice = _review_choice(value)
        if choice not in knowledge.CHOICES:
            print("review #%s left pending (unknown choice)" % identifier)
            continue
        how, reply = feedback_action(
            cfg,
            store,
            "review_answer",
            review_id=identifier,
            choice=choice,
            **({"owner": owner} if owner and owner != review.get("owner") else {}),
        )
        if not reply or not reply.get("ok"):
            print(
                "review #%s left pending (%s)"
                % (identifier, (reply or {}).get("error", "could not answer"))
            )
        else:
            print("review #%s answered %s (%s)" % (identifier, choice, how))
    return 0


def _emit_event(event, args, line_only=False):
    from .. import events as event_views

    record = {"schema": "taema.event.v1", **event_views.view_event(event)}
    if line_only:
        print(event_views.event_line(event))
    elif getattr(args, "jsonl", False) or getattr(args, "follow", False):
        print(json.dumps(record, ensure_ascii=False, sort_keys=True))
    else:
        print(event_views.event_line(event))


def _follow_events(cfg, args, since_seq, line_only=False):
    from .. import events as event_views

    try:
        for item in subscribe(cfg, event_views.TOPICS, since_seq):
            if "error" in item:
                print("taema: %s" % item["error"], file=sys.stderr)
                return 3
            event = item.get("event")
            if isinstance(event, dict):
                if not getattr(args, "event", None) or event.get("event") == args.event:
                    _emit_event(event, args, line_only=line_only)
            elif item.get("resync") is True:
                marker = {
                    "schema": "taema.resync.v1",
                    "latest_seq": item.get("latest_seq", since_seq),
                }
                if line_only:
                    print("resync %s" % marker["latest_seq"])
                elif getattr(args, "json", False) or getattr(args, "jsonl", False):
                    print(json.dumps(marker, sort_keys=True))
                else:
                    print("resync %s" % marker["latest_seq"])
    except KeyboardInterrupt:
        return 0
    return 0


def cmd_events(a):
    """Query retained audit events, optionally continuing as a live stream."""
    from .. import events as event_views
    from ..protocol import MAX_REQUEST_ID

    if not 0 <= a.since <= MAX_REQUEST_ID:
        return die("--since must be a non-negative safe sequence number")
    cfg, store = _load_events(a)
    result = store.events_since(a.since, limit=1000)
    events = result["events"]
    records = [event_views.view_event(event) for event in events]
    if a.event:
        records = [record for record in records if record["event"] == a.event]
    if a.json:
        print(
            json.dumps(
                {
                    "schema": "taema.events.v1",
                    "events": records,
                    "latest_seq": result["latest_seq"],
                    "has_more": result["more"],
                },
                ensure_ascii=False,
                sort_keys=True,
            )
        )
    else:
        for event in events:
            if not a.event or event.get("event") == a.event:
                _emit_event(event, a)
    if not a.follow:
        return 0
    cursor = events[-1]["seq"] if events else a.since
    return _follow_events(cfg, a, cursor)


def cmd_watch(a):
    """Print one plain event line whenever the daemon reports a change."""
    cfg, store = _load_events(a)
    return _follow_events(
        cfg, a, store.events_since(0, limit=1)["latest_seq"], line_only=True
    )


def cmd_prompt(a):
    """Print the cached prompt segment without connecting to the daemon."""
    from . import framework

    return framework._fast_prompt()


def cmd_learn_export(a):
    """Write the current store in the JSON format understood by the 0.2 release."""
    import tempfile

    _cfg, store, _units = _load(a)
    payload = json.dumps(store.export_legacy(), indent=2, sort_keys=True) + "\n"
    if not a.output:
        sys.stdout.write(payload)
        return 0
    path = os.path.abspath(os.path.expanduser(a.output))
    directory = os.path.dirname(path)
    temporary = None
    try:
        fd, temporary = tempfile.mkstemp(prefix=".taema-export-", dir=directory)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            os.fchmod(output.fileno(), 0o600)
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    except OSError as error:
        if temporary:
            try:
                os.unlink(temporary)
            except OSError:
                pass
        return die("could not write export: %s" % error)
    return 0


def cmd_gc(a):
    from . import view

    cfg, store, units = _load(a)
    reply = ask(cfg, {"cmd": "gc", "dry_run": a.dry_run}, timeout=60)
    available = reply is not None
    if reply is None:
        cands = engine.gc_candidates(cfg, units, store, {})
        reply = {
            "candidates": [[cgroup.rel(p), why] for p, why in cands],
            "note": "daemon not running; immediate candidates only",
        }
    model = view.record("gc", {"result": reply})
    view.emit(model, a, json.dumps(reply, indent=1, ensure_ascii=False) + "\n")
    return 0 if available else 3


def cmd_complete(a):
    """Return registry-backed commands and live target names for shell completion."""
    import shlex

    from . import targets
    from .registry import COMMANDS, GLOBAL_OPTIONS

    _cfg, store, _units = _load(a)
    candidates = targets.live_targets()
    candidates.extend(targets.known_app_targets(store))
    reviews = [str(item.get("id")) for item in store.open_reviews()]
    line = getattr(a, "line", "") or ""
    cursor = getattr(a, "cursor", None)
    prefix = line[:cursor] if cursor is not None else line
    try:
        words = shlex.split(prefix)
    except ValueError:
        words = prefix.split()
    if prefix and not prefix[-1].isspace() and words:
        words = words[:-1]
    if words and words[0] in ("taema", "tæma"):
        words = words[1:]
    command_names = [
        name
        for spec in COMMANDS
        if not spec.get("hidden")
        for name in (spec["name"], *spec["aliases"])
    ]
    command = next((word for word in words if word in command_names), None)
    word = getattr(a, "word", "") or ""
    if word.startswith("-"):
        values = [name[0] for name, _options in GLOBAL_OPTIONS]
        for spec in COMMANDS:
            if command not in (spec["name"], *spec["aliases"]):
                continue
            for names, _options in spec.get("arguments", ()):
                values.extend(name for name in names if name.startswith("-"))
            for child in spec.get("children", ()):
                for names, _options in child.get("arguments", ()):
                    values.extend(name for name in names if name.startswith("-"))
    elif command in (
        "kill",
        "stop",
        "explain",
        "why",
        "do-not-kill",
        "dnk",
        "never",
        "keep",
        "forget",
    ):
        values = targets.completion_values(candidates, reviews)
    elif command == "review":
        values = ["review:%s" % item for item in reviews]
    else:
        values = command_names + [name[0] for name, _options in GLOBAL_OPTIONS]
    folded = word.casefold()
    for value in sorted(set(values), key=str.casefold):
        if value.casefold().startswith(folded):
            print(value)
    return 0


def cmd_adopt(a):
    cfg, store, units = _load(a)
    if getattr(a, "standalone", False):
        if a.all:
            return die("--standalone cannot be combined with --all", 2)
        pt = inspect.ProcTable.scan()
        lin = lineage.Lineage(cfg)
        lin.observe(pt)
        in_session = set()
        for session in policy.session_cgroups(cfg):
            in_session.update(cgroup.procs(session))
        wanted = set(store.data.get("standalone", {}))
        candidates = sorted(
            (
                entry
                for entry in lin.entries.values()
                if entry.get("key") in wanted
                and entry.get("pid") in in_session
                and not policy.protected_reason(entry["pid"], cfg)
            ),
            key=lambda entry: (-len(entry.get("chain_ids", [])), entry["pid"]),
        )
        claimed = set()
        ops = []
        for entry in candidates:
            pid = entry["pid"]
            if pid in claimed:
                continue
            pids = [
                child
                for child in pt.descendants([pid])
                if child in in_session and child not in claimed
            ]
            if not pids:
                continue
            claimed.update(pids)
            ops.append(
                {
                    "op": "move",
                    "scope": engine.auto_scope_name(entry["key"], pid, entry["start"]),
                    "owner": entry["key"],
                    "unit": None,
                    "auto": True,
                    "pids": pids,
                }
            )
        decision = authorization.authorize(authorization.UNIT_ADOPT, cfg["mode"])
    elif a.all:
        pt = inspect.ProcTable.scan()
        lin = lineage.Lineage(cfg)
        lin.observe(pt)
        ops = engine.adopt_plan(cfg, units, pt) + engine.carve_plan(cfg, units, pt)
        ops += engine.auto_adopt_plan(cfg, units, pt, lin, store)
        decision = authorization.authorize(authorization.AUTO_ADOPT, cfg["mode"])
    else:
        ops = engine.adopt_plan(cfg, units) + engine.carve_plan(cfg, units)
        decision = authorization.authorize(authorization.UNIT_ADOPT, cfg["mode"])
    if a.all and len(ops) > 1 and not a.dry_run:
        if not _confirm_bulk(
            "adopt",
            [
                "%s %s (%d pids)" % (op["op"], op["scope"], len(op["pids"]))
                for op in ops
            ],
            a,
        ):
            return 1
    execute = (not a.dry_run) and decision.verdict == authorization.ACT
    ops = engine.run_ops(cfg, store, ops, execute)
    for op in ops:
        print(
            "%-6s %-34s pids=%d%s"
            % (op["op"], op["scope"], len(op["pids"]), " done" if op["done"] else "")
        )
    if not execute:
        print(
            "nothing moved (mode=%s%s)"
            % (cfg["mode"], ", --dry-run" if a.dry_run else "")
        )
    return 0


def cmd_daemon(a):
    from ..daemon import service as daemon

    cfg = policy.load_config(path=getattr(a, "config", None))
    socket_override = getattr(a, "socket", None)
    if socket_override:
        socket_override = policy.expand(socket_override)
        cfg["paths"]["socket"] = socket_override
        cfg["paths"]["socket_fallback"] = socket_override
    return daemon.run(cfg)


def main(argv):
    from .framework import main as framework_main

    return framework_main(argv)
