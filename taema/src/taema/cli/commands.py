"""`taema` command line. scoperun / scopekill / scopels are thin aliases (see bin/)."""

from contextlib import nullcontext
from datetime import datetime as _datetime
from datetime import time as _local_time
from datetime import timedelta as _timedelta
from itertools import count
import json
import math as _math
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
memory = _LazyModule("memory", "taema.core.memory")
inspect = _LazyModule("inspect", "taema.core.process")
lineage = _LazyModule("lineage", "taema.core.lineage")
engine = _LazyModule("engine", "taema.governor.engine")
knowledge = _LazyModule("knowledge", "taema.store.knowledge")
policy = _LazyModule("policy", "taema.config.policy")
transfer = _LazyModule("transfer", "taema.store.transfer")
desktop = _LazyModule("desktop", "taema.desktop")
bar = _LazyModule("bar", "taema.bar")
_pressure_guard = _LazyModule("_pressure_guard", "taema.governor.guard")

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


def _default_sock_paths():
    """[primary, fallback] socket paths from built-in defaults, without loading config."""
    primary = "/run/user/%d/taema.sock" % os.getuid()
    state_home = os.environ.get("XDG_STATE_HOME") or os.path.expanduser(
        "~/.local/state"
    )
    return [primary, os.path.join(state_home, "taema", "taema.sock")]


def _ask_paths(paths, msg, timeout=3.0):
    """One JSON request to the daemon over explicit socket paths.

    Returns the reply dict, or None when it is not running.
    """
    import socket

    identifier = next(_REQUEST_IDS)
    envelope = {
        "v": 2,
        "id": identifier,
        "cmd": msg["cmd"],
        "args": {key: value for key, value in msg.items() if key != "cmd"},
    }
    for path in paths:
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


def ask(cfg, msg, timeout=3.0):
    """One JSON request to the daemon. Returns the reply dict, or None when it is not running."""
    if not isinstance(msg, dict) or not isinstance(msg.get("cmd"), str):
        return {"error": "invalid request", "code": "invalid_request"}
    return _ask_paths(sock_paths(cfg), msg, timeout=timeout)


#: Reply keys bare `status` needs so it can skip the config load entirely.
_FAST_STATUS_KEYS = frozenset(
    {
        "mode",
        "authority",
        "authority_source",
        "profile",
        "profile_reason",
        "feedback_invalid",
        "hold",
        "hold_state",
        "guard",
        "config",
        "mem_enabled",
    }
)


def _fast_status_probe(a):
    """Return a complete status reply without loading config, or None for slow path."""
    if not getattr(a, "_fast", False):
        return None
    if getattr(a, "socket", None) or getattr(a, "config", None):
        return None
    if os.environ.get("TAEMA_CONFIG"):
        return None
    reply = _ask_paths(_default_sock_paths(), {"cmd": "status"})
    if not isinstance(reply, dict) or "error" in reply:
        return None
    if not _FAST_STATUS_KEYS.issubset(reply):
        return None
    if not isinstance(reply.get("mem_enabled"), bool):
        return None
    return reply


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


def feedback_action(cfg, store, op, queue_if_down=True, timeout=3.0, **fields):
    """Send a versioned policy action to the daemon or append it for offline replay."""
    import uuid

    msg = {"v": 2, "id": uuid.uuid4().hex, "op": op, **fields}
    reply = ask(cfg, {"cmd": "feedback", **msg}, timeout=timeout)
    if reply is not None:
        return "daemon", reply
    if not queue_if_down:
        return "offline", {"error": "daemon is not running"}
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
    if target.get("kind") == "pair":
        return "pair %s>%s" % (target.get("owner"), target.get("leftover"))
    label = "%s %s" % (target["kind"], target["value"])
    if target["kind"] == "pid" and target.get("start") is not None:
        label += " (starttime %s)" % target["start"]
    return label


def _veto_target_key(target):
    if target.get("kind") == "pair":
        return target["kind"], target.get("owner"), target.get("leftover")
    return target["kind"], str(target.get("value")), target.get("start")


def _map_resolved_target(selected):
    if selected.kind == "scope":
        return {"kind": "scope", "value": selected.value, "start": None}
    if selected.kind == "pid":
        if (
            selected.pid is None
            or selected.start is None
            or inspect.starttime(selected.pid) != selected.start
        ):
            raise ValueError("pid %s changed since target selection" % selected.value)
        return {
            "kind": "pid",
            "value": selected.value,
            "start": selected.start,
        }
    value = selected.app_key or selected.value
    if not value:
        raise ValueError("target has no stable application identity")
    return {"kind": "app", "value": value, "start": None}


def resolve_veto_targets(a, store, units, *, removal=False):
    """Resolve one explicit selector or a positional query without guessing."""
    from . import targets

    selectors = (
        "scope",
        "pid",
        "pair",
        "signature",
        "app",
        "owner",
        "unit",
        "cgroup",
        "path",
    )
    selected_flags = [name for name in selectors if getattr(a, name, None) is not None]
    query = getattr(a, "target", None)
    if query is None:
        query = getattr(a, "exe", None)
    if selected_flags and query:
        raise ValueError("use one explicit selector or a positional target")
    if len(selected_flags) > 1:
        raise ValueError("choose one veto target form")

    active = store._active_vetoes()
    if removal and query and not selected_flags:
        try:
            existing = veto_target(query, store, for_removal=True)
        except ValueError:
            existing = None
        if existing and any(
            store._same_veto_target(veto, existing, pid_wildcard=True)
            for veto in active
        ):
            return [(existing, ["active " + veto_label(existing)])]

    candidates = _target_candidates(None, store)
    pid_query = query.split(":", 1)[-1] if isinstance(query, str) else ""
    if isinstance(pid_query, str) and pid_query.isdigit():
        try:
            pid_target = targets.process_target(pid_query)
        except targets.TargetNotFound:
            pass
        else:
            if not any(
                item.kind == "pid"
                and item.value == pid_target.value
                and item.start == pid_target.start
                for item in candidates
            ):
                candidates.append(pid_target)

    if not selected_flags:
        if not query:
            return []
        matches = targets.matching_targets(query, candidates)
        if not matches:
            raise ValueError("no target matches %r" % query)
        if len(matches) > 1 and not getattr(a, "all", False):
            raise ValueError(
                "target %r is ambiguous: %s; use --all or a more specific target form"
                % (query, ", ".join(item.label for item in matches))
            )
        resolved = []
        for item in matches:
            target = _map_resolved_target(item)
            resolved.append((target, [item.label]))
    else:
        selector = selected_flags[0]
        value = getattr(a, selector)
        if removal:
            if selector == "pair":
                probe = {
                    "kind": "pair",
                    "value": value[1],
                    "start": None,
                    "owner": value[0],
                    "leftover": value[1],
                }
            elif selector == "pid":
                existing = next(
                    (
                        store._target(v)
                        for v in active
                        if v.get("kind") == "pid" and v.get("value") == str(value)
                    ),
                    None,
                )
                probe = existing
            else:
                probe = {"kind": selector, "value": value, "start": None}
            if probe and any(
                store._same_veto_target(veto, probe, pid_wildcard=True)
                for veto in active
            ):
                return [(probe, ["active " + veto_label(probe)])]
        if selector == "pair":
            owner, leftover = value
            if not owner or not leftover or len(owner) > 256 or len(leftover) > 256:
                raise ValueError("pair veto requires OWNER and LEFTOVER keys")
            key = store.pkey(owner, leftover)
            if key not in store.data.get("pairs", {}):
                if not any(
                    v.get("kind") == "pair"
                    and v.get("owner") == owner
                    and v.get("leftover") == leftover
                    for v in active
                ):
                    raise ValueError("no stored pair matches %s>%s" % (owner, leftover))
            target = {
                "kind": "pair",
                "value": leftover,
                "start": None,
                "owner": owner,
                "leftover": leftover,
            }
            resolved = [(target, ["stored pair %s>%s" % (owner, leftover)])]
        elif selector == "signature":
            if not store.db.signature(value) and not any(
                v.get("kind") == "signature" and v.get("value") == value for v in active
            ):
                raise ValueError("no stored signature matches %s" % value)
            resolved = [
                (
                    {"kind": "signature", "value": value, "start": None},
                    ["stored signature " + value],
                )
            ]
        elif selector == "pid":
            try:
                item = targets.process_target(value)
            except targets.TargetNotFound:
                if removal:
                    existing = next(
                        (
                            store._target(v)
                            for v in active
                            if v.get("kind") == "pid" and v.get("value") == str(value)
                        ),
                        None,
                    )
                    if existing:
                        resolved = [(existing, ["active " + veto_label(existing)])]
                    else:
                        raise ValueError("no live pid matches %s" % value) from None
                else:
                    raise ValueError("no live pid matches %s" % value) from None
            else:
                resolved = [(_map_resolved_target(item), [item.label])]
        elif selector in ("scope", "app"):
            kind = selector
            matches = [
                item
                for item in candidates
                if item.kind == kind
                and (
                    item.value == value
                    or (kind == "scope" and item.value.rsplit("/", 1)[-1] == value)
                )
            ]
            if not matches:
                if removal:
                    existing = next(
                        (
                            store._target(v)
                            for v in active
                            if v.get("kind") == kind and v.get("value") == str(value)
                        ),
                        None,
                    )
                    if existing:
                        return [(existing, ["active " + veto_label(existing)])]
                raise ValueError("no %s target matches %r" % (kind, value))
            if len(matches) > 1 and not getattr(a, "all", False):
                raise ValueError(
                    "%s target %r is ambiguous: %s; use --all"
                    % (kind, value, ", ".join(item.label for item in matches))
                )
            resolved = [
                (
                    {"kind": kind, "value": item.value, "start": None},
                    [item.label],
                )
                for item in matches
            ]
        elif selector == "owner":
            known = {item.value for item in candidates if item.kind == "app"}
            known.update(
                key.split(knowledge.SEP, 1)[0] for key in store.data.get("pairs", {})
            )
            if value not in known:
                raise ValueError("no owner identity matches %r" % value)
            resolved = [
                (
                    {"kind": "owner", "value": value, "start": None},
                    ["owner app:" + value],
                )
            ]
        elif selector == "unit":
            names = {
                item.get("unit", {}).get("name")
                for item in units
                if isinstance(item.get("unit", {}).get("name"), str)
            }
            if value not in names:
                raise ValueError("no configured unit matches %r" % value)
            live = [
                item.label
                for item in candidates
                if item.kind == "scope"
                and (item.value == value or item.value.startswith(value + "-"))
            ]
            resolved = [
                (
                    {"kind": "unit", "value": value, "start": None},
                    live or ["configured unit " + value],
                )
            ]
        elif selector in ("cgroup", "path"):
            if selector == "path" and not os.path.isabs(value):
                raise ValueError("executable path must be absolute")

            def is_under(path, prefix):
                path, prefix = path.strip("/"), prefix.strip("/")
                return bool(path and prefix) and (
                    path == prefix or path.startswith(prefix + "/")
                )

            matched = []
            pids = [item for item in candidates if item.kind == "pid"]
            for item in pids:
                path = (
                    inspect.exe(item.pid)
                    if selector == "path" and item.pid is not None
                    else cgroup.proc_cgroup(item.pid)
                    if item.pid is not None
                    else None
                )
                if selector == "path" and path == value:
                    matched.append(item.label)
                elif (
                    selector == "cgroup"
                    and isinstance(path, str)
                    and is_under(path, value)
                ):
                    matched.append(item.label)
            if selector == "cgroup":
                matched.extend(
                    item.label
                    for item in candidates
                    if item.kind == "scope" and is_under(item.value, value)
                )
            if not matched:
                raise ValueError("no %s target matches %r" % (selector, value))
            resolved = [
                (
                    {"kind": selector, "value": value, "start": None},
                    list(dict.fromkeys(matched)),
                )
            ]

    deduped = {}
    for target, labels in resolved:
        key = _veto_target_key(target)
        if key not in deduped:
            deduped[key] = [target, []]
        deduped[key][1].extend(
            label for label in labels if label not in deduped[key][1]
        )
    return [(target, labels) for target, labels in deduped.values()]


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
    restore_launch = os.environ.pop("TAEMA_RESTORE_LAUNCH", None) == "1"
    restore_ack_fd = None
    if restore_launch:
        raw_ack_fd = os.environ.pop("TAEMA_RESTORE_ACK_FD", "")
        if raw_ack_fd.isdecimal():
            restore_ack_fd = int(raw_ack_fd)

    def restore_fail(message, code=1):
        if restore_launch and restore_ack_fd is not None:
            try:
                os.write(
                    restore_ack_fd,
                    b"E" + str(message).encode("utf-8", errors="replace")[:2048],
                )
            except OSError:
                pass
        return die(message, code)

    if restore_launch and restore_ack_fd is None:
        return die("restore startup acknowledgment is unavailable")
    cfg, store, units = _load(a)
    name = a.name
    if not cgroup.valid_rel(name) or "/" in name or len(name) > 32:
        return restore_fail("bad name (use a-z 0-9 _ -, max 32)")
    base = cgroup.base()
    if not os.path.isdir(base):
        return restore_fail(
            "%s missing; is the taema service running and are you in the taema group? (sv status taema)"
            % base
        )
    leaf = "%s/scope-%s" % (base, name)
    if os.path.isdir(leaf) and cgroup.tree_procs(leaf) and not a.join:
        return restore_fail("scope %s already has processes (use --join to add)" % name)
    owner = os.getpid() if a.bind else a.owner
    if owner and inspect.uid_of(owner) == -1:
        return restore_fail(
            "owner pid %d is gone; not starting scope-%s" % (owner, name)
        )
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
        return restore_fail("register failed: %s" % reply["error"])
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
        return restore_fail("attach failed: %s" % e)
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
    if restore_launch:
        try:
            target_env = inspect.restore_environment(os.environ)
            os.set_inheritable(restore_ack_fd, False)
            os.write(restore_ack_fd, b"R")
            os.execvpe(a.cmd[0], a.cmd, target_env)
        except OSError as error:
            try:
                os.write(
                    restore_ack_fd,
                    b"E" + str(error).encode("utf-8", errors="replace")[:2048],
                )
            except OSError:
                pass
            return die("could not exec restored command: %s" % error)
    os.execvp(a.cmd[0], a.cmd)


# ---- launch -------------------------------------------------------------------------------


def cmd_launch(a):
    from .. import agent as agent_mod

    cfg, _store, _units = _load(a)
    cmd = list(getattr(a, "cmd", None) or [])
    if cmd[:1] == ["--"]:
        cmd = cmd[1:]
    if not cmd:
        return die("launch needs a command to run", 2)
    app = getattr(a, "app", None) or os.path.basename(cmd[0])
    if not app or not cgroup.valid_rel(app) or "/" in app or len(app) > 32:
        return die("bad app name (use a-z 0-9 _ -, max 32)", 2)
    base = cgroup.base()
    if not os.path.isdir(base):
        return die(
            "%s missing; is the taema service running and are you in the taema group? (sv status taema)"
            % base
        )
    if getattr(a, "dry_run", False):
        print("dry run: reserve app-%s and attach %s" % (app, " ".join(cmd)))
        return 0
    unit = getattr(a, "unit", None) or None
    owner = os.getpid() if getattr(a, "bind", False) else None
    session = agent_mod.session_key()
    request = {
        "cmd": "launch_prepare",
        "app": app,
        "pid": os.getpid(),
        "session": session,
    }
    if unit is not None:
        request["unit"] = unit
    if owner is not None:
        request["owner"] = owner
    reply = ask(cfg, request)
    if reply is None:
        return _launch_offline(cfg, app, cmd)
    if "error" in reply:
        return die("launch failed: %s" % reply["error"])
    scope = reply.get("scope", "")
    if reply.get("via") == "agent":
        attached = ask(cfg, {"cmd": "attach", "scope": scope, "pids": [os.getpid()]})
        if not (attached and attached.get("ok")):
            ask(cfg, {"cmd": "launch_release", "scope": scope})
            return die(
                "attach failed: %s"
                % (attached or {}).get("error", "daemon did not attach")
            )
    else:
        try:
            engine.helper_move(cfg, scope, [os.getpid()])
        except engine.Refused as e:
            ask(cfg, {"cmd": "launch_release", "scope": scope})
            return die("attach failed: %s" % e)
    claim = ask(
        cfg,
        {
            "cmd": "launch_claim",
            "scope": scope,
            "pid": os.getpid(),
            "app": app,
        },
    )
    if not (claim and claim.get("ok")):
        ask(cfg, {"cmd": "launch_release", "scope": scope})
        return die(
            "launch failed: %s" % (claim or {}).get("error", "claim was refused")
        )
    os.execvp(cmd[0], cmd)


def _launch_offline(cfg, app, cmd):
    """Without a daemon there is no reservation: scope the leaf directly, unmanaged."""
    leaf = "%s/app-%s" % (cgroup.base(), app)
    try:
        os.makedirs(leaf, exist_ok=True)
        engine.helper_move(cfg, "app-" + app, [os.getpid()])
    except (OSError, engine.Refused) as e:
        return die("attach failed: %s" % e)
    print(
        "taema: daemon not running; app-%s is not auto-managed" % app,
        file=sys.stderr,
    )
    os.execvp(cmd[0], cmd)


# ---- desktop ------------------------------------------------------------------------------


def cmd_desktop(a):
    """Desktop entry wrapping tools."""
    del a
    print("usage: taema desktop <wrap|unwrap|list>")
    return 2


def cmd_desktop_wrap(a):
    cfg, _store, _units = _load(a)
    if cfg.get("experimental", {}).get("launch_wrap") is not True:
        return die(
            "desktop wrapping needs [experimental] launch_wrap = true",
            hint="set launch_wrap in taema.toml to wrap launcher entries",
        )
    try:
        record = desktop.wrap(getattr(a, "name", None) or "")
    except desktop.DesktopError as e:
        return die(str(e))
    verb = "rewrapped" if record["updated"] else "wrapped"
    print(
        "%s %s -> %s (app %s)"
        % (
            verb,
            os.path.basename(record["file"]),
            record["source"],
            record["app"],
        )
    )
    return 0


def cmd_desktop_unwrap(a):
    _cfg, _store, _units = _load(a)
    if getattr(a, "all", False):
        removed = desktop.unwrap_all()
        for record in removed:
            print("removed %s" % record["file"])
        if not removed:
            print("no wrapped desktop entries")
            return 0
        print("removed %d wrappers" % len(removed))
        return 0
    name = getattr(a, "name", None)
    if not name:
        return die("unwrap needs NAME or --all", 2)
    try:
        record = desktop.unwrap(name)
    except desktop.DesktopError as e:
        return die(str(e))
    print("removed %s" % record["file"])
    return 0


def cmd_desktop_list(a):
    _cfg, _store, _units = _load(a)
    items = desktop.list_wraps()
    if not items:
        print("no wrapped desktop entries")
        return 0
    for item in items:
        print(
            "%s app=%s source=%s%s"
            % (
                os.path.basename(item["file"]),
                item["app"],
                item["source"],
                " DRIFTED" if item["drifted"] else "",
            )
        )
    return 0


# ---- bar ----------------------------------------------------------------------------------


def cmd_bar(a):
    from .. import events as event_views

    cfg, _store, _units = _load(a)
    format_name = getattr(a, "format", None) or "plain"
    if getattr(a, "json", False) or getattr(a, "jsonl", False):
        format_name = "json"
    if format_name not in bar.FORMATS:
        return die(
            "unknown bar format %r (use %s)" % (format_name, ", ".join(bar.FORMATS)),
            2,
        )
    reply = ask(cfg, {"cmd": "status"})
    if reply is None:
        print(bar.render(format_name, bar.error_model()))
        return 1
    model = bar.model_from_status(reply)
    print(bar.render(format_name, model))
    if not getattr(a, "follow", False):
        return 0
    last = model
    for result in subscribe(cfg, event_views.TOPICS, 1 << 60):
        if not isinstance(result, dict) or (
            "error" in result and "event" not in result
        ):
            print(bar.render(format_name, bar.error_model()))
            return 1
        if "event" not in result and "resync" not in result:
            continue
        reply = ask(cfg, {"cmd": "status"})
        if reply is None:
            print(bar.render(format_name, bar.error_model()))
            return 1
        model = bar.model_from_status(reply)
        if model != last:
            print(bar.render(format_name, model))
            last = model
    print(bar.render(format_name, bar.error_model()))
    return 1


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
    leaf_name = os.path.basename(path)
    unit = engine.unit_for_leaf(units, leaf_name)
    vetoes = engine.vetoes_for_scope(store, path, unit=unit)
    force_veto = bool(getattr(a, "force_veto", False))
    if vetoes and force_veto:
        if not _confirm_bulk(
            "override veto",
            [store.describe_veto(veto) for veto in vetoes],
            a,
        ):
            return 1
    veto = vetoes[0] if vetoes else None
    scope = cgroup.rel(path)
    facts = authorization.Facts(
        scope=scope,
        vetoed=veto_label(veto) if veto and not force_veto else "",
        veto_source=veto.get("source", "user") if veto else "",
        veto_target=veto_label(veto) if veto else "",
        unit_veto=(
            "kill.never_stop" if unit and unit.get("kill", {}).get("never_stop") else ""
        ),
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
                    event="unit_vetoed" if facts.unit_veto else "vetoed",
                    trigger=authorization.MANUAL_STOP,
                    scope=cgroup.rel(path),
                    target=facts.veto_target or facts.vetoed or dec.reason,
                    source=("unit" if facts.unit_veto else facts.veto_source or "user"),
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
                veto_override=bool(vetoes and force_veto),
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


def _memory_scope_sources(scope):
    """Summarize fallbacks and unavailable scope features for human reports."""
    features = scope.get("features", {})
    sources = []
    for feature in ("peak", "pressure"):
        source = features.get(feature, "unsupported")
        if source not in ("kernel", "cgroup"):
            sources.append("%s=%s" % (feature, source))
    for feature in ("accounting", "memory_stat", "swap", "zswap"):
        if features.get(feature) == "unsupported":
            sources.append("%s=unsupported" % feature)
    return ",".join(sources) or "-"


def _memory_peak_cache(store=None):
    peak_cache = {}
    if store is not None:
        for key, sample in store.latest_memory_samples().items():
            if sample.get("peak") is not None:
                peak_cache[key] = sample["peak"]
    return peak_cache


def _memory_snapshot(cfg=None, store=None, peak_cache=None, include_scopes=True):
    if not memory.enabled(cfg):
        return memory.snapshot(base=cgroup.base(), cfg=cfg)
    if peak_cache is None and include_scopes:
        peak_cache = _memory_peak_cache(store)
    return memory.snapshot(
        base=cgroup.base(),
        cfg=cfg,
        peak_cache=peak_cache,
        include_scopes=include_scopes,
    )


def _memory_config(args):
    cfg = policy.load_config(path=getattr(args, "config", None))
    store = _status_store(cfg)
    return cfg, store


def _memory_human(report, pressure_only=False):
    if not report.get("enabled"):
        return "memory collection is disabled\n"
    host = report.get("host") or {}
    lines = ["host memory"]
    lines.append(
        "  total %s  available %s  pressure %s%%  swap %s / %s  zswap %s"
        % (
            _fmt_mem(host.get("total_bytes")),
            _fmt_mem(host.get("available_bytes")),
            _fmt_psi(host.get("pressure_avg10")),
            _fmt_mem(host.get("swap_used_bytes")),
            _fmt_mem(host.get("swap_total_bytes")),
            _fmt_mem(host.get("zswap_bytes")),
        )
    )
    lines.append(
        "  delegated current %s  zswap source %s"
        % (
            _fmt_mem(host.get("delegated_current_bytes")),
            host.get("zswap_source") or "unsupported",
        )
    )
    if report.get("features", {}).get("accounting") == "unsupported":
        lines.append("memory accounting: unsupported; no cgroup memory.current")
    rows = report.get("scopes", [])
    if pressure_only:
        rows = sorted(
            rows,
            key=lambda row: (
                row.get("psi_avg10") if row.get("psi_avg10") is not None else -1
            ),
            reverse=True,
        )
        lines.append("scope pressure (avg10)")
        for scope in rows:
            lines.append(
                "  %-28s %-10s %6s%% (%s)"
                % (
                    scope["name"],
                    scope["class"],
                    _fmt_psi(scope.get("psi_avg10")),
                    scope.get("psi_source") or "unsupported",
                )
            )
        return "\n".join(lines) + "\n"
    lines.append(
        "scope class current peak anon file swap zswap reclaimable PSI10 capabilities"
    )
    for scope in rows:
        lines.append(
            "%-28s %-9s %8s %8s %8s %8s %8s %8s %8s %6s%% %s"
            % (
                scope["name"],
                scope["class"],
                _fmt_mem(scope.get("current_bytes")),
                _fmt_mem(scope.get("peak_bytes")),
                _fmt_mem(scope.get("anon_bytes")),
                _fmt_mem(scope.get("file_bytes")),
                _fmt_mem(scope.get("swap_bytes")),
                _fmt_mem(scope.get("zswap_bytes")),
                _fmt_mem(scope.get("reclaimable_bytes")),
                _fmt_psi(scope.get("psi_avg10")),
                _memory_scope_sources(scope),
            )
        )
    if not rows:
        lines.append("no active scopes")
    return "\n".join(lines) + "\n"


def _emit_memory(report, args, human=None):
    if getattr(args, "json", False):
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    elif getattr(args, "jsonl", False):
        for record in _memory_jsonl_records(report):
            print(json.dumps(record, ensure_ascii=False, sort_keys=True))
    else:
        print(human if human is not None else _memory_human(report), end="")


def _memory_jsonl_records(report):
    if not report.get("enabled"):
        return [report]
    return [
        {
            "schema": "taema.memory-host.v1",
            "sampled_at": report["sampled_at"],
            "host": report["host"],
            "features": report["features"],
        }
    ] + [
        {"schema": "taema.memory-scope.v1", "scope": scope}
        for scope in report.get("scopes", [])
    ]


def cmd_memory(a):
    cfg, store = _memory_config(a)
    report = _memory_snapshot(cfg, store)
    _emit_memory(report, a)
    return 0


def cmd_memory_top(a):
    limit = getattr(a, "limit", 10)
    if limit <= 0:
        return die("--limit must be positive")
    cfg, store = _memory_config(a)
    report = _memory_snapshot(cfg, store)
    report["scopes"] = sorted(
        report.get("scopes", []),
        key=lambda row: row.get("current_bytes") or 0,
        reverse=True,
    )[:limit]
    _emit_memory(report, a)
    return 0


def cmd_memory_pressure(a):
    cfg, store = _memory_config(a)
    report = _memory_snapshot(cfg, store)
    _emit_memory(report, a, _memory_human(report, pressure_only=True))
    return 0


def cmd_memory_reclaim(a):
    """Ask the daemon to reclaim bounded page cache from one managed scope."""
    cfg, store, units = _load(a)
    name = getattr(a, "name", None)
    path = cgroup.resolve(name) if isinstance(name, str) else None
    if path is None:
        return die("scope %s not found" % (name or ""), 2)
    force_veto = getattr(a, "force_veto", False) is True
    unit = engine.unit_for_leaf(units, os.path.basename(path))
    vetoes = engine.vetoes_for_scope(store, path, unit=unit) if force_veto else []
    if vetoes and not _confirm_bulk(
        "override veto", [store.describe_veto(veto) for veto in vetoes], a
    ):
        return 1
    reply = ask(
        cfg,
        {
            "cmd": "reclaim",
            "scope": cgroup.rel(path),
            "force_veto": force_veto,
            "dry_run": getattr(a, "dry_run", False) is True,
        },
        timeout=60,
    )
    if reply is None:
        return die("daemon is not running; reclaim requires live safety checks", 3)
    if not isinstance(reply, dict):
        return die("daemon returned an invalid reclaim reply", 3)
    status = reply.get("status")
    if status in ("failed", "skipped"):
        reason = str(reply.get("reason", reply.get("error", "reclaim was refused")))
        code = (
            4
            if any(
                word in reason.lower()
                for word in ("veto", "held", "protected", "daemon", "dependency")
            )
            else 1
        )
        if getattr(a, "json", False):
            print(json.dumps({"schema": "taema.memory-reclaim.v1", **reply}, indent=2))
            return code
        return die(str(reason), code)
    if getattr(a, "json", False):
        print(json.dumps({"schema": "taema.memory-reclaim.v1", **reply}, indent=2))
        return 0
    if status == "would":
        print(
            "would reclaim %s from %s (anon %s; swap +%s; zswap +%s)"
            % (
                _fmt_mem(reply.get("requested_bytes")),
                reply.get("scope", name),
                _fmt_mem(reply.get("anonymous_requested_bytes")),
                _fmt_mem(reply.get("swap_delta_bytes")),
                _fmt_mem(reply.get("zswap_delta_bytes")),
            )
        )
        return 0
    print(
        "reclaim requested %s from %s (%s; observed %s; swap +%s; zswap +%s)"
        % (
            _fmt_mem(reply.get("requested_bytes")),
            reply.get("scope", name),
            reply.get("method", "unknown method"),
            _fmt_mem(reply.get("reclaimed_bytes")),
            _fmt_mem(reply.get("swap_delta_bytes")),
            _fmt_mem(reply.get("zswap_delta_bytes")),
        )
    )
    if reply.get("error"):
        print("  partial reclaim: %s" % reply["error"])
    return 0


def cmd_memory_budget(a):
    """Show the daemon's current budget, classifications, and owned memory controls."""
    cfg, _store = _memory_config(a)
    reply = ask(cfg, {"cmd": "memory_budget"})
    if reply is None:
        return die(
            "daemon is not running; live memory budget state requires the daemon", 3
        )
    if not isinstance(reply, dict) or reply.get("schema") != "taema.memory-budget.v1":
        return die("daemon returned an invalid memory budget", 3)
    if getattr(a, "json", False) or getattr(a, "jsonl", False):
        print(
            json.dumps(
                reply,
                ensure_ascii=False,
                indent=not getattr(a, "jsonl", False),
                sort_keys=True,
            )
        )
        return 0
    if not reply.get("enabled"):
        print("memory management is disabled")
        return 0
    lines = [
        "memory budget (%s management)" % reply["manage"],
        "  ceiling %s  availability floor %s  allocatable %s  delegated max %s"
        % (
            _fmt_mem(reply.get("budget_bytes")),
            _fmt_mem(reply.get("floor_bytes")),
            _fmt_mem(reply.get("allocatable_bytes")),
            _fmt_mem(reply.get("delegated_max_bytes")),
        ),
        "scope class current share reservation high low max ownership",
    ]
    for scope in reply.get("scopes", []):
        lines.append(
            "%-28s %-14s %8s %8s %8s %8s %8s %8s %s"
            % (
                scope["name"],
                scope["class"],
                _fmt_mem(scope.get("current_bytes")),
                _fmt_mem(scope.get("share_bytes")),
                _fmt_mem(scope.get("reservation_bytes")),
                scope.get("high") or "-",
                scope.get("low") or "-",
                scope.get("max") or "-",
                "user-owned" if scope.get("owned") else "unavailable",
            )
        )
    if not reply.get("scopes"):
        lines.append("no managed scopes")
    print("\n".join(lines))
    return 0


def cmd_memory_watch(a):
    interval = getattr(a, "interval", 5.0)
    count = getattr(a, "count", None)
    if not _math.isfinite(interval) or interval <= 0:
        return die("--interval must be a finite positive number")
    if count is not None and count <= 0:
        return die("--count must be positive")
    cfg, store = _memory_config(a)
    if not memory.enabled(cfg):
        _emit_memory(_memory_snapshot(cfg, store), a)
        return 0
    peak_cache = _memory_peak_cache(store)
    if getattr(a, "json", False) and count is None:
        count = 1
    snapshots = []
    emitted = 0
    while count is None or emitted < count:
        report = _memory_snapshot(cfg, store, peak_cache=peak_cache)
        emitted += 1
        if getattr(a, "json", False):
            snapshots.append(report)
        elif getattr(a, "jsonl", False):
            _emit_memory(report, a)
        else:
            print(_memory_human(report), end="")
        if count is None or emitted < count:
            time.sleep(interval)
    if getattr(a, "json", False):
        print(
            json.dumps(
                {"schema": "taema.memory-watch.v1", "snapshots": snapshots},
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
        )
    return 0


def _deprioritized_scopes(store):
    if store is None:
        return set()
    states = store.data.get("qos_scopes", {})
    if not isinstance(states, dict):
        return set()
    return {
        scope
        for scope, state in states.items()
        if isinstance(scope, str)
        and isinstance(state, dict)
        and state.get("deprioritized") is True
    }


def _daemon_windows(cfg):
    """Window summary from the daemon; {} when it is away or silent."""
    try:
        reply = ask(cfg, {"cmd": "status"})
    except (OSError, ValueError):
        return {}
    if not isinstance(reply, dict):
        return {}
    windows = reply.get("windows")
    return windows if isinstance(windows, dict) else {}


def _walk(
    path,
    depth,
    out,
    memory_scopes=None,
    deprioritized_scopes=None,
    frozen_scopes=None,
    window_scopes=None,
):
    pids = cgroup.procs(path)
    comms = []
    for p in pids:
        c = inspect.comm(p)
        if c and c not in comms:
            comms.append(c)
    key = cgroup.rel(path)
    metrics = memory_scopes.get(key) if memory_scopes is not None else None
    if memory_scopes is None and memory.enabled():
        current = cgroup.memory_current(path)
        pressure = cgroup.memory_psi(path)
    else:
        current = metrics.get("current_bytes") if metrics else None
        pressure = metrics.get("psi_avg10") if metrics else None
    windows = (window_scopes or {}).get(key)
    out.append(
        {
            "depth": depth,
            "name": os.path.basename(path) if depth else cgroup.rel(path),
            "processes": len(pids),
            "memory_bytes": current,
            "psi_avg10": pressure,
            "memory": metrics,
            "commands": sorted(comms),
            "deprioritized": cgroup.rel(path) in (deprioritized_scopes or set()),
            "frozen": cgroup.rel(path) in (frozen_scopes or set()),
            "windows": (
                {
                    "count": windows.get("count", 0),
                    "focused": bool(windows.get("focused")),
                }
                if isinstance(windows, dict)
                else None
            ),
        }
    )
    for d in sorted(cgroup.subdirs(path)):
        _walk(
            d,
            depth + 1,
            out,
            memory_scopes,
            deprioritized_scopes,
            frozen_scopes,
            window_scopes,
        )


def _count_scopes(base):
    pending = list(cgroup.subdirs(base))
    count_scopes = 0
    while pending:
        path = pending.pop()
        count_scopes += 1
        pending.extend(cgroup.subdirs(path))
    return count_scopes


def _ls_rows(cfg, store):
    """Scope rows shared by ls and dash; (None, memory) when unavailable."""
    memory_view = _memory_snapshot(cfg, store)
    memory_scopes = {scope["name"]: scope for scope in memory_view.get("scopes", [])}
    deprioritized_scopes = _deprioritized_scopes(store)
    frozen_scopes = set((store.data.get("frozen_scopes", {}) if store else {}).keys())
    window_scopes = _daemon_windows(cfg).get("scopes", {})
    if not isinstance(window_scopes, dict):
        window_scopes = {}
    base = cgroup.base()
    if not os.path.isdir(base):
        return None, memory_view
    rows = []
    for d in sorted(cgroup.subdirs(base)):
        _walk(
            d,
            0,
            rows,
            memory_scopes,
            deprioritized_scopes,
            frozen_scopes,
            window_scopes,
        )
    return rows, memory_view


def cmd_ls(a):
    from . import view

    try:
        cfg, store, _units = _load(a)
    except (OSError, ValueError):
        cfg, store = None, None
    rows, memory_view = _ls_rows(cfg, store)
    if rows is None:
        model = view.snapshot("ls", scopes=(), memory=memory_view)
        view.emit(model, a, "scope tree unavailable: %s\n" % cgroup.base())
        return 3
    model = view.snapshot("ls", scopes=rows, memory=memory_view)
    records = [view.record("scope", row) for row in rows]
    if getattr(a, "jsonl", False):
        records.insert(0, memory_view)
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
            "desktop_id": getattr(live, "desktop_id", None) or "",
        }
    persisted = store.app_identity(key) or {}
    invalid = policy.bad_owner(key, policy.owner_deny(cfg))
    return {
        "key": key,
        "display": persisted.get("display") or key,
        "kind": persisted.get("kind") or key.split(":", 1)[0],
        "validated": invalid is None,
        "reason": invalid or "",
        "desktop_id": persisted.get("desktop_id") or "",
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
        "scope": {
            "name": target_scope or "",
            "live": bool(scope_live),
            "deprioritized": target_scope in _deprioritized_scopes(store),
            "frozen": target_scope
            in (store.data.get("frozen_scopes", {}) if store else {}),
        },
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
            launch_apps = store.data.get("launch_apps") if store else None
            launch = launch_apps.get(scope) if isinstance(launch_apps, dict) else None
            if not isinstance(launch, dict):
                launch = None
            launch_key = members[0]["apps"][0] if launch and members else None
            explanation = _why_report(
                cfg,
                store,
                key=launch_key,
                target_scope=scope,
                scope_live=True,
                members=members,
                provenance=(
                    store.latest_app_instance(launch_key)
                    if launch_key and store
                    else None
                ),
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
            if launch and explanation.get("identity") is not None:
                explanation["identity"]["desktop_id"] = (
                    explanation["identity"].get("desktop_id") or launch.get("app") or ""
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
            if store is not None:
                # Same bridge as the app-key branch below: the launch
                # record lives under the scope while a pid resolves to
                # its executable identity.
                launch_apps = store.data.get("launch_apps")
                if isinstance(launch_apps, dict):
                    leaf = scope.rsplit("/", 1)[-1] if scope else ""
                    for candidate in (scope, leaf):
                        launch = launch_apps.get(candidate) if candidate else None
                        if isinstance(launch, dict) and launch.get("launched_by"):
                            provenance["launched_by"] = launch["launched_by"]
                            break
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
            if not persisted.get("launched_by") and store is not None:
                # The launch record lives under the app name while a pid
                # resolves to its executable identity; bridge the two so
                # `why PID` shows how a launched app arrived (as scope
                # explanations already do via launch_apps).
                launch_apps = store.data.get("launch_apps")
                if isinstance(launch_apps, dict):
                    leaf = scope.rsplit("/", 1)[-1] if scope else ""
                    for candidate in (scope, leaf):
                        launch = launch_apps.get(candidate) if candidate else None
                        if isinstance(launch, dict) and launch.get("launched_by"):
                            persisted = dict(
                                persisted, launched_by=launch["launched_by"]
                            )
                            break
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


def cmd_mute(a):
    cfg, store, _units = _load(a)
    app = getattr(a, "app", None)
    if not app:
        muted = sorted(store.data.get("muted_apps", []))
        if not muted:
            print("no muted apps")
        else:
            print("muted: %s" % ", ".join(muted))
        return 0
    how, reply = feedback_action(cfg, store, "mute", app=app, muted=True)
    if not reply or reply.get("error") or not reply.get("ok", True):
        return die((reply or {}).get("error", "could not mute %s" % app))
    print("%s: muted (%s)" % (app, how))
    return 0


def cmd_unmute(a):
    cfg, store, _units = _load(a)
    app = getattr(a, "app", None)
    if not app:
        return die("unmute requires an app", 2)
    how, reply = feedback_action(cfg, store, "mute", app=app, muted=False)
    if not reply or reply.get("error") or not reply.get("ok", True):
        return die((reply or {}).get("error", "could not unmute %s" % app))
    print("%s: unmuted (%s)" % (app, how))
    return 0


def cmd_do_not_kill(a):
    cfg, store, units = _load(a)
    if (
        getattr(a, "all", False)
        and not a.target
        and not any(
            getattr(a, name, None) is not None
            for name in (
                "scope",
                "pid",
                "pair",
                "signature",
                "app",
                "owner",
                "unit",
                "cgroup",
                "path",
            )
        )
    ):
        return die("--all requires an explicit target", 2)
    try:
        if a.target or any(
            getattr(a, name, None) is not None
            for name in (
                "scope",
                "pid",
                "pair",
                "signature",
                "app",
                "owner",
                "unit",
                "cgroup",
                "path",
            )
        ):
            resolved = resolve_veto_targets(a, store, units)
        else:
            resolved = None
        if resolved is None:
            action = store.auto_action()
            if not action:
                return die("no automatic stop to veto", 2)
            apps = action.get("apps") or [
                pair[1]
                for pair in action.get("pairs", [])
                if isinstance(pair, list) and len(pair) == 2
            ]
            targets = (
                [
                    (
                        {"kind": "app", "value": app, "start": None},
                        ["automatic stop %s, app:%s" % (action["scope"], app)],
                    )
                    for app in dict.fromkeys(apps)
                ]
                if apps
                else [
                    (
                        {"kind": "scope", "value": action["scope"], "start": None},
                        ["automatic stop " + action["scope"]],
                    )
                ]
            )
        else:
            targets = resolved
        for_duration = getattr(a, "for_duration", None)
        until = getattr(a, "until", None)
        reason = getattr(a, "reason", None) or ""
        if for_duration is not None and until:
            return die("use either --for or --until, not both", 2)
        if len(reason) > 256:
            return die("--reason must be at most 256 characters", 2)
        expires = None
        if for_duration is not None:
            if for_duration <= 0:
                return die("--for must be greater than zero", 2)
            expires = time.time() + for_duration
        elif until:
            from .inputs import parse_time

            expires = parse_time(until).timestamp()
            if expires <= time.time():
                return die("--until must be in the future", 2)
    except ValueError as error:
        return die(str(error), 2)
    if getattr(a, "dry_run", False):
        for target, matched in targets:
            print(
                "dry run: veto %s (matched: %s)"
                % (veto_label(target), ", ".join(matched))
            )
        return 0
    if len(targets) > 1 and not _confirm_bulk(
        "veto", [veto_label(target) for target, _matched in targets], a
    ):
        return 1
    for target, matched in targets:
        fields = {"target": target}
        if expires is not None:
            fields["expires"] = expires
        if reason:
            fields["reason"] = reason
        how, reply = feedback_action(cfg, store, "veto", **fields)
        if not reply or not reply.get("ok"):
            return die((reply or {}).get("error", "could not add veto"))
        suffix = (
            "permanent"
            if expires is None
            else "expires %s"
            % time.strftime("%Y-%m-%d %H:%M:%S %Z", time.localtime(expires))
        )
        if reason:
            suffix += "; reason: " + reason
        print(
            "vetoed %s (matched: %s; %s; %s)"
            % (veto_label(target), ", ".join(matched), how, suffix)
        )
    return 0


def cmd_undo(a):
    cfg, store, _units = _load(a)
    decision = store.undo_candidate(getattr(a, "decision_id", None))
    if not decision:
        return die("no retained automatic action to undo", 2)
    target_id = decision["id"]
    kind = decision.get("kind", "automatic action")
    stop = kind in ("stop", "auto_stop")
    restore_requested = bool(getattr(a, "restore", False))
    if getattr(a, "dry_run", False):
        suffix = " and restore" if restore_requested else ""
        print("dry run: undo %s decision %s%s" % (kind, target_id, suffix))
        return 0
    if (
        restore_requested
        and stop
        and not (decision.get("argv") and decision.get("cwd"))
    ):
        how, reply = feedback_action(cfg, store, "undo", action_id=str(target_id))
        if not reply or not reply.get("ok"):
            return die((reply or {}).get("error", "could not undo automatic stop"))
        print(
            "undo: %s; restore unavailable because [learn].remember_argv was false when it stopped"
            % (decision.get("scope") or "automatic stop")
        )
        return 0

    if restore_requested and stop:
        how, reply = feedback_action(
            cfg,
            store,
            "undo",
            action_id=str(target_id),
            restore=True,
            queue_if_down=False,
            timeout=20.0,
        )
        if how == "offline":
            how, reply = feedback_action(cfg, store, "undo", action_id=str(target_id))
            if not reply or not reply.get("ok"):
                return die((reply or {}).get("error", "could not queue undo"))
            print(
                "undo: %s; restore deferred because the daemon is not running"
                % (decision.get("scope") or "automatic stop")
            )
            return 0
        if not reply or not reply.get("ok"):
            return die((reply or {}).get("error", "could not undo automatic stop"))
        if reply.get("error"):
            return die("undo completed, but restore failed: %s" % reply["error"], 1)
        if reply.get("restored"):
            print(
                "undo: %s; restored in %s (pid %s)"
                % (
                    decision.get("scope", "automatic stop"),
                    reply["scope"],
                    reply["pid"],
                )
            )
        else:
            print(
                "undo: %s; %s"
                % (
                    decision.get("scope", "automatic action"),
                    reply.get("restore_unavailable", "restore was not started"),
                )
            )
        return 0

    how, reply = feedback_action(
        cfg,
        store,
        "undo",
        action_id=str(target_id),
        queue_if_down=stop,
    )
    if not reply or not reply.get("ok"):
        return die((reply or {}).get("error", "could not undo automatic action"))
    targets = reply.get("targets", [])
    details = (
        "; vetoed %s"
        % (", ".join(veto_label(target) for target in targets) or "the stopped scope")
        if stop
        else ""
    )
    if restore_requested and not stop:
        details += "; restore applies only to a stopped process"
    print(
        "undo: %s%s (%s)" % (decision.get("scope") or "automatic action", details, how)
    )
    return 0


def cmd_restore(a):
    cfg, store, _units = _load(a)
    identifier = getattr(a, "decision_id", None)
    if not isinstance(identifier, str) or not identifier.isdecimal():
        return die("restore requires a numeric decision id", 2)
    decision = store.decision(int(identifier))
    if not decision or decision.get("kind") not in ("stop", "auto_stop"):
        return die("no retained stop decision matches %s" % identifier, 2)
    if not decision.get("argv") or not decision.get("cwd"):
        return die(
            "restore unavailable: [learn].remember_argv was false when the app stopped",
            2,
        )
    payload = decision.get("undo") or {}
    if payload.get("restored_at") is not None:
        return die("decision %s has already been restored" % identifier, 2)
    how, reply = feedback_action(
        cfg,
        store,
        "undo",
        action_id=identifier,
        restore=True,
        queue_if_down=False,
        timeout=20.0,
    )
    if how == "offline":
        return die("restore requires the taema daemon to be running", 2)
    if not reply or not reply.get("ok"):
        return die((reply or {}).get("error", "could not restore stopped app"))
    if reply.get("error"):
        return die(reply["error"], 1)
    if reply.get("restored"):
        print(
            "restored decision %s in %s (pid %s)"
            % (identifier, reply["scope"], reply["pid"])
        )
        return 0
    return die(reply.get("restore_unavailable", "restore was not started"), 2)


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
    if getattr(a, "all", False) and getattr(a, "veto", False):
        return die("--all cannot be combined with --veto", 2)
    if getattr(a, "veto", False):
        try:
            selected = resolve_veto_targets(a, store, units, removal=True)
        except ValueError as error:
            return die(str(error), 2)
        if not selected:
            return die("forget --veto requires a target", 2)
        if getattr(a, "dry_run", False):
            for target, matched in selected:
                print(
                    "dry run: remove veto for %s (matched: %s)"
                    % (veto_label(target), ", ".join(matched))
                )
            return 0
        if len(selected) > 1 and not _confirm_bulk(
            "remove veto", [veto_label(target) for target, _ in selected], a
        ):
            return 1
        active = store._active_vetoes()
        for target, matched in selected:
            existed = any(
                store._same_veto_target(veto, target, pid_wildcard=True)
                for veto in active
            )
            how, reply = feedback_action(cfg, store, "unveto", target=target)
            if not reply or not reply.get("ok"):
                return die((reply or {}).get("error", "could not remove veto"))
            removed = reply.get("removed", []) or existed
            phrase = "forgot veto" if removed else "no veto"
            print(
                "%s for %s (matched: %s; %s)"
                % (phrase, veto_label(target), ", ".join(matched), how)
            )
        return 0
    if not getattr(a, "exe", None):
        return die(
            "forget requires an executable; use --veto TARGET to remove a veto", 2
        )
    if getattr(a, "dry_run", False):
        action = (
            "forget all learned records for" if getattr(a, "all", False) else "forget"
        )
        print("dry run: %s %s" % (action, a.exe))
        return 0
    if getattr(a, "all", False):
        known = store.forget(a.exe, all_records=True)
        how, reply = feedback_action(cfg, store, "forget", key=a.exe, all=True)
        if not reply or not reply.get("ok"):
            return die((reply or {}).get("error", "could not forget learned records"))
        if known:
            print(
                "forgot all learned records for %s (%s); vetoes preserved"
                % (a.exe, how)
            )
        else:
            print("no learned records for %s (%s); vetoes preserved" % (a.exe, how))
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

    probed = _fast_status_probe(a)
    if probed is not None:
        cfg = {"mem": {"enabled": probed["mem_enabled"]}}
        store = None
        reply = probed
        client_config_error = None
    else:
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
    if store is None and probed is None:
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
            "guard": _pressure_guard.empty_status(),
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
            "mode": reply["mode"] if "mode" in reply else cfg["mode"],
            "authority": reply["authority"]
            if "authority" in reply
            else policy.effective_authority(cfg)["value"],
            "authority_source": reply["authority_source"]
            if "authority_source" in reply
            else policy.effective_authority(cfg)["source"],
            "profile": reply.get("profile", cfg.get("_profile_name", "auto")),
            "profile_reason": reply.get(
                "profile_reason",
                cfg.get("_profile_reason", "automatic profile selection"),
            ),
            "feedback_invalid": int(reply["feedback_invalid"]),
            "hold": reply["hold"] or "",
            "hold_state": reply["hold_state"],
            "guard": reply["guard"]
            if "guard" in reply
            else _pressure_guard.empty_status(),
            "config": list(reply["config"] if "config" in reply else cfg["_sources"]),
            "config_error": reply.get("config_error") or client_config_error,
            "details": reply,
        }
        result = 0
    want_json = bool(getattr(a, "json", False) or getattr(a, "jsonl", False))
    memory_view = _memory_snapshot(cfg, store, include_scopes=want_json)
    memory_scopes = {scope["name"]: scope for scope in memory_view.get("scopes", [])}
    deprioritized_scopes = _deprioritized_scopes(store)
    frozen_scopes = set((store.data.get("frozen_scopes", {}) if store else {}).keys())
    if reply is not None:
        frozen_scopes.update(
            item.get("scope")
            for item in reply.get("frozen_scopes", [])
            if isinstance(item, dict) and isinstance(item.get("scope"), str)
        )
    base = cgroup.base()
    if os.path.isdir(base):
        if getattr(a, "json", False) or getattr(a, "jsonl", False):
            scopes = []
            for path in sorted(cgroup.subdirs(base)):
                _walk(
                    path, 0, scopes, memory_scopes, deprioritized_scopes, frozen_scopes
                )
            scope_count = len(scopes)
        else:
            scopes = []
            scope_count = _count_scopes(base)
    else:
        scopes = []
        scope_count = 0
    model = view.snapshot(
        "status", status, scopes, scope_count=scope_count, memory=memory_view
    )
    records = [view.record("status", {"status": status})]
    if getattr(a, "jsonl", False):
        records.extend(_memory_jsonl_records(memory_view))
    records.extend(view.record("scope", row) for row in scopes)
    view.emit(
        model,
        a,
        view.render_status(model, a, summary=bool(getattr(a, "_summary", False))),
        records,
    )
    if (
        result in (0, 3)
        and bool(getattr(a, "_summary", False))
        and not (getattr(a, "json", False) or getattr(a, "jsonl", False))
    ):
        from .. import suggest as suggest_mod

        reader = store
        if reader is None:
            try:
                reader = _status_store(policy.load_config())
            except Exception:
                reader = None
        try:
            trailer = suggest_mod.trailing(reader, cfg, 1) if reader is not None else []
        except Exception:
            trailer = []
        for line in trailer:
            print(line)
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
    if getattr(a, "fix", False):
        fixes = doctor.repair(
            cfg,
            store,
            sudo=getattr(a, "sudo", False),
        )
        repair_report = {
            "schema": "taema.doctor.repair.v1",
            "status": "fail"
            if any(item["status"] in ("fail", "needs-root") for item in fixes)
            else "ok",
            "fixes": fixes,
        }
        view.emit(repair_report, a, doctor.render_repair(fixes))
        if repair_report["status"] == "fail":
            return 1
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
    from ..model import authorization

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


def dash_snapshot(a):
    """View-model snapshot shared by dash --once, --json, and the live screen."""
    from . import view
    from .. import events as event_views

    cfg, store, _units = _load(a)
    rows, memory_view = _ls_rows(cfg, store)
    budget = ask(cfg, {"cmd": "memory_budget"})
    if not isinstance(budget, dict) or budget.get("schema") != "taema.memory-budget.v1":
        budget = None
    alive = ask(cfg, {"cmd": "status"}) is not None
    recent = store.events_since(0, limit=1000)["events"][-10:]
    events = []
    for event in recent:
        record = event_views.view_event(event)
        record["scope"] = event.get("scope", "")
        record["why"] = event.get("why", "")
        events.append(record)
    model = view.snapshot("dash", scopes=rows or [], memory=memory_view)
    model["learned"] = {
        "apps": store.apps_summary(limit=10),
        "pairs": store.pairs_summary(limit=10),
        "signatures": store.signatures_summary(limit=10),
    }
    model["budget"] = budget
    model["events"] = events
    model["reviews"] = store.open_reviews()
    model["daemon"] = "ok" if alive else "unavailable"
    return model


def cmd_dash(a):
    """Show the terminal dashboard, or its snapshot with --once/--json."""
    from . import dash as dash_ui
    from . import view

    if (
        not getattr(a, "once", False)
        and not getattr(a, "json", False)
        and not getattr(a, "jsonl", False)
    ):
        try:
            import curses
        except ImportError:
            curses = None
        return dash_ui.main(a, curses_module=curses)
    model = dash_snapshot(a)
    if getattr(a, "once", False):
        print(view.render_dash(model, a), end="")
        return 0
    view.emit(model, a, view.render_dash(model, a))
    return 0


def cmd_prompt(a):
    """Print the cached prompt segment without connecting to the daemon."""
    from . import framework

    return framework._fast_prompt()


def cmd_learn_export(a):
    """Write learned answers in the versioned format, or legacy 0.2 JSON."""
    import tempfile

    _cfg, store, _units = _load(a)
    if getattr(a, "format", "learn-v1") == "v2":
        if getattr(a, "redact", False):
            return die("--redact needs --format learn-v1", 2)
        payload = json.dumps(store.export_legacy(), indent=2, sort_keys=True) + "\n"
    else:
        payload = (
            json.dumps(
                transfer.export_learn(store, redacted=getattr(a, "redact", False)),
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )
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


def _read_learn_document(path):
    """Read and validate a learn export file. Returns (document, error)."""
    try:
        size = os.path.getsize(path)
    except OSError as error:
        return None, "could not read import: %s" % error
    if size > transfer.MAX_IMPORT_BYTES:
        return None, "import is larger than 4 MiB; move state with backup instead"
    try:
        with open(path, encoding="utf-8") as stream:
            document = json.load(stream)
    except (OSError, ValueError) as error:
        return None, "could not parse import: %s" % error
    problem = transfer.validate_learn_document(document)
    if problem is not None:
        return None, "invalid import: %s" % problem
    return document, None


def _writable_store(cfg):
    return knowledge.Store(
        policy.state_dir(cfg),
        cfg.get("seeds"),
        read_only=False,
        deny=policy.owner_deny(cfg),
        mode=cfg.get("mode", "observe"),
        learn=cfg.get("learn"),
    )


def cmd_learn_import(a):
    """Import learned answers from a versioned export file."""
    if getattr(a, "merge", False) and getattr(a, "replace", False):
        return die("--merge cannot be combined with --replace", 2)
    mode = "replace" if getattr(a, "replace", False) else "merge"
    document, error = _read_learn_document(os.path.abspath(os.path.expanduser(a.file)))
    if error is not None:
        return die(error, 2)
    cfg, store, _units = _load(a)
    rows = transfer.import_diff(store, document, mode=mode)
    if not rows:
        print("import: nothing to change")
        return 0
    if not _confirm_bulk("import learning", rows, a):
        return 1
    how, reply = feedback_action(
        cfg, store, "import_learning", queue_if_down=False, mode=mode, document=document
    )
    if how == "offline":
        writer = _writable_store(cfg)
        summary = writer.import_learning_document(document, mode=mode)
        writer.save()
        how = "direct"
        reply = {"ok": True, **(summary or {})}
    if not reply or not reply.get("ok"):
        return die((reply or {}).get("error", "could not import learning"))
    print(
        "imported learning via %s: %d pairs added, %d updated, %d skipped"
        % (
            how,
            reply.get("pairs_added", 0),
            reply.get("pairs_updated", 0),
            reply.get("pairs_skipped", 0),
        )
    )
    return 0


def _parse_since(value):
    """Epoch float or relative Nd/Nh/Nm/Ns. Returns (timestamp, error)."""
    import re

    if value is None:
        return 0, None
    try:
        return float(value), None
    except (TypeError, ValueError):
        pass
    match = re.fullmatch(r"(\d+)([smhd])", str(value).strip())
    if not match:
        return None, "--since takes an epoch timestamp or a relative Ns/Nm/Nh/Nd"
    amount, unit = int(match.group(1)), match.group(2)
    span = {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]
    return time.time() - amount * span, None


def _history_entries(timeline):
    entries = []
    for decision in timeline["decisions"]:
        entries.append(
            {
                "ts": decision.get("ts") or 0,
                "kind": decision.get("kind") or "unknown",
                "decision_id": decision.get("id"),
                "scope": decision.get("scope"),
                "owner": decision.get("owner"),
                "detail": (decision.get("why") or "").splitlines()[0]
                if decision.get("why")
                else "",
            }
        )
    for event in timeline["events"]:
        try:
            data = json.loads(event.get("data") or "{}")
        except ValueError:
            data = {}
        if not isinstance(data, dict):
            data = {}
        entries.append(
            {
                "ts": event.get("ts") or 0,
                "kind": event.get("event") or "unknown",
                "decision_id": event.get("decision_id"),
                "scope": data.get("scope"),
                "owner": data.get("owner"),
                "detail": str(data.get("why") or data.get("reason") or ""),
            }
        )
    for launch in timeline["launches"]:
        entries.append(
            {
                "ts": launch.get("born") or 0,
                "kind": "launch",
                "decision_id": None,
                "scope": launch.get("scope"),
                "owner": launch.get("app"),
                "detail": "pid %s" % launch.get("pid"),
            }
        )
    entries.sort(key=lambda entry: (entry["ts"], str(entry["kind"])))
    return entries


def cmd_history(a):
    """Show the timeline of one app or scope."""
    target = a.target
    if target.startswith("scope:"):
        owner, scope = None, target[len("scope:") :]
    elif target.startswith("app:"):
        owner, scope = target[len("app:") :], None
    elif not target:
        return die("history needs an APP or SCOPE target", 2)
    else:
        owner, scope = target, target
    since, error = _parse_since(getattr(a, "since", None))
    if error is not None:
        return die(error, 2)
    cfg, store = _load_events(a)
    del cfg
    entries = _history_entries(
        store.db.history_timeline(owner=owner, scope=scope, since=since)
    )
    if getattr(a, "json", False):
        from . import view

        print(
            json.dumps(
                view.record("history", {"target": target, "entries": entries}),
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    for entry in entries:
        line = "%s %s" % (
            _datetime.fromtimestamp(entry["ts"]).strftime("%Y-%m-%d %H:%M:%S"),
            entry["kind"],
        )
        if entry["decision_id"] is not None:
            line += " #%s" % entry["decision_id"]
        for key in ("scope", "owner"):
            if entry[key]:
                line += " %s=%s" % (key, entry[key])
        if entry["detail"]:
            line += " %s" % " ".join(entry["detail"].split())
        print(line)
    return 0


def _top_scope(pid, base):
    try:
        rel = cgroup.proc_cgroup(pid)
    except OSError:
        return "?"
    if not rel:
        return "(outside)"
    if base != "/" and not rel.startswith(base.lstrip("/")):
        return "(outside)"
    return os.path.basename(rel.rstrip("/")) or "(outside)"


def _scope_psi_avg10(pid, cache):
    """Memory PSI avg10 of the pid's scope cgroup, cached per scope path."""
    rel = cgroup.proc_cgroup(pid)
    if not rel:
        return None
    if rel in cache:
        return cache[rel]
    root = os.environ.get("TAEMA_CGROOT", "/sys/fs/cgroup")
    value = None
    try:
        with open(
            os.path.join(root, rel.lstrip("/"), "memory.pressure"),
            encoding="ascii",
        ) as source:
            for line in source:
                fields = line.split()
                if len(fields) >= 2 and fields[0] == "some":
                    for field in fields[1:]:
                        if field.startswith("avg10="):
                            value = float(field[6:])
                            break
    except (OSError, ValueError):
        value = None
    cache[rel] = value
    return value


def _top_details(pids, windows=None, decisions=None):
    window_pids = windows if isinstance(windows, dict) else {}
    decisions = decisions if isinstance(decisions, dict) else {}
    psi_cache = {}
    try:
        base = cgroup.base()
    except OSError:
        base = "/"
    details = {}
    for pid in pids:
        try:
            cmd = inspect.cmdline(pid) or "[%s]" % inspect.comm(pid)
            marker = window_pids.get(str(pid))
            scope = _top_scope(pid, base)
            details[pid] = {
                "scope": scope,
                "psi": _scope_psi_avg10(pid, psi_cache),
                "decision": decisions.get(scope, ""),
                "user": inspect.username(inspect.uid_of(pid)),
                "mem": inspect.rss_bytes(pid) or 0,
                "threads": inspect.thread_count(pid) or 0,
                "cmd": " ".join(cmd.split()),
                "window": (
                    "F"
                    if isinstance(marker, dict) and marker.get("focused")
                    else "w"
                    if marker is not None
                    else ""
                ),
            }
        except OSError:
            continue
    details["__total__"] = inspect.mem_total_bytes() or 0
    return details


def _top_tick_hz():
    try:
        return os.sysconf("SC_CLK_TCK")
    except (AttributeError, ValueError, OSError):
        return 100


def _stdin_has_key():
    import select

    try:
        ready, _, _ = select.select([sys.stdin], [], [], 0)
    except (OSError, ValueError):
        return False
    return bool(ready)


def cmd_top(a):
    """Live process table sorted by CPU, then memory, then PID."""
    from . import view

    try:
        interval = float(getattr(a, "interval", 1.0) or 1.0)
    except (TypeError, ValueError):
        return die("--interval must be a number of seconds", 2)
    if interval <= 0:
        return die("--interval must be positive", 2)
    count = getattr(a, "count", None)
    if count is not None:
        try:
            count = int(count)
        except (TypeError, ValueError):
            return die("top count must be an integer", 2)
        if count <= 0:
            return die("top count must be positive", 2)
    sort_name = (getattr(a, "sort", None) or "cpu").lower()
    if sort_name not in ("cpu", "mem", "delta", "psi", "scope", "pid"):
        return die("top --sort must be cpu, mem, delta, psi, scope, or pid", 2)
    if getattr(a, "once", False):
        count = 1
    as_json = bool(getattr(a, "json", False) or getattr(a, "jsonl", False))
    try:
        live_stdin = bool(sys.stdin.isatty())
    except (AttributeError, OSError, ValueError):
        live_stdin = False
    hz = _top_tick_hz()
    previous = inspect.ProcTable.scan()
    time.sleep(interval)
    frames = 0
    first = True
    cfg, store, _units = _load(a)
    window_pids = _daemon_windows(cfg).get("pids", {})
    previous_details = None
    while True:
        current = inspect.ProcTable.scan()
        details = _top_details(
            current.rows,
            windows=window_pids,
            decisions=_scope_decisions(store),
        )
        model = view.top_model(
            previous.rows,
            current.rows,
            interval,
            hz,
            details,
            previous_details,
            sort=sort_name,
        )
        previous = current
        previous_details = details
        frames += 1
        if as_json:
            view.emit(view.record("top", {"rows": model}), a, view.render_top(model, a))
            return 0
        a._width = view.terminal_width(a)
        if live_stdin and not first:
            sys.stdout.write("\033[H\033[J")
        sys.stdout.write(view.render_top(model, a))
        sys.stdout.flush()
        first = False
        if count is not None:
            if frames >= count:
                return 0
            time.sleep(interval)
            continue
        if not live_stdin:
            return 0
        time.sleep(interval)
        if _stdin_has_key():
            try:
                sys.stdin.readline()
            except (OSError, ValueError):
                pass
            return 0


def _tree_scope(pid, base):
    try:
        rel = cgroup.proc_cgroup(pid)
    except OSError:
        return "(outside)"
    if not rel:
        return "(outside)"
    if base != "/" and not rel.startswith(base.lstrip("/")):
        return "(outside)"
    return rel.rstrip("/") or "(outside)"


def _scope_decisions(store):
    """Latest decision kind per scope leaf, for the top table."""
    out = {}
    if store is None:
        return out
    try:
        rows = store.db.decisions(limit=200)
    except Exception:
        return out
    for row in rows:
        scope = row.get("scope") or ""
        leaf = os.path.basename(scope.rstrip("/"))
        if leaf and leaf not in out:
            out[leaf] = row.get("kind", "")
    return out


def _tree_edges(table, base):
    """Scope -> [(peer scope leaf, detail)] dependency edges between scopes."""
    groups = {}
    for pid in table.rows:
        groups.setdefault(_tree_scope(pid, base), set()).add(pid)
    try:
        snap = inspect.Snapshot()
    except Exception:
        return {}
    out = {}
    for scope, members in groups.items():
        try:
            found = inspect.edges(members, snap)
        except Exception:
            continue
        lines = set()
        for member, member_edges in found.items():
            for edge in member_edges:
                for peer in edge.get("peers", []):
                    peer_scope = _tree_scope(peer, base)
                    if peer_scope == scope:
                        continue
                    lines.add(
                        (
                            os.path.basename(peer_scope.rstrip("/")) or peer_scope,
                            edge.get("detail", edge.get("kind", "")),
                        )
                    )
        if lines:
            out[scope] = sorted(lines)
    return out


def cmd_tree(a):
    """Process trees grouped under scope headers."""
    from . import view

    try:
        base = cgroup.base()
    except OSError:
        base = "/"
    table = inspect.ProcTable.scan(include_zombies=True)
    cfg, _store, _units = _load(a)
    window_pids = _daemon_windows(cfg).get("pids", {})
    parents = {}
    scopes = {pid: _tree_scope(pid, base) for pid in table.rows}
    for pid, proc in table.rows.items():
        if proc.ppid and scopes.get(proc.ppid) != scopes[pid]:
            try:
                parents[proc.ppid] = inspect.comm(proc.ppid) or ""
            except OSError:
                continue
    parents = {pid: comm for pid, comm in parents.items() if comm}
    model = view.tree_model(
        table,
        lambda pid: _tree_scope(pid, base),
        windows=window_pids,
        target=getattr(a, "target", None),
        parents=parents,
        edges=_tree_edges(table, base),
    )
    if getattr(a, "json", False) or getattr(a, "jsonl", False):
        document = view.record(
            "tree",
            {
                "groups": [
                    {
                        "scope": scope,
                        "nodes": nodes,
                        "edges": [
                            {"peer": peer, "detail": detail}
                            for peer, detail in edge_lines
                        ],
                    }
                    for scope, nodes, edge_lines in model
                ]
            },
        )
        view.emit(document, a, view.render_tree(model, a))
        return 0
    a._width = view.terminal_width(a)
    sys.stdout.write(view.render_tree(model, a))
    return 0


def cmd_unit(a):
    """Unit authoring tools."""
    del a
    print("usage: taema unit <new|draft|test|dry-run|lint|list|enable|disable|install>")
    return 2


def _unit_cfg(args):
    return policy.load_config(path=getattr(args, "config", None))


def cmd_unit_list(a):
    """List units with their source and whether they are active."""
    cfg = _unit_cfg(a)
    for entry in policy.describe_units(cfg):
        print(
            "%s %s %s"
            % (entry["name"], entry["source"], "yes" if entry["active"] else "no")
        )
    return 0


def _unit_filename_for(cfg, name):
    """Map a unit name to its unit filename across all unit directories."""
    for directory in policy.units_dirs(cfg):
        if not os.path.isdir(directory):
            continue
        for filename in sorted(os.listdir(directory)):
            if not filename.endswith(".toml"):
                continue
            if filename[: -len(".toml")] == name:
                return filename
            unit, error = policy.read_unit_file(os.path.join(directory, filename))
            if error is None and unit.get("unit", {}).get("name") == name:
                return filename
    return None


def cmd_unit_disable(a):
    """Mask a unit with a user tombstone so the loader skips it."""
    cfg = _unit_cfg(a)
    filename = _unit_filename_for(cfg, a.name)
    if filename is None:
        return die("no such unit: %s" % a.name, 1)
    units_dir = os.path.join(policy.user_config_dir(), "units")
    os.makedirs(units_dir, exist_ok=True)
    tombstone = os.path.join(units_dir, filename + ".disabled")
    if os.path.exists(tombstone):
        print("already disabled: %s" % a.name)
        return 0
    with open(tombstone, "w", encoding="utf-8") as stream:
        stream.write("")
    print("disabled: %s" % a.name)
    return 0


def cmd_unit_enable(a):
    """Remove a user tombstone so the unit loads again."""
    cfg = _unit_cfg(a)
    filename = _unit_filename_for(cfg, a.name)
    tombstone = None
    if filename is not None:
        tombstone = os.path.join(
            policy.user_config_dir(), "units", filename + ".disabled"
        )
    else:
        orphan = os.path.join(
            policy.user_config_dir(), "units", a.name + ".toml.disabled"
        )
        if os.path.isfile(orphan):
            tombstone = orphan
    if tombstone is None:
        return die("no such unit: %s" % a.name, 1)
    if not os.path.isfile(tombstone):
        print("already enabled: %s" % a.name)
        return 0
    os.unlink(tombstone)
    print("enabled: %s" % a.name)
    return 0


def cmd_unit_install(a):
    """Install a curated pack to the user units directory."""
    source = policy.pack_source(a.name)
    if source is None:
        return die(
            "no such pack: %s (available: %s)"
            % (a.name, ", ".join(policy.available_packs())),
            2,
        )
    units_dir = os.path.join(policy.user_config_dir(), "units")
    ok, message, target = policy.install_pack_file(
        source, units_dir, a.name, force=getattr(a, "force", False)
    )
    if not ok:
        if os.path.exists(target):
            return die(message, 1)
        print(message)
        return 2
    print(target)
    return 0


def cmd_suggest(a):
    """List ranked improvement suggestions with ids."""
    from .. import suggest as suggest_mod

    cfg, store = _load_status(a)
    ranked = suggest_mod.rank(store, cfg)
    if not ranked:
        print("no suggestions.")
        return 0
    for item in ranked:
        print("%s [%s] %s" % (item["id"], item["kind"], item["title"]))
        print("  %s" % item["detail"])
    return 0


def cmd_suggest_apply(a):
    """Apply one suggestion by id after confirmation."""
    from .. import suggest as suggest_mod

    cfg, reader = _load_status(a)
    ranked = suggest_mod.rank(reader, cfg)
    match = next((item for item in ranked if item["id"] == a.identifier), None)
    if match is None:
        return die(
            "no such suggestion: %s" % a.identifier
            + (" (available: %s)" % ", ".join(item["id"] for item in ranked) if ranked else ""),
            2,
        )
    if not _confirm_bulk("apply suggestion", [match["title"]], a):
        return 1
    store = _writable_store(cfg)
    ok, message = suggest_mod.apply_suggestion(
        store,
        cfg,
        match,
        choice=getattr(a, "choice", None),
        force=getattr(a, "force", False),
    )
    if ok:
        store.save()
    print(message)
    return 0 if ok else 1


def _stdin_is_tty():
    try:
        return bool(sys.stdin.isatty())
    except (AttributeError, OSError, ValueError):
        return False


def _unit_target_pid(target):
    """Resolve a unit --from target (PID, scope:REL, or app comm) to a pid."""
    try:
        number = int(target)
    except (TypeError, ValueError):
        number = None
    if number is not None:
        return number
    if target.startswith("scope:") or "/" in target:
        rel = target[6:] if target.startswith("scope:") else target
        matches = []
        for pid in inspect.all_pids():
            try:
                pid_rel = cgroup.proc_cgroup(pid)
            except OSError:
                continue
            if pid_rel and (pid_rel == rel or pid_rel.endswith("/" + rel)):
                matches.append(pid)
        return min(matches) if matches else None
    for pid in sorted(inspect.all_pids()):
        try:
            if inspect.comm(pid) == target:
                return pid
        except OSError:
            continue
    return None


def _unit_name_for(identity, requested):
    if requested:
        return requested
    comm = (identity or {}).get("comm") or "app"
    slug = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in comm)
    return "app-" + slug.strip("-").lower() if slug.strip("-") else "app"


def cmd_unit_new(a):
    """Draft a unit from a running process, scope, or app; edit in a terminal."""
    pid = _unit_target_pid(a.from_target)
    if pid is None:
        return die("no such process, scope, or app: %s" % a.from_target, 2)
    identity, error = _process_identity(pid)
    if error is not None:
        return die(error, 2)
    if not identity["comm"]:
        return die("process has no comm; refusing to draft", 2)
    name = _unit_name_for(identity, getattr(a, "name", None))
    children = []
    try:
        table = inspect.ProcTable.scan()
        children = [
            inspect.comm(kid) or ""
            for kid, proc in table.rows.items()
            if proc.ppid == pid
        ]
    except OSError:
        children = []
    peak = None
    try:
        root = os.environ.get("TAEMA_CGROOT", "/sys/fs/cgroup")
        with open(
            os.path.join(root, identity["cgroup"].lstrip("/"), "memory.peak"),
            encoding="ascii",
        ) as source:
            peak = int(source.read().strip())
    except (OSError, ValueError):
        peak = None
    units_dir = os.path.join(policy.user_config_dir(), "units")
    os.makedirs(units_dir, exist_ok=True)
    target = os.path.join(units_dir, name + ".toml")
    if os.path.exists(target) and not getattr(a, "force", False):
        return die("unit file exists: %s (use --force to overwrite)" % target, 1)
    body = policy.draft_unit(
        name,
        comm=identity["comm"],
        exe=identity["exe"],
        cmdline=identity["cmdline"],
        cgroup=identity["cgroup"],
        children=children,
        peak_bytes=peak,
    )
    with open(target, "w", encoding="utf-8") as stream:
        stream.write(body)
    os.chmod(target, 0o600)
    print(target)
    editor = os.environ.get("EDITOR") or os.environ.get("VISUAL")
    if editor and _stdin_is_tty():
        import shlex
        import subprocess

        try:
            edited = subprocess.run(shlex.split(editor) + [target], check=False)
        except OSError as error:
            return die("could not run editor: %s" % error, 2)
        if edited.returncode != 0:
            return die("editor exited with %d" % edited.returncode, 2)
        unit, read_error = policy.read_unit_file(target)
        if read_error is not None:
            print(read_error)
            return 2
        problems = policy.validate_unit(unit)
        for problem in problems:
            print("%s: %s" % (target, problem))
        if problems:
            return 2
    return 0


def _resolve_unit_file(target):
    """Resolve a unit test target: a file path, or a unit name."""
    expanded = os.path.abspath(os.path.expanduser(target))
    if os.path.isfile(expanded):
        return expanded
    filename = target if target.endswith(".toml") else target + ".toml"
    for directory in (os.path.join(policy.user_config_dir(), "units"),):
        candidate = os.path.join(directory, filename)
        if os.path.isfile(candidate):
            return candidate
    return None


def cmd_unit_test(a):
    """Dry-run a unit file or name: matches, scopes, and ladder effects."""
    path = _resolve_unit_file(a.target)
    if path is None:
        return die("no such unit file or name: %s" % a.target, 2)
    unit, error = policy.read_unit_file(path)
    if error is not None:
        print(error)
        return 2
    problems = policy.validate_unit(unit)
    if problems:
        for problem in problems:
            print("%s: %s" % (path, problem))
        return 2
    match = unit.get("match", {})
    matched = []
    for pid in sorted(inspect.all_pids()):
        if engine.unit_matches(match, pid):
            matched.append(pid)
    for pid in matched:
        try:
            key = policy.app_key(pid, units=[unit])
            scope = engine.auto_scope_name(key, pid, inspect.starttime(pid))
        except (OSError, ValueError):
            scope = "?"
        print("%d %s scope %s" % (pid, inspect.comm(pid) or "?", scope))
    window = unit.get("window", {}) if isinstance(unit.get("window"), dict) else {}
    gc = unit.get("gc", {}) if isinstance(unit.get("gc"), dict) else {}
    mem = unit.get("mem", {}) if isinstance(unit.get("mem"), dict) else {}
    head = unit.get("unit", {}) if isinstance(unit.get("unit"), dict) else {}
    print(
        "gc: requires_window=%s stop_when_unneeded=%s keep_while_children=%s"
        % (
            window.get("requires_window", True),
            head.get("stop_when_unneeded", False),
            gc.get("keep_while_children", False),
        )
    )
    print(
        "mem: class=%s max=%s background=%s"
        % (mem.get("class", "app"), mem.get("max", "-"), mem.get("background", False))
    )
    print("qos: profile classes apply; no per-unit qos table")
    print("%d processes" % len(matched))
    return 0


def _process_identity(pid):
    try:
        number = int(pid)
    except (TypeError, ValueError):
        return None, "pid must be an integer"
    if number <= 0 or not os.path.isdir("/proc/%d" % number):
        return None, "no such process: %s" % pid
    return (
        {
            "comm": inspect.comm(number),
            "exe": inspect.exe(number),
            "cmdline": inspect.cmdline(number),
            "cgroup": cgroup.proc_cgroup(number),
        },
        None,
    )


def cmd_unit_draft(a):
    """Generate a unit file from a running process."""
    identity, error = _process_identity(a.from_pid)
    if error is not None:
        return die(error, 2)
    if not identity["comm"]:
        return die("process has no comm; refusing to draft", 2)
    units_dir = os.path.join(policy.user_config_dir(), "units")
    os.makedirs(units_dir, exist_ok=True)
    target = os.path.join(units_dir, a.name + ".toml")
    if os.path.exists(target) and not getattr(a, "force", False):
        return die("unit file exists: %s (use --force to overwrite)" % target, 1)
    body = policy.draft_unit(
        a.name,
        comm=identity["comm"],
        exe=identity["exe"],
        cmdline=identity["cmdline"],
        cgroup=identity["cgroup"],
    )
    with open(target, "w", encoding="utf-8") as stream:
        stream.write(body)
    os.chmod(target, 0o600)
    print(target)
    return 0


def _unit_peaks(a, unit):
    """Observed peak bytes for the unit's name from retained samples."""
    name = (unit.get("unit") or {}).get("name")
    if not isinstance(name, str) or not name:
        return {}
    try:
        _cfg, store, _units = _load(a)
        samples = store.latest_memory_samples() if store is not None else {}
    except Exception:
        return {}
    peaks = {}
    for scope_key, sample in (samples or {}).items():
        peak = sample.get("peak") if isinstance(sample, dict) else None
        if not isinstance(peak, (int, float)):
            continue
        leaf = os.path.basename(str(scope_key).rstrip("/"))
        if leaf == name or leaf.startswith(name + "-"):
            peaks[name] = max(peaks.get(name, 0), peak)
    return peaks


def cmd_unit_lint(a):
    """Lint one unit file."""
    unit, error = policy.read_unit_file(os.path.abspath(os.path.expanduser(a.file)))
    if error is not None:
        print(error)
        return 2
    problems = policy.validate_unit(unit, peaks=_unit_peaks(a, unit))
    for problem in problems:
        print("%s: %s" % (a.file, problem))
    return 2 if problems else 0


def cmd_setup(a):
    """Walk a new user from install to a working setup."""
    from .. import setup as setup_mod

    cfg, store = _load_status(a)
    report = setup_mod.run_setup(
        cfg,
        store,
        system_root="/",
        proc_root=None,
        yes=getattr(a, "yes", False),
    )
    for step in report["steps"]:
        print("%s: %s: %s" % (step["name"], step["status"], step["message"]))
    for path in report["wrote"]:
        print("wrote %s" % path)
    for command in report["root_commands"]:
        print("needs root: %s" % command)
    if any(step["status"] == "fail" for step in report["steps"]):
        return 1
    return 0


def cmd_unit_dry_run(a):
    """Show what a unit file would match, changing nothing."""
    unit, error = policy.read_unit_file(os.path.abspath(os.path.expanduser(a.file)))
    if error is not None:
        print(error)
        return 2
    problems = policy.validate_unit(unit)
    if problems:
        for problem in problems:
            print("%s: %s" % (a.file, problem))
        return 2
    match = unit.get("match", {})
    matched = []
    for pid in sorted(inspect.all_pids()):
        if engine.unit_matches(match, pid):
            matched.append((pid, inspect.comm(pid)))
    for pid, comm in matched:
        print("%d %s" % (pid, comm))
    print("%d processes" % len(matched))
    return 0


def cmd_report(a):
    """Summarize a day, week, or month of cleanup activity."""
    windows = [
        (name, span)
        for name, span in (("day", 86400), ("week", 7 * 86400), ("month", 30 * 86400))
        if getattr(a, name, False)
    ]
    if len(windows) != 1:
        return die("report needs exactly one of --day --week --month", 2)
    name, span = windows[0]
    end = time.time()
    cfg, store = _load_events(a)
    report = store.report_window(end - span, end)
    report["window"] = name
    if getattr(a, "json", False):
        from . import view

        print(json.dumps(view.record("report", report), indent=2, sort_keys=True))
        return 0
    memory = report["memory_freed_bytes"]
    print(
        "memory freed: %d bytes by stop, %d bytes by reclaim"
        % (memory["stop"], memory["reclaim"])
    )
    print(
        "stops: %d automatic, %d answered"
        % (report["stops"]["automatic"], report["stops"]["answered"])
    )
    print("undos: %d, regrets: %d" % (report["undos"], report["regrets"]))
    print(
        "reviews: %d answered, %d expired"
        % (report["reviews"]["answered"], report["reviews"]["expired"])
    )
    print("guard events: %d" % report["guard_events"]["total"])
    frozen = report["frozen"]
    print(
        "frozen: %d seconds, %d thaws (%d on connection), %d frozen now"
        % (
            frozen["frozen_seconds"],
            frozen["thaws"],
            frozen["connection_thaws"],
            frozen["frozen_now"],
        )
    )
    print("top leftover makers:")
    for row in report["top_leftovers"][:10]:
        print(
            "  %s launches=%d closes=%d kills=%d"
            % (row["leftover"], row["launches"], row["closes"], row["kills"])
        )
    from .. import suggest as suggest_mod

    try:
        trailer = suggest_mod.trailing(store, cfg, 3)
    except Exception:
        trailer = []
    for line in trailer:
        print(line)
    return 0


def cmd_recent(a):
    """List the latest automatic actions."""
    cfg, store = _load_events(a)
    del cfg
    actions = store.db.recent_auto_actions(limit=50)
    if getattr(a, "json", False):
        from . import view

        print(
            json.dumps(
                view.record("recent", {"actions": actions}),
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    for action in actions:
        line = "%s %s #%s freed=%d restore=%s" % (
            _datetime.fromtimestamp(action["ts"] or 0).strftime("%Y-%m-%d %H:%M:%S"),
            action["scope"],
            action["decision_id"],
            action["freed_bytes"],
            "yes" if action["restore_possible"] else "no",
        )
        if action["why"]:
            line += " %s" % " ".join(str(action["why"]).split())
        print(line)
    return 0


def cmd_restore_backup(a):
    """Restore state, config, and units from a backup tarball."""
    import tempfile

    tarball = os.path.abspath(os.path.expanduser(a.file))
    rows, error = transfer.restore_plan(tarball)
    if error is not None:
        return die(error, 2)
    if not rows:
        print("restore: backup holds nothing to restore")
        return 0
    if not _confirm_bulk("restore backup", rows, a):
        return 1
    cfg, store, _units = _load(a)
    with tempfile.TemporaryDirectory(prefix="taema-restore-") as staging:
        problem = transfer.stage_backup(tarball, staging)
        if problem is not None:
            return die(problem, 2)
        how, reply = feedback_action(
            cfg, store, "restore_backup", queue_if_down=False, staging=staging
        )
        if how == "offline":
            summary, apply_error = transfer.apply_staged_backup(
                staging, policy.state_dir(cfg)
            )
            if apply_error is not None:
                return die(apply_error, 1)
            how = "direct"
            reply = {"ok": True, **summary}
    if not reply or not reply.get("ok"):
        return die((reply or {}).get("error", "could not restore backup"))
    print("restored backup via %s" % how)
    return 0


def cmd_reset(a):
    """Clear learning, vetoes, history, or all state after a backup."""
    scopes = [
        name
        for name in ("learning", "vetoes", "history", "all")
        if getattr(a, name, False)
    ]
    if len(scopes) != 1:
        return die("reset needs exactly one of --learning --vetoes --history --all", 2)
    scope = scopes[0]
    cfg, store, _units = _load(a)
    rows = transfer.reset_plan(store, scope)
    if not _confirm_bulk("reset " + scope, rows, a):
        return 1
    try:
        backup_path = transfer.create_backup(cfg)
    except OSError as error:
        return die("could not write pre-reset backup: %s" % error)
    print("backup: %s" % backup_path)
    how, reply = feedback_action(
        cfg, store, "reset_scope", queue_if_down=False, scope=scope
    )
    if how == "offline":
        writer = _writable_store(cfg)
        summary = writer.reset_scope(scope)
        writer.save()
        how = "direct"
        reply = {"ok": True, **(summary or {})}
    if not reply or not reply.get("ok"):
        return die((reply or {}).get("error", "could not reset " + scope))
    print("reset %s via %s" % (scope, how))
    return 0


def cmd_backup(a):
    """Write a tarball with the database, user config, and user units."""
    cfg, _store, _units = _load(a)
    try:
        path = transfer.create_backup(cfg, target=getattr(a, "to", None))
    except OSError as error:
        return die("could not write backup: %s" % error)
    if getattr(a, "json", False):
        from . import view

        print(
            json.dumps(view.record("backup", {"path": path}), indent=2, sort_keys=True)
        )
        return 0
    print(path)
    return 0


def _learn_evidence_text(record):
    evidence = record.get("evidence") or {}
    return (
        ", ".join("%s=%s" % (name, evidence[name]) for name in sorted(evidence))
        or "none"
    )


def cmd_learn(a):
    """Show the read-only learning views shared with status and why."""
    from . import view

    _cfg, store, _units = _load(a)
    selected = getattr(a, "_command", "learn show").partition(" ")[2] or "show"
    if selected == "show" and getattr(a, "legacy", False):
        legacy = store.legacy_invalid_summary(limit=1000)
        records = legacy["records"]
        reviews = legacy["reviews"]
        human_lines = ["legacy-invalid pairs: %d" % len(records)]
        for pair in records:
            human_lines.append(
                "  %s -> %s  previous=%s  review=%s"
                % (
                    lineage.clean(pair["owner"], 30),
                    lineage.clean(pair["leftover"], 30),
                    pair.get("legacy_answer") or "none",
                    pair.get("review_id") or "none",
                )
            )
        human_lines.extend(
            "  review #%s owner=%s survivor=%s answer=%s"
            % (
                review.get("id", "?"),
                lineage.clean(review.get("owner", "?"), 30),
                lineage.clean(", ".join(review.get("survivors", [])), 30),
                review.get("answer", "?"),
            )
            for review in reviews
        )
        human = "\n".join(human_lines)
        fields = {
            "view": "show",
            "legacy": True,
            "records": records,
            "reviews": reviews,
            "count": len(records),
        }
    elif selected == "show":
        apps = store.apps_summary(limit=2000)
        pairs = store.pairs_summary(limit=1000)
        signatures = store.signatures_summary(limit=2000)

        def outcome_text(record):
            outcome = record.get("last_outcome") or {}
            if not outcome:
                return "none"
            decision = outcome.get("decision")
            label = outcome.get("outcome") or "unknown"
            return "%s (%s)" % (label, decision) if decision else label

        human_lines = [
            "apps: %d" % len(apps),
            "  app  decision  confidence  evidence  last outcome",
        ]
        for app in apps:
            human_lines.append(
                "  %s (%s)  %s  %.2f  %s  %s"
                % (
                    lineage.clean(app["display"], 32),
                    lineage.clean(app["key"], 32),
                    app["decision"],
                    app["confidence"],
                    _learn_evidence_text(app),
                    outcome_text(app),
                )
            )
        human_lines.extend(
            [
                "pairs: %d" % len(pairs),
                "  owner -> leftover  decision  confidence  evidence  last outcome",
            ]
        )
        for pair in pairs:
            human_lines.append(
                "  %s -> %s  %s  %.2f  %s  %s"
                % (
                    lineage.clean(pair["owner"], 32),
                    lineage.clean(pair["leftover"], 32),
                    pair.get("decision", pair.get("action", "ask")),
                    pair.get("confidence", 0.0),
                    _learn_evidence_text(pair),
                    outcome_text(pair),
                )
            )
        human_lines.extend(
            [
                "signatures: %d" % len(signatures),
                "  signature  owner  decision  confidence  evidence  last outcome",
            ]
        )
        for signature in signatures:
            human_lines.append(
                "  %s  %s  %s  %.2f  %s  %s"
                % (
                    lineage.clean(signature["id"], 32),
                    lineage.clean(signature["owner"], 32),
                    signature["decision"],
                    signature["confidence"],
                    _learn_evidence_text(signature),
                    outcome_text(signature),
                )
            )
        human = "\n".join(human_lines)
        fields = {
            "view": "show",
            "legacy": False,
            "apps": apps,
            "pairs": pairs,
            "signatures": signatures,
            "counts": {
                "apps": len(apps),
                "pairs": len(pairs),
                "signatures": len(signatures),
            },
        }
    elif selected == "apps":
        records = store.apps_summary(limit=2000)
        lines = [
            "%-28s %-8s %10s %-56s  %s"
            % (
                "app",
                "decision",
                "confidence",
                "evidence",
                "last outcome",
            )
        ]
        for app in records:
            last = app.get("last_outcome") or {}
            outcome = last.get("outcome") or "none"
            lines.append(
                "%-28s %-8s %10.2f %-56s  %s"
                % (
                    lineage.clean(app["display"], 28),
                    app["decision"],
                    app["confidence"],
                    _learn_evidence_text(app),
                    outcome,
                )
            )
        human = "\n".join(lines) if records else "apps: none learned yet"
    elif selected == "signatures":
        records = store.signatures_summary(limit=2000)
        lines = [
            "%-32s %-32s %-8s %10s %7s %7s %7s  %s"
            % (
                "signature",
                "owner",
                "decision",
                "confidence",
                "closes",
                "stop_ok",
                "respawn",
                "last outcome",
            )
        ]
        for signature in records:
            evidence = signature["evidence"]
            last = signature.get("last_outcome") or {}
            lines.append(
                "%-32s %-32s %-8s %10.2f %7d %7d %7d  %s"
                % (
                    lineage.clean(signature["id"], 32),
                    lineage.clean(signature["owner"], 32),
                    signature["decision"],
                    signature["confidence"],
                    evidence["closes"],
                    evidence["stop_ok"],
                    evidence["respawn"],
                    last.get("outcome") or "none",
                )
            )
        human = "\n".join(lines) if records else "signatures: none learned yet"
    elif selected == "pairs":
        records = store.pairs_summary(limit=1000)
        lines = [
            "%-22s %-22s %-10s %10s %7s %7s %7s  %s"
            % (
                "owner",
                "leftover",
                "decision",
                "confidence",
                "closes",
                "stop",
                "keep",
                "last outcome",
            )
        ]
        for pair in records:
            outcome = pair.get("last_outcome") or {}
            last = outcome.get("outcome") or "none"
            lines.append(
                "%-22s %-22s %-10s %10.2f %7d %7.2f %7.2f  %s"
                % (
                    lineage.clean(pair.get("owner", ""), 22),
                    lineage.clean(pair.get("leftover", ""), 22),
                    pair.get("decision", pair.get("action", "ask")),
                    pair.get("confidence", 0.0),
                    pair.get("closes", 0),
                    pair.get("stop", 0.0),
                    pair.get("keep", 0.0),
                    last,
                )
            )
        human = "\n".join(lines) if records else "pairs: none learned yet"
    else:
        return die("learn %s is not available yet" % selected, 2)

    if selected != "show":
        fields = {"view": selected, "records": records, "count": len(records)}
    model = view.record("learn", fields)
    view.emit(model, a, human)
    return 0


def cmd_gc(a):
    from . import view

    cfg, store, units = _load(a)
    reply = ask(
        cfg,
        {
            "cmd": "gc",
            "dry_run": a.dry_run,
            "memory": getattr(a, "memory", False) is True,
        },
        timeout=60,
    )
    available = reply is not None
    if reply is None:
        cands = engine.gc_candidates(cfg, units, store, {})
        reply = {
            "candidates": [[cgroup.rel(p), why] for p, why in cands],
            "note": (
                "daemon not running; immediate candidates only; memory reclaim requires the daemon"
                if getattr(a, "memory", False)
                else "daemon not running; immediate candidates only"
            ),
        }
    model = view.record("gc", {"result": reply})
    view.emit(model, a, json.dumps(reply, indent=1, ensure_ascii=False) + "\n")
    return 0 if available else 3


def cmd_freeze(a):
    """Request a manually authorized, safety-checked freeze from the daemon."""
    cfg, _store, _units = _load(a)
    name = getattr(a, "name", None)
    path = cgroup.resolve(name) if isinstance(name, str) else None
    if path is None:
        return die("scope %s not found" % (name or ""), 2)
    scope = cgroup.rel(path)
    reply = ask(cfg, {"cmd": "freeze", "scope": scope})
    if reply is None:
        return die("daemon is not running; freeze requires live safety checks", 3)
    if not isinstance(reply, dict):
        return die("daemon returned an invalid freeze reply", 3)
    if reply.get("error"):
        return die(str(reply["error"]), 4)
    print("frozen %s" % scope)
    return 0


def cmd_thaw(a):
    """Thaw one cgroup or every scope Taema recorded as frozen."""
    cfg, _store, _units = _load(a)
    name = getattr(a, "name", None)
    all_scopes = getattr(a, "all", False) is True
    if all_scopes == (name is not None):
        return die("choose exactly one scope or --all", 2)
    if all_scopes:
        request = {"cmd": "thaw", "all": True}
    else:
        path = cgroup.resolve(name) if isinstance(name, str) else None
        if path is None:
            return die("scope %s not found" % (name or ""), 2)
        request = {"cmd": "thaw", "scope": cgroup.rel(path)}
    reply = ask(cfg, request)
    if reply is None:
        return die("daemon is not running; thaw requires live cgroup ownership", 3)
    if not isinstance(reply, dict):
        return die("daemon returned an invalid thaw reply", 3)
    if reply.get("error"):
        return die(str(reply["error"]), 4)
    if all_scopes:
        thawed = reply.get("thawed", [])
        print("thawed %s" % (", ".join(thawed) if thawed else "no managed scopes"))
    elif reply.get("thawed"):
        print("thawed %s" % request["scope"])
    else:
        print("%s is already thawed" % request["scope"])
    return 0


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
    from ..daemon_entrypoint import launch_daemon

    return launch_daemon(
        config_path=getattr(a, "config", None),
        socket_override=getattr(a, "socket", None),
    )


def cmd_agent(a):
    """Run this session's relay: lock, join the agent leaf, register, beat."""
    import time

    from .. import agent as agent_mod

    cfg = policy.load_config(path=getattr(a, "config", None))
    socket_override = getattr(a, "socket", None)
    if socket_override:
        socket_override = policy.expand(socket_override)
        cfg["paths"]["socket"] = socket_override
        cfg["paths"]["socket_fallback"] = socket_override
    session = agent_mod.session_key()
    lock = agent_mod.hold_lock(agent_mod.lock_path(policy.state_dir(cfg), session))
    if lock is None:
        print("taema: agent already running for session %s" % session)
        return 0
    try:
        compositor = agent_mod.compositor_socket()
        if not agent_mod.compositor_live(compositor):
            return die("no compositor socket; the agent needs a graphical session")
        if not agent_mod.ensure_leaf(os.getpid(), lambda message: ask(cfg, message)):
            return die("could not join the agent leaf")
        agent = agent_mod.Agent(cfg, session)
        attempt = 0
        while not agent.connect():
            time.sleep(agent_mod.backoff(attempt))
            attempt += 1
        try:
            result = agent.run()
        except KeyboardInterrupt:
            return 0
        if result == "compositor-gone":
            print("taema: compositor socket went away; agent exiting")
        return 0
    finally:
        agent_mod.release_lock(lock)


def cmd_help(a):
    """Show a topic, or list topics when none is given."""
    from . import help_topics

    topic = getattr(a, "topic", None)
    if not topic:
        print(help_topics.listing(), end="")
        return 0
    body = help_topics.text(topic)
    if body is None:
        return die(
            "unknown topic %r" % topic,
            hint="Run `taema help` to list topics.",
        )
    print(body, end="" if body.endswith("\n") else "\n")
    return 0


def cmd_bug_report(a):
    """Write a sanitized support tarball (issue #83)."""
    from .. import bugreport
    from . import view

    _cfg, store, units = _load(a)
    try:
        path = bugreport.create_bundle(
            _cfg, store, units, target=getattr(a, "to", None)
        )
    except OSError as error:
        return die("could not write bug report: %s" % error)
    if getattr(a, "json", False):
        print(
            json.dumps(view.record("bug-report", {"path": path}), indent=2, sort_keys=True)
        )
        return 0
    print(path)
    return 0


def main(argv):
    from .framework import main as framework_main

    return framework_main(argv)
