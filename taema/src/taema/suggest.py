"""Ranked, user-confirmed improvement suggestions (issue #79).

Nothing here grants authority: every suggestion needs an explicit
``suggest apply`` confirmation, and review answers use the user's own
choice. Suggestions never touch learner pairs, answers, or authority.
"""

import os
import re
import time

STALE_REVIEW_AGE_S = 3 * 86400.0
STABLE_CLOSES = 5
FREQUENT_INSTANCES = 5

_KIND_ORDER = (
    "stale-review",
    "stable-unit",
    "wrap",
    "veto",
    "zswap",
    "earlyoom",
    "grace",
)


def _now(current):
    if callable(current):
        return float(current())
    if isinstance(current, (int, float)) and not isinstance(current, bool):
        return float(current)
    return time.time()


def _stale_reviews(store, current):
    try:
        details = store.review_details()
    except Exception:
        return []
    found = []
    for item in details:
        try:
            age = float(item.get("age", 0))
        except (TypeError, ValueError):
            continue
        if age <= STALE_REVIEW_AGE_S:
            continue
        identifier = item.get("id")
        owner = item.get("owner") or "?"
        found.append(
            {
                "id": "stale-review-%s" % identifier,
                "kind": "stale-review",
                "title": "answer stale review #%s (%s)" % (identifier, owner),
                "detail": "open for %d days; answer it to record the decision"
                % int(age // 86400),
                "payload": {"review_id": identifier},
                "_rank": age,
            }
        )
    found.sort(key=lambda entry: entry.pop("_rank"), reverse=True)
    return found


def _slug(value):
    return re.sub(r"[^A-Za-z0-9]+", "-", str(value)).strip("-").lower() or "item"


def _expired(veto, current):
    expires = veto.get("expires")
    return (
        isinstance(expires, (int, float))
        and not isinstance(expires, bool)
        and expires <= current
    )


def _known_apps(store):
    try:
        identities = store.db.app_identities()
    except Exception:
        identities = []
    known = {item.get("key") for item in identities if item.get("key")}
    data = store.data if isinstance(store.data, dict) else {}
    for section in ("exes", "standalone", "noise"):
        section_data = data.get(section)
        if isinstance(section_data, dict):
            known.update(key for key in section_data if isinstance(key, str))
    pairs = data.get("pairs")
    if isinstance(pairs, dict):
        for key in pairs:
            if isinstance(key, str):
                known.update(part for part in key.split("\x00") if part)
    return known


def _vetoes(store, current):
    data = store.data if isinstance(store.data, dict) else {}
    vetoes = data.get("vetoes")
    if not isinstance(vetoes, list):
        return []
    known = _known_apps(store)
    found = []
    for veto in vetoes:
        if not isinstance(veto, dict):
            continue
        kind = veto.get("kind")
        value = veto.get("value")
        if kind not in ("app", "owner", "scope") or not isinstance(value, str):
            continue
        if _expired(veto, current):
            reason = "expired"
        elif value not in known:
            reason = "unused"
        else:
            continue
        found.append(
            {
                "id": "veto-%s-%s" % (kind, _slug(value)),
                "kind": "veto",
                "title": "remove %s veto %s" % (reason, value),
                "detail": "veto %s %s is %s; removing it changes nothing active"
                % (kind, value, reason),
                "payload": {"kind": kind, "value": value},
            }
        )
    return found


def _loaded_unit_names(cfg):
    from .config import policy as policy_mod

    if not isinstance(cfg, dict) or not isinstance(cfg.get("paths"), dict):
        return set()
    try:
        units = policy_mod.load_units(cfg)
    except Exception:
        return set()
    names = set()
    for unit in units:
        if not isinstance(unit, dict):
            continue
        head = unit.get("unit")
        name = head.get("name") if isinstance(head, dict) else None
        if name:
            names.add(name)
        filename = os.path.basename(unit.get("_file", ""))
        if filename.endswith(".toml"):
            names.add(filename[: -len(".toml")])
    return names


def _signature_children(signature, owner):
    members = signature.get("members") or []
    children = []
    for member in members:
        key = member.get("key") if isinstance(member, dict) else member
        if isinstance(key, str) and key and key != owner:
            children.append(key)
    return sorted(set(children))


def _stable_units(store, cfg):
    try:
        identities = store.db.app_identities(limit=2000)
    except Exception:
        identities = []
    try:
        owners = [item.get("owner") for item in store.db.signatures(limit=2000)]
    except Exception:
        owners = []
    apps = [item.get("key") for item in identities if item.get("key")]
    apps.extend(owner for owner in owners if owner)
    names = _loaded_unit_names(cfg)
    found = []
    for app in sorted(set(apps)):
        if app in names:
            continue
        try:
            summaries = store.signature_summaries(app, limit=20)
        except Exception:
            continue
        best = None
        for summary in summaries:
            try:
                closes = int(summary.get("closes", 0) or 0)
            except (TypeError, ValueError):
                continue
            if closes < STABLE_CLOSES:
                continue
            children = _signature_children(summary, app)
            if not children:
                continue
            if best is None or closes > best[0]:
                best = (closes, children)
        if best is None:
            continue
        closes, children = best
        found.append(
            {
                "id": "stable-unit-%s" % _slug(app),
                "kind": "stable-unit",
                "title": "draft a unit for %s" % app,
                "detail": "children %s stayed the same across %d closes"
                % (", ".join(children), closes),
                "payload": {"app": app, "children": children},
            }
        )
    return found


def _desktop_file_for(app, directories):
    for directory in directories:
        if not os.path.isdir(directory):
            continue
        for filename in sorted(os.listdir(directory)):
            if not filename.endswith(".desktop"):
                continue
            name = filename[: -len(".desktop")]
            entry_name = ""
            entry_exec = ""
            try:
                path = os.path.join(directory, filename)
                with open(path, encoding="utf-8") as stream:
                    for line in stream:
                        stripped = line.strip()
                        if stripped.startswith("Name=") and not entry_name:
                            entry_name = stripped.split("=", 1)[1].strip()
                        elif stripped.startswith("Exec=") and not entry_exec:
                            entry_exec = stripped.split("=", 1)[1].strip()
            except OSError:
                continue
            first = entry_exec.split()[0] if entry_exec.split() else ""
            if (
                name == app
                or os.path.basename(first) == app
                or entry_name.casefold() == app.casefold()
            ):
                return filename
    return None


def _wraps(store, cfg):
    from . import desktop as desktop_mod

    try:
        identities = store.db.app_identities(limit=2000)
    except Exception:
        return []
    try:
        wrapped = {
            os.path.basename(item.get("file", ""))
            for item in desktop_mod.list_wraps()
            if isinstance(item, dict)
        }
    except Exception:
        wrapped = set()
    try:
        directories = desktop_mod.system_dirs()
    except Exception:
        directories = []
    names = _loaded_unit_names(cfg)
    found = []
    for identity in identities:
        app = identity.get("key")
        try:
            launches = int(identity.get("instances") or 0)
        except (TypeError, ValueError):
            launches = 0
        if not app or launches < FREQUENT_INSTANCES or app in names:
            continue
        filename = _desktop_file_for(app, directories)
        if filename is None or filename in wrapped:
            continue
        found.append(
            {
                "id": "wrap-%s" % _slug(app),
                "kind": "wrap",
                "title": "wrap %s for launch-time scoping" % app,
                "detail": "%d recorded instances and no wrapper yet"
                % launches,
                "payload": {"app": app, "file": filename, "launches": launches},
            }
        )
    return found


def _read_text(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as stream:
            return stream.read()
    except OSError:
        return None


def _zswap(store, cfg, system_root):
    del store, cfg
    swaps = _read_text(
        os.path.join(system_root, "proc/swaps") if system_root != "/" else "/proc/swaps"
    )
    if swaps is None:
        return []
    active = [
        line.split()[0]
        for line in swaps.splitlines()[1:]
        if line.split()
    ]
    if not active:
        return []
    enabled = None
    for candidate in (
        "sys/module/zswap/parameters/enabled",
        "sys/kernel/mm/zswap/enabled",
    ):
        text = _read_text(os.path.join(system_root, candidate))
        if text is not None:
            enabled = text.strip().lower() in ("y", "1", "yes")
            break
    if enabled is None or enabled:
        return []
    return [
        {
            "id": "zswap",
            "kind": "zswap",
            "title": "enable zswap for compressed swap",
            "detail": "swap is active (%s) but uncompressed; zswap is off"
            % ", ".join(active),
            "payload": {"devices": active},
        }
    ]


_BROAD_PREFER = ("", ".*", ".+", "^.*$", "*", "--")


def _earlyoom(store, proc_root):
    from .governor import guard as guard_mod

    try:
        handlers = guard_mod.detect_oom_handlers(proc_root)
    except Exception:
        return []
    if not handlers.get("earlyoom"):
        return []
    try:
        identities = store.db.app_identities(limit=2000)
    except Exception:
        identities = []
    candidates = sorted(
        (
            (int(identity.get("instances") or 0), identity.get("key"))
            for identity in identities
            if identity.get("key")
        ),
        reverse=True,
    )
    candidate = candidates[0][1] if candidates and candidates[0][0] > 0 else None
    if candidate is None:
        return []
    found = []
    for handler in handlers["earlyoom"]:
        prefer = handler.option("--prefer")
        if prefer is not None and prefer.strip() not in _BROAD_PREFER:
            continue
        found.append(
            {
                "id": "earlyoom",
                "kind": "earlyoom",
                "title": "narrow earlyoom --prefer to %s" % candidate,
                "detail": "earlyoom (pid %d) has no narrow --prefer; prefer %s"
                % (handler.pid, candidate),
                "payload": {"candidate": candidate, "pid": handler.pid},
            }
        )
        break
    return found


def _agent_grace_base(cfg):
    agent = cfg.get("agent") if isinstance(cfg, dict) else None
    base = agent.get("windowless_grace", 30) if isinstance(agent, dict) else 30
    if isinstance(base, bool) or not isinstance(base, (int, float)):
        return 30.0
    return float(base)


def _grace(store, cfg):
    data = store.data if isinstance(store.data, dict) else {}
    pairs = data.get("pairs")
    if not isinstance(pairs, dict):
        return []
    learned = data.get("windowless_grace")
    if not isinstance(learned, dict):
        learned = {}
    base = _agent_grace_base(cfg)
    if base >= 600:
        return []
    respawns = {}
    for key, pair in pairs.items():
        if not isinstance(pair, dict) or not isinstance(key, str):
            continue
        try:
            count = float(pair.get("respawn") or 0)
        except (TypeError, ValueError):
            continue
        if count <= 0:
            continue
        owner = key.split("\x00")[0]
        if owner:
            respawns[owner] = max(respawns.get(owner, 0.0), count)
    found = []
    for owner in sorted(respawns):
        if owner in learned:
            continue
        seconds = min(600.0, max(30.0, base * 2))
        if seconds <= base:
            continue
        found.append(
            {
                "id": "grace-%s" % _slug(owner),
                "kind": "grace",
                "title": "raise windowless_grace for %s" % owner,
                "detail": "relaunched after %d stops; wait %d seconds"
                % (int(respawns[owner]), int(seconds)),
                "payload": {"app": owner, "seconds": seconds},
            }
        )
    return found


def rank(store, cfg, *, system_root="/", proc_root=None, now=None):
    """Return ranked suggestion dicts with stable ids."""
    if store is None:
        return []
    current = _now(now)
    suggestions = []
    suggestions.extend(_stale_reviews(store, current))
    suggestions.extend(_vetoes(store, current))
    suggestions.extend(_stable_units(store, cfg))
    suggestions.extend(_wraps(store, cfg))
    suggestions.extend(_zswap(store, cfg, system_root))
    suggestions.extend(_earlyoom(store, proc_root))
    suggestions.extend(_grace(store, cfg))
    order = {kind: index for index, kind in enumerate(_KIND_ORDER)}
    return sorted(
        suggestions, key=lambda entry: (order.get(entry["kind"], 99), entry["id"])
    )


def trailing(store, cfg, limit=3, *, system_root="/", proc_root=None, now=None):
    """At most ``limit`` one-line suggestions for the end of a report."""
    ranked = rank(
        store, cfg, system_root=system_root, proc_root=proc_root, now=now
    )
    return [
        "suggestion: %s [%s]" % (item["title"], item["id"])
        for item in ranked[: max(0, limit)]
    ]


def apply_suggestion(
    store, cfg, suggestion, *, choice=None, input_fn=None, force=False
):
    """Apply one ranked suggestion after the caller confirmed it.

    Returns (ok, message). Review answers use ``choice`` (prompted when
    missing); nothing here changes learner authority.
    """
    from .store import knowledge as knowledge_mod

    kind = suggestion.get("kind")
    if kind == "stale-review":
        return _apply_review(store, suggestion, choice, input_fn, knowledge_mod)
    if kind == "veto":
        return _apply_veto(store, suggestion)
    if kind == "stable-unit":
        return _apply_unit(store, cfg, suggestion, force)
    if kind == "wrap":
        return _apply_wrap(store, cfg, suggestion)
    if kind == "zswap":
        return _apply_zswap(store, cfg, suggestion)
    if kind == "earlyoom":
        return _apply_earlyoom(store, cfg, suggestion)
    if kind == "grace":
        return _apply_grace(store, cfg, suggestion)
    return False, "unknown suggestion kind: %s" % kind


def _apply_grace(store, _cfg, suggestion):
    payload = suggestion.get("payload") or {}
    app = payload.get("app")
    seconds = payload.get("seconds")
    if not isinstance(app, str) or not app:
        return False, "suggestion has no app"
    try:
        seconds = float(seconds)
    except (TypeError, ValueError):
        return False, "suggestion has no grace value"
    learned = store.data.setdefault("windowless_grace", {})
    if not isinstance(learned, dict):
        store.data["windowless_grace"] = learned = {}
    learned[app] = min(600.0, max(0.0, seconds))
    store.dirty = True
    return True, "raised windowless_grace for %s to %d seconds" % (
        app,
        int(learned[app]),
    )


def _apply_zswap(_store, _cfg, _suggestion):
    return (
        False,
        "needs root: enable for this boot with "
        "sudo sh -c 'echo Y > /sys/module/zswap/parameters/enabled', "
        "then persist zswap.enabled=1 on the kernel command line",
    )


def _apply_earlyoom(_store, _cfg, suggestion):
    candidate = (suggestion.get("payload") or {}).get("candidate", "APP")
    return (
        False,
        "needs root: add --prefer %s to the earlyoom service, then restart it"
        % candidate,
    )


def _apply_wrap(_store, _cfg, suggestion):
    from . import desktop as desktop_mod

    payload = suggestion.get("payload") or {}
    filename = payload.get("file")
    app = payload.get("app")
    if not filename:
        return False, "suggestion has no desktop file"
    try:
        desktop_mod.wrap(filename)
    except Exception as error:
        return False, "could not wrap %s: %s" % (app or filename, error)
    return True, "wrapped %s for launch-time scoping" % (app or filename)


def _apply_veto(store, suggestion):
    payload = suggestion.get("payload") or {}
    target = {"kind": payload.get("kind"), "value": payload.get("value")}
    removed = store.remove_veto(target)
    if not removed:
        return False, "veto already gone"
    return True, "removed veto %s %s" % (target["kind"], target["value"])


def _apply_unit(_store, _cfg, suggestion, force):
    import tomllib

    from .config import policy as policy_mod

    payload = suggestion.get("payload") or {}
    app = payload.get("app")
    children = payload.get("children") or []
    if not isinstance(app, str) or not app:
        return False, "suggestion has no app"
    units_dir = os.path.join(policy_mod.user_config_dir(), "units")
    os.makedirs(units_dir, exist_ok=True)
    target = os.path.join(units_dir, _slug(app) + ".toml")
    if os.path.exists(target) and not force:
        return False, "unit file exists: %s (use --force to overwrite)" % target
    body = policy_mod.draft_unit(
        app, comm=app, exe=None, cmdline=[], cgroup="/", children=children
    )
    try:
        parsed = tomllib.loads(body)
    except tomllib.TOMLDecodeError as error:
        return False, "drafted unit does not parse: %s" % error
    problems = policy_mod.validate_unit(parsed)
    if problems:
        return False, "drafted unit fails lint: %s" % "; ".join(problems)
    with open(target, "w", encoding="utf-8") as stream:
        stream.write(body)
    os.chmod(target, 0o600)
    return True, "drafted unit %s; adjust [match] before relying on it" % target


def _apply_review(store, suggestion, choice, input_fn, knowledge_mod):
    review_id = (suggestion.get("payload") or {}).get("review_id")
    if choice is None:
        ask = input_fn or input
        try:
            choice = ask("Choice [stop, keep, standalone, never]: ").strip().lower()
        except (EOFError, OSError):
            return False, "no choice given; review left pending"
    if choice not in knowledge_mod.CHOICES:
        return False, "unknown choice: %s" % choice
    result = store.answer_review(review_id, choice, source="suggest")
    if result is None:
        return False, "review #%s could not be answered" % review_id
    return True, "review #%s answered: %s" % (review_id, choice)
