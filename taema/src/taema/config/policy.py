"""Configuration and hard rules. Nothing in here is learnable.

Configuration is layered from built-in defaults, system files and per-user files. Drop-ins
are read in lexical order. A user file may change settings and add protected entries; it can
never remove protected entries from an earlier layer. TAEMA_CONFIG names a single file that
replaces all file layers (used by tests and isolated runs).
"""

import copy
import fnmatch
import math
import os
import re
import tomllib
import glob

SYSTEM_CONFIG = os.environ.get("TAEMA_SYSTEM_CONFIG", "/etc/taema/taema.toml")
SYSTEM_UNITS = "/etc/taema/units"
USERS_DIR = os.environ.get("TAEMA_USERSDIR", "/run/systemd/users")
HELPER = "/usr/libexec/taema/taema-attach"
MODES = ("observe", "adopt", "enforce", "auto")
LEARN_AUTHORITIES = ("answered", "learned", "aggressive")
PROTECTED_LISTS = ("comm", "cgroup_prefix")

_DEFAULTS = {
    "mode": "observe",
    "paths": {},
    "timers": {"leftover_expire_days": 0},
    "protected": {"comm": [], "cgroup_prefix": [], "env_prefix": {}},
    "seeds": {},
    "learner": {"deny_owners": []},
    "learn": {
        "enabled": True,
        "silent_kills": 5,
        "silent_days": 3,
        "silent_ratio": 0.9,
        "burn_in_days": 7,
        "burn_in_closes": 20,
        "probation_stops": 3,
        "allow_self_authority": False,
        "respawn_window": 60,
        "revive_window": 1800,
        "regret_window": 1800,
        "regret_suspend_days": 7,
        "ask_per_day": 3,
        "ask_pair_gap_days": 7,
        "ask_gui": True,
        "review_ttl_days": 14,
        "identity_denylist": [
            "MainThread",
            "Thread-*",
            "pool-*",
            "GC",
            "Finalizer",
            "sleep",
            "cat",
            "head",
            "sort",
            "grep",
            "true",
        ],
        "remember_argv": False,
    },
    "mem": {
        "enabled": True,
        "manage": "soft",
        "budget": "auto",
        "fraction": 0.80,
        "floor": "512M",
        "min_headroom": "128M",
        "headroom_percent": 10,
        "reclaim": True,
        "reclaim_interval": 60,
        "reclaim_cooldown": 300,
        "reclaim_max": "2G",
        "idle_reclaim_grace": 300,
        "pressure_gate": 10,
        "pressure_ceiling": 60,
        "swap_reclaim": True,
        "zswap": True,
        "oom_policy": "log",
        "probe": False,
    },
    "veto": {"enabled": True, "default_expiry": "0", "block_reclaim": True},
    "ui": {"color": "auto", "dashboard_refresh": 2, "events_tail": 200},
    "review": {"queue": True, "prompt": True, "prompt_interval": 86400},
    "agent": {
        "enabled": True,
        "window_backend": "auto",
        "windowless_grace": 30,
        "max_events_per_s": 50,
        "store_titles": False,
    },
    "notify": {
        "enabled": True,
        "backend": "auto",
        "batch_seconds": 60,
        "max_per_hour": 6,
        "min_mem": "200M",
        "quiet_hours": "22:00-08:00",
        "ttl": 600,
        "undo_toast_seconds": 30,
        "countdown_seconds": 30,
        "digest": "off",
    },
    "freeze": {
        "enabled": True,
        "adopt": False,
        "after": 120,
        "wake_on_connect": True,
        "max_frozen": 32,
        "cpu_idle_max": 0.5,
    },
    "qos": {
        "enabled": True,
        "leftover_cpu_idle": True,
        "leftover_io_weight": 10,
        "background_cpu_weight": 50,
        "focus_boost": False,
        "focus_cpu_weight": 300,
        "leftover_pids_max": 0,
    },
    "guard": {
        "enabled": True,
        "available_floor": "auto",
        "psi_some": "150ms/2s",
        "psi_full": "50ms/2s",
        "cooldown": 10,
        "freeze_in_adopt": False,
        "oom_adj_leftover": 500,
        "oom_adj_shared": 200,
        "oom_group_leftover": True,
    },
    "store": {
        "path": "~/.local/state/taema/state.db",
        "retention_days": 90,
        "sample_interval": 60,
        "max_events": 200000,
        "daily_export": True,
    },
    "experimental": {
        "freeze": True,
        "guard": True,
        "window_close": True,
        "launch_wrap": True,
        "eventd": False,
    },
    "profile": {
        "active": "auto",
        "runtime_mode": "",
        "auto": {"on_battery": "battery", "when_running": {"gamescope": "game"}},
        "default": {},
        "focus": {"qos": {"focus_boost": True}},
        "battery": {
            "timers": {"adopt_interval": 60, "gc_interval": 300},
            "freeze": {"after": 30},
        },
        "game": {
            "protected": {"comm": ["gamescope", "steam"]},
            "notify": {"enabled": False},
            "freeze": {"after": 30},
            "timers": {"adopt_interval": 5, "gc_interval": 15},
        },
        "quiet": {"notify": {"enabled": False}},
        "server": {
            "agent": {"enabled": False},
            "notify": {"enabled": False},
            "experimental": {"window_close": False, "launch_wrap": False},
        },
    },
}


def __getattr__(name):
    if name == "cgroup":
        from ..core import cgroup

        return cgroup
    if name == "inspect":
        from ..core import process

        return process
    raise AttributeError("module %r has no attribute %r" % (__name__, name))


def expand(p):
    return os.path.expanduser(p)


def xdg(var, fallback):
    return os.environ.get(var) or expand(fallback)


def user_config_dir():
    return os.path.join(xdg("XDG_CONFIG_HOME", "~/.config"), "taema")


def user_state_dir():
    return os.path.join(xdg("XDG_STATE_HOME", "~/.local/state"), "taema")


def _toml_location(error, content=""):
    """Read TOMLDecodeError locations on Python 3.11 and later."""
    line = getattr(error, "lineno", None)
    col = getattr(error, "colno", None)
    if not isinstance(line, int) or not isinstance(col, int):
        match = re.search(r"at line (\d+), column (\d+)", str(error))
        if match:
            line, col = int(match.group(1)), int(match.group(2))
    if not isinstance(line, int) or not isinstance(col, int):
        line, col = len(content.splitlines()) + 1, 1
    return line, col


def _read(path):
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except FileNotFoundError:
        return {}
    except tomllib.TOMLDecodeError as error:
        try:
            with open(path, "rb") as source:
                content = source.read().decode("utf-8", errors="replace")
        except OSError:
            content = ""
        line, col = _toml_location(error, content)
        raise ValueError("%s:%d:%d: %s" % (path, line, col, error)) from error


def merge(system, user):
    """Deep merge. Protected lists are unioned so a user file can only add to them."""
    out = copy.deepcopy(system)
    for k, v in user.items():
        if k == "protected" and isinstance(v, dict):
            prot = out.setdefault("protected", {})
            for pk, pv in v.items():
                if pk in PROTECTED_LISTS:
                    previous = prot.get(pk, [])
                    if isinstance(previous, list) and isinstance(pv, list):
                        prot[pk] = list(dict.fromkeys(previous + pv))
                    else:
                        prot[pk] = copy.deepcopy(pv)
                elif pk == "env_prefix":
                    if isinstance(pv, dict) and isinstance(prot.get(pk, {}), dict):
                        env = prot.setdefault("env_prefix", {})
                        for var, prefixes in pv.items():
                            old = env.get(var, [])
                            if isinstance(old, list) and isinstance(prefixes, list):
                                env[var] = list(dict.fromkeys(old + prefixes))
                            else:
                                env[var] = copy.deepcopy(prefixes)
                    else:
                        prot[pk] = copy.deepcopy(pv)
                else:
                    prot[pk] = copy.deepcopy(pv)
            continue
        if k == "learner" and isinstance(v, dict):
            out_l = out.setdefault("learner", {})
            for lk, lv in v.items():
                if lk == "deny_owners" and isinstance(lv, list):
                    out_l[lk] = list(dict.fromkeys(list(out_l.get(lk, [])) + list(lv)))
                else:
                    out_l[lk] = copy.deepcopy(lv)
            continue
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def _layers(path=None):
    override = path or os.environ.get("TAEMA_CONFIG")
    if override:
        return [override]
    system_dir = os.path.join(os.path.dirname(SYSTEM_CONFIG), "taema.d")
    user_dir = user_config_dir()
    return [
        SYSTEM_CONFIG,
        *sorted(glob.glob(os.path.join(system_dir, "*.toml"))),
        os.path.join(user_dir, "taema.toml"),
        *sorted(glob.glob(os.path.join(user_dir, "taema.d", "*.toml"))),
    ]


def _flatten_sources(value, source, prefix="", out=None):
    out = {} if out is None else out
    for key, child in value.items():
        name = "%s.%s" % (prefix, key) if prefix else key
        if isinstance(child, dict) and child:
            _flatten_sources(child, source, name, out)
        else:
            out[name] = source
    return out


def _validate_config(cfg, sources):
    if cfg.get("mode") not in MODES:
        source = sources.get("mode", "built-in defaults")
        raise ValueError("%s:1:1: mode must be one of %s" % (source, MODES))
    guard = cfg.get("guard")
    guard_source = sources.get("guard", "built-in defaults")
    if not isinstance(guard, dict):
        raise ValueError("%s:1:1: guard must be a table" % guard_source)
    for name in ("oom_adj_leftover", "oom_adj_shared"):
        value = guard.get(name, _DEFAULTS["guard"][name])
        source = sources.get("guard." + name, guard_source)
        if type(value) is not int or not -1000 <= value <= 1000:
            raise ValueError(
                "%s:1:1: guard.%s must be an integer from -1000 to 1000"
                % (source, name)
            )
    group_oom = guard.get(
        "oom_group_leftover", _DEFAULTS["guard"]["oom_group_leftover"]
    )
    group_source = sources.get("guard.oom_group_leftover", guard_source)
    if type(group_oom) is not bool:
        raise ValueError(
            "%s:1:1: guard.oom_group_leftover must be a boolean" % group_source
        )
    learn = cfg.get("learn")
    learn_source = sources.get("learn", "built-in defaults")
    if not isinstance(learn, dict):
        raise ValueError("%s:1:1: learn must be a table" % learn_source)
    authority = learn.get("authority")
    if authority is not None and authority not in LEARN_AUTHORITIES:
        source = sources.get("learn.authority", learn_source)
        raise ValueError(
            "%s:1:1: learn.authority must be one of %s" % (source, LEARN_AUTHORITIES)
        )
    if type(learn.get("allow_self_authority", False)) is not bool:
        source = sources.get("learn.allow_self_authority", learn_source)
        raise ValueError(
            "%s:1:1: learn.allow_self_authority must be a boolean" % source
        )
    for name in ("silent_kills", "silent_days", "burn_in_closes", "probation_stops"):
        value = learn.get(name, _DEFAULTS["learn"][name])
        source = sources.get("learn." + name, learn_source)
        if type(value) is not int or value < (0 if name == "probation_stops" else 1):
            raise ValueError(
                "%s:1:1: learn.%s must be a non-negative integer" % (source, name)
            )
    ratio = learn.get("silent_ratio", _DEFAULTS["learn"]["silent_ratio"])
    ratio_source = sources.get("learn.silent_ratio", learn_source)
    if (
        isinstance(ratio, bool)
        or not isinstance(ratio, (int, float))
        or not math.isfinite(ratio)
        or not 0 <= ratio <= 1
    ):
        raise ValueError(
            "%s:1:1: learn.silent_ratio must be between 0 and 1" % ratio_source
        )
    for name in (
        "burn_in_days",
        "respawn_window",
        "revive_window",
        "regret_window",
        "regret_suspend_days",
    ):
        value = learn.get(name, _DEFAULTS["learn"][name])
        source = sources.get("learn." + name, learn_source)
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or value < 0
        ):
            raise ValueError(
                "%s:1:1: learn.%s must be a non-negative number" % (source, name)
            )
    protected = cfg.get("protected")
    if not isinstance(protected, dict):
        source = sources.get("protected", "built-in defaults")
        raise ValueError("%s:1:1: protected must be a table" % source)
    for name in PROTECTED_LISTS:
        if not isinstance(protected.get(name, []), list):
            source = sources.get("protected." + name, "built-in defaults")
            raise ValueError("%s:1:1: protected.%s must be an array" % (source, name))
    env_prefix = protected.get("env_prefix", {})
    if not isinstance(env_prefix, dict) or any(
        not isinstance(prefixes, list) for prefixes in env_prefix.values()
    ):
        source = sources.get("protected.env_prefix", "built-in defaults")
        raise ValueError(
            "%s:1:1: protected.env_prefix must be a table of arrays" % source
        )
    profiles = cfg.get("profile")
    profile_source = sources.get("profile.active", "built-in defaults")
    if not isinstance(profiles, dict):
        raise ValueError("%s:1:1: profile must be a table" % profile_source)
    active = profiles.get("active", "auto")
    if not isinstance(active, str) or not active:
        raise ValueError(
            "%s:1:1: profile.active must be a non-empty string" % profile_source
        )
    if active != "auto":
        overlay = profiles.get(active)
        if not isinstance(overlay, dict):
            raise ValueError(
                "%s:1:1: profile.active names no profile: %s" % (profile_source, active)
            )
    runtime_mode = profiles.get("runtime_mode", "")
    if not isinstance(runtime_mode, str):
        source = sources.get("profile.runtime_mode", profile_source)
        raise ValueError("%s:1:1: profile.runtime_mode must be a string" % source)
    if runtime_mode and runtime_mode not in MODES:
        source = sources.get("profile.runtime_mode", profile_source)
        raise ValueError(
            "%s:1:1: profile.runtime_mode must be one of %s" % (source, MODES)
        )


def effective_authority(cfg):
    """Return the authority used by this mode and where that choice came from."""
    mode = cfg.get("mode", "observe")
    if mode == "enforce":
        return {"value": "unit", "source": "enforce mode unit rules"}
    learn = cfg.get("learn") or {}
    configured = learn.get("authority") if isinstance(learn, dict) else None
    if configured in LEARN_AUTHORITIES:
        source = (cfg.get("_source_map") or {}).get("learn.authority", "configuration")
        return {"value": configured, "source": source}
    if mode == "adopt":
        return {"value": "answered", "source": "mode default for adopt"}
    return {"value": "learned", "source": "mode default for %s" % mode}


def _load_files(files, required=()):
    cfg = copy.deepcopy(_DEFAULTS)
    source_map = _flatten_sources(cfg, "built-in defaults")
    sources = []
    for filename in files:
        if filename in required and not os.path.exists(filename):
            raise FileNotFoundError(filename)
        if not os.path.exists(filename):
            continue
        layer = _read(filename)
        cfg = merge(cfg, layer)
        source_map.update(_flatten_sources(layer, filename))
        sources.append(filename)
    cfg["_sources"] = sources
    cfg["_source_map"] = source_map
    _validate_config(cfg, source_map)
    active_profile = cfg["profile"].get("active", "auto")
    if active_profile != "auto":
        overlay = cfg["profile"][active_profile]
        cfg = merge(copy.deepcopy(cfg), copy.deepcopy(overlay))
        source_map.update(_flatten_sources(overlay, "profile %s" % active_profile))
    runtime_mode = cfg.get("profile", {}).get("runtime_mode", "")
    if runtime_mode:
        cfg["mode"] = runtime_mode
        source_map["mode"] = source_map.get(
            "profile.runtime_mode", "runtime mode override"
        )
    cfg["_profile_name"] = active_profile
    cfg["_profile_reason"] = (
        "automatic profile selection"
        if active_profile == "auto"
        else "manual profile selection"
    )
    cfg["_profile_suppress_stops"] = active_profile == "quiet"
    cfg["_source_map"] = source_map
    _validate_config(cfg, source_map)
    p = cfg["paths"]
    p.setdefault("session_cgroup", "auto")
    p.setdefault("state_dir", user_state_dir())
    p.setdefault("socket", "/run/user/%d/taema.sock" % os.getuid())
    p.setdefault("socket_fallback", os.path.join(expand(p["state_dir"]), "taema.sock"))
    p.setdefault("helper", HELPER)
    p.setdefault("hooks_dir", os.path.join(user_config_dir(), "hooks"))
    source_map = cfg["_source_map"]
    for key in (
        "session_cgroup",
        "state_dir",
        "socket",
        "socket_fallback",
        "helper",
        "hooks_dir",
    ):
        source_map.setdefault("paths." + key, "built-in defaults")
    return cfg


def load_config(path=None):
    override = path or os.environ.get("TAEMA_CONFIG")
    return _load_files(_layers(path), required=(override,) if override else ())


def load_system_config():
    """Return built-in defaults plus the system file and its ordered drop-ins."""
    dropin_dir = os.path.join(os.path.dirname(SYSTEM_CONFIG), "taema.d")
    return _load_files(
        [SYSTEM_CONFIG, *sorted(glob.glob(os.path.join(dropin_dir, "*.toml")))]
    )


def state_dir(cfg):
    d = expand(cfg["paths"]["state_dir"])
    os.makedirs(d, exist_ok=True)
    return d


def timer(cfg, name, default):
    return cfg["timers"].get(name, default)


def units_dirs(cfg):
    """Directories read in order; a later file with the same name replaces an earlier one."""
    if "units_dir" in cfg["paths"]:
        return [expand(cfg["paths"]["units_dir"])]
    return [SYSTEM_UNITS, os.path.join(user_config_dir(), "units")]


def config_watch_paths(cfg=None):
    """Small set of files and directories whose mtimes drive config and unit reloads."""
    paths = set(_layers())
    paths.update(os.path.dirname(path) for path in _layers())
    for directory in units_dirs(cfg or load_config()):
        paths.add(directory)
        if os.path.isdir(directory):
            paths.update(
                os.path.join(directory, name)
                for name in os.listdir(directory)
                if name.endswith(".toml")
            )
    return sorted(paths)


def file_fingerprint(paths):
    result = []
    for path in paths:
        try:
            info = os.stat(path)
            result.append((path, info.st_mtime_ns, info.st_size, info.st_ino))
        except OSError:
            result.append((path, None, None, None))
    return tuple(result)


def load_units(cfg):
    by_name = {}
    errors = []
    for d in units_dirs(cfg):
        if not os.path.isdir(d):
            continue
        for fn in sorted(os.listdir(d)):
            if fn.endswith(".toml"):
                path = os.path.join(d, fn)
                try:
                    with open(path, "rb") as f:
                        u = tomllib.load(f)
                except (OSError, tomllib.TOMLDecodeError) as error:
                    if isinstance(error, tomllib.TOMLDecodeError):
                        try:
                            with open(path, "rb") as source:
                                content = source.read().decode(
                                    "utf-8", errors="replace"
                                )
                        except OSError:
                            content = ""
                        line, col = _toml_location(error, content)
                        message = "%s:%d:%d: %s" % (path, line, col, error)
                    else:
                        message = "%s: %s" % (path, error)
                    errors.append(message)
                    continue
                u["_file"] = os.path.join(d, fn)
                by_name[fn] = u
    cfg["_unit_errors"] = errors
    return [by_name[k] for k in sorted(by_name)]


def unit_for_scope(units, leaf_name):
    for u in units:
        if u.get("unit", {}).get("name") == leaf_name:
            return u
    return None


def hook_for(cfg, leaf_name):
    """$hooks_dir/<name>.stop for scope-<name>, if it exists."""
    h = os.path.join(
        expand(cfg["paths"]["hooks_dir"]), leaf_name.replace("scope-", "", 1) + ".stop"
    )
    return h if os.path.exists(h) else None


def session_dirs(cfg):
    """Candidate login session cgroups, without looking inside: the pinned path, or every
    top-level numeric cgroup (elogind names them after the session id)."""
    from ..core import cgroup

    sc = cfg["paths"].get("session_cgroup", "auto")
    if sc != "auto":
        return [sc] if os.path.isdir(sc) else []
    return [d for d in cgroup.subdirs(cgroup.CG) if os.path.basename(d).isdigit()]


def session_cgroups(cfg, uid=None):
    """Login session cgroups that hold this user's processes. 'auto' means every top-level
    numeric cgroup with at least one process of uid."""
    from ..core import cgroup, process as inspect

    uid = os.getuid() if uid is None else uid
    if cfg["paths"].get("session_cgroup", "auto") != "auto":
        return session_dirs(cfg)
    return [
        d
        for d in session_dirs(cfg)
        if any(inspect.uid_of(p) == uid for p in cgroup.procs(d))
    ]


def session_state(uid=None):
    """(STATE, [session ids]) from elogind's /run/systemd/users/<uid>, or None when unreadable."""
    uid = os.getuid() if uid is None else uid
    try:
        with open("%s/%d" % (USERS_DIR, uid)) as f:
            lines = f.read().splitlines()
    except OSError:
        return None
    kv = dict(l.split("=", 1) for l in lines if "=" in l)
    return kv.get("STATE", ""), kv.get("SESSIONS", "").split()


def comm_protected(c, patterns):
    return any(fnmatch.fnmatchcase(c, pat) for pat in patterns)


def protected_reason(pid, cfg, pp=None):
    """Why this pid must never be signalled or moved, or None."""
    from ..core import cgroup, process as inspect

    me = os.getuid()
    if pid <= 1:
        return "pid 1"
    if pid == os.getpid():
        return "self"
    u = inspect.uid_of(pid)
    if u != me:
        return "not owned by uid %d" % me
    if inspect.is_kernel_thread(pid):
        return "kernel thread"
    prot = cfg["protected"]
    c = inspect.comm(pid)
    if comm_protected(c, prot.get("comm", [])):
        return "protected comm %s" % c
    cg = cgroup.proc_cgroup(pid) or ""
    full = cgroup.CG + cg
    for pre in prot.get("cgroup_prefix", []):
        if full == pre or full.startswith(pre.rstrip("/") + "/"):
            return "protected cgroup %s" % pre
    env_rules = prot.get("env_prefix", {})
    if env_rules:
        env = inspect.environ(pid)
        for var, prefixes in env_rules.items():
            val = env.get(var)
            for pre in prefixes:
                if val and (val == pre or val.startswith(pre.rstrip("/") + "/")):
                    return "protected env %s=%s" % (var, pre)
    return None


def exe_key(pid):
    """Compatibility alias for the one authority-bearing application identity key."""
    return app_key(pid)


INTERPRETERS = (
    "node",
    "nodejs",
    "bun",
    "deno",
    "java",
    "ruby",
    "perl",
    "sh",
    "bash",
    "dash",
    "zsh",
    "fish",
)
INTERP_PREFIXES = ("python", "lua", "php")
_VERSIONED = re.compile(r"^(python3?|lua|php|nodejs)[0-9.]*$")


def interp_name(base):
    """Canonical interpreter name for an exe basename (python3.12 -> python3, lua5.4 -> lua,
    nodejs -> node), or None when base is not an interpreter."""
    if base in INTERPRETERS:
        return "node" if base == "nodejs" else base
    if base.startswith(INTERP_PREFIXES):
        m = _VERSIONED.match(base)
        if m:
            return {"nodejs": "node"}.get(m.group(1), m.group(1))
    return None


def app_identity(pid, units=(), hints=None):
    """Resolve one process to a validated, provenance-bearing application identity."""
    from ..core.identity import resolve_process

    return resolve_process(pid, units=units, hints=hints)


def app_key(pid, table=None, units=(), hints=None):
    """Return the authority-bearing application identity key for pid.

    ``table`` remains accepted for the old call-site contract. ``units`` and ``hints`` let
    daemon collectors add unit and later desktop/launch evidence without a second key path.
    """
    return app_identity(pid, units=units, hints=hints).key


leaf_key = app_key  # name used by knowledge pairs


def env_excluded(env, rules):
    for k, pat in (rules or {}).items():
        if fnmatch.fnmatch(env.get(k, ""), pat):
            return True
    return False


# ---- learner hygiene: names that must never own a pair ----
OWNER_NAMES = ("MainThread", "GC", "Finalizer")  # generic thread names
OWNER_GLOBS = ("Thread-*", "pool-*")
OWNER_SHELLS = ("sh", "bash", "dash", "zsh", "fish")
OWNER_TRIVIAL = ("sleep", "cat", "head", "sort", "grep", "true")


def owner_deny(cfg):
    """Configured extra owner-deny entries ([learner] deny_owners). They extend the built-in
    classes rejected by bad_owner(); a missing or malformed section is just no extras."""
    deny = ((cfg or {}).get("learner") or {}).get("deny_owners") or []
    return (
        [e for e in deny if isinstance(e, str) and e] if isinstance(deny, list) else []
    )


def bad_owner(key, deny=()):
    """Why `key` must never own a learned pair, or None when it is a plausible application.
    Rejected outright: generic thread names, digit-led (version-like) names, shells, trivial
    commands and interpreters running no script. `deny` holds configured glob entries that
    extend those defaults."""
    if not isinstance(key, str) or not key:
        return "empty name"
    if key.startswith("invalid:"):
        return "unvalidated identity %s" % key[8:]
    # Desktop and launch names decorate an evidence key; policy always validates the evidence.
    evidence_key = key.rsplit("|", 1)[-1]
    if evidence_key.startswith("invalid:"):
        return "unvalidated identity %s" % evidence_key[8:]
    if evidence_key.startswith("exe:"):
        name = evidence_key.split(":", 2)[1]
        candidate = name
        base = name
    elif evidence_key.startswith("script:"):
        parts = evidence_key.split(":", 3)
        candidate = evidence_key
        base = parts[1] if len(parts) > 1 else ""
    elif evidence_key.startswith("comm:"):
        candidate = evidence_key.partition(":")[2]
        base = candidate.split(":", 1)[0]
    elif evidence_key.startswith("runtime:"):
        candidate = evidence_key
        base = ""
    else:
        candidate = evidence_key
        base = evidence_key.split(":", 1)[0]
    if candidate in OWNER_NAMES or any(
        fnmatch.fnmatchcase(candidate, g) for g in OWNER_GLOBS
    ):
        return "generic thread name %s" % candidate
    if candidate and candidate[0].isdigit():
        return "name starts with a digit"
    if base in OWNER_SHELLS:
        return "shell %s" % base
    if base in OWNER_TRIVIAL:
        return "trivial command %s" % base
    if evidence_key.startswith("comm:") and interp_name(candidate) is not None:
        return "interpreter %s without a script" % candidate
    if evidence_key.startswith("exe:") and interp_name(base) is not None:
        return "interpreter %s without a script" % base
    if (
        not evidence_key.startswith(("script:", "runtime:"))
        and interp_name(evidence_key) is not None
    ):
        return "interpreter %s without a script" % evidence_key
    for pat in deny:
        if fnmatch.fnmatchcase(candidate, pat) or fnmatch.fnmatchcase(key, pat):
            return "denied by config %s" % pat
    return None
