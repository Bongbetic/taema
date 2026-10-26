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
import time as _time
import tomllib
import glob

SYSTEM_CONFIG = os.environ.get("TAEMA_SYSTEM_CONFIG", "/etc/taema/taema.toml")
SYSTEM_UNITS = "/etc/taema/units"
USERS_DIR = os.environ.get("TAEMA_USERSDIR", "/run/systemd/users")
HELPER = "/usr/libexec/taema/taema-attach"
AGENT_LEAF = "agent"
MODES = ("observe", "adopt", "enforce", "auto")


def is_agent_scope(rel):
    """True for the protected session-agent leaf and anything below it."""
    return rel == AGENT_LEAF or (
        isinstance(rel, str) and rel.startswith(AGENT_LEAF + "/")
    )


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
        "reclaim_minimum": "16M",
        "idle_reclaim_grace": 300,
        "pressure_gate": 10,
        "pressure_ceiling": 60,
        "swap_reclaim": True,
        "swap_reclaim_adopt": False,
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
        "freeze": False,
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
    freeze = cfg.get("freeze")
    freeze_source = sources.get("freeze", "built-in defaults")
    if not isinstance(freeze, dict):
        raise ValueError("%s:1:1: freeze must be a table" % freeze_source)
    for name in ("enabled", "adopt", "wake_on_connect"):
        value = freeze.get(name, _DEFAULTS["freeze"][name])
        source = sources.get("freeze." + name, freeze_source)
        if type(value) is not bool:
            raise ValueError("%s:1:1: freeze.%s must be a boolean" % (source, name))
    after = freeze.get("after", _DEFAULTS["freeze"]["after"])
    after_source = sources.get("freeze.after", freeze_source)
    if (
        isinstance(after, bool)
        or not isinstance(after, (int, float))
        or not math.isfinite(after)
        or after < 0
    ):
        raise ValueError(
            "%s:1:1: freeze.after must be a non-negative number of seconds"
            % after_source
        )
    maximum = freeze.get("max_frozen", _DEFAULTS["freeze"]["max_frozen"])
    maximum_source = sources.get("freeze.max_frozen", freeze_source)
    if type(maximum) is not int or maximum < 0:
        raise ValueError(
            "%s:1:1: freeze.max_frozen must be a non-negative integer" % maximum_source
        )
    cpu_limit = freeze.get("cpu_idle_max", _DEFAULTS["freeze"]["cpu_idle_max"])
    cpu_source = sources.get("freeze.cpu_idle_max", freeze_source)
    if (
        isinstance(cpu_limit, bool)
        or not isinstance(cpu_limit, (int, float))
        or not math.isfinite(cpu_limit)
        or not 0 <= cpu_limit <= 100
    ):
        raise ValueError(
            "%s:1:1: freeze.cpu_idle_max must be between 0 and 100" % cpu_source
        )
    experimental = cfg.get("experimental")
    experimental_source = sources.get("experimental", "built-in defaults")
    if not isinstance(experimental, dict):
        raise ValueError("%s:1:1: experimental must be a table" % experimental_source)
    experimental_freeze = experimental.get(
        "freeze", _DEFAULTS["experimental"]["freeze"]
    )
    if type(experimental_freeze) is not bool:
        raise ValueError(
            "%s:1:1: experimental.freeze must be a boolean" % experimental_source
        )
    experimental_guard = experimental.get("guard", _DEFAULTS["experimental"]["guard"])
    if type(experimental_guard) is not bool:
        raise ValueError(
            "%s:1:1: experimental.guard must be a boolean" % experimental_source
        )
    guard = cfg.get("guard")
    guard_source = sources.get("guard", "built-in defaults")
    if not isinstance(guard, dict):
        raise ValueError("%s:1:1: guard must be a table" % guard_source)
    for name in ("enabled", "freeze_in_adopt"):
        value = guard.get(name, _DEFAULTS["guard"][name])
        source = sources.get("guard." + name, guard_source)
        if type(value) is not bool:
            raise ValueError("%s:1:1: guard.%s must be a boolean" % (source, name))
    available_floor = guard.get(
        "available_floor", _DEFAULTS["guard"]["available_floor"]
    )
    available_source = sources.get("guard.available_floor", guard_source)
    if available_floor != "auto" and (
        isinstance(available_floor, bool)
        or not isinstance(available_floor, (int, float))
        or not math.isfinite(available_floor)
        or not 0 <= available_floor <= 100
    ):
        raise ValueError(
            "%s:1:1: guard.available_floor must be auto or between 0 and 100"
            % available_source
        )
    cooldown = guard.get("cooldown", _DEFAULTS["guard"]["cooldown"])
    cooldown_source = sources.get("guard.cooldown", guard_source)
    if (
        isinstance(cooldown, bool)
        or not isinstance(cooldown, (int, float))
        or not math.isfinite(cooldown)
        or cooldown < 0
    ):
        raise ValueError(
            "%s:1:1: guard.cooldown must be a non-negative number of seconds"
            % cooldown_source
        )
    from ..governor import guard as guard_policy

    for name in ("psi_some", "psi_full"):
        value = guard.get(name, _DEFAULTS["guard"][name])
        source = sources.get("guard." + name, guard_source)
        if not isinstance(value, str):
            raise ValueError("%s:1:1: guard.%s must be a PSI duration" % (source, name))
        try:
            guard_policy.psi_trigger("some" if name == "psi_some" else "full", value)
        except ValueError as error:
            raise ValueError(
                "%s:1:1: guard.%s is invalid: %s" % (source, name, error)
            ) from error
    mem = cfg.get("mem")
    mem_source = sources.get("mem", "built-in defaults")
    if not isinstance(mem, dict):
        raise ValueError("%s:1:1: mem must be a table" % mem_source)
    from ..core import memory

    for name in ("enabled", "reclaim", "swap_reclaim", "swap_reclaim_adopt"):
        value = mem.get(name, _DEFAULTS["mem"][name])
        source = sources.get("mem." + name, mem_source)
        if type(value) is not bool:
            raise ValueError("%s:1:1: mem.%s must be a boolean" % (source, name))
    for name, minimum in (
        ("reclaim_interval", 1),
        ("reclaim_cooldown", 0),
        ("idle_reclaim_grace", 0),
    ):
        value = mem.get(name, _DEFAULTS["mem"][name])
        source = sources.get("mem." + name, mem_source)
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or value < minimum
        ):
            raise ValueError(
                "%s:1:1: mem.%s must be a finite number of at least %s seconds"
                % (source, name, minimum)
            )
    fraction = mem.get("fraction", _DEFAULTS["mem"]["fraction"])
    fraction_source = sources.get("mem.fraction", mem_source)
    if (
        isinstance(fraction, bool)
        or not isinstance(fraction, (int, float))
        or not math.isfinite(fraction)
        or not 0 <= fraction <= 1
    ):
        raise ValueError(
            "%s:1:1: mem.fraction must be between 0 and 1" % fraction_source
        )
    manage = mem.get("manage", _DEFAULTS["mem"]["manage"])
    manage_source = sources.get("mem.manage", mem_source)
    if manage not in ("soft", "hard"):
        raise ValueError("%s:1:1: mem.manage must be soft or hard" % manage_source)
    budget = mem.get("budget", _DEFAULTS["mem"]["budget"])
    budget_source = sources.get("mem.budget", mem_source)
    if budget != "auto":
        try:
            memory.size_bytes(budget)
        except ValueError as error:
            raise ValueError(
                "%s:1:1: mem.budget must be auto or a valid binary size" % budget_source
            ) from error
    for name in ("pressure_gate", "pressure_ceiling", "headroom_percent"):
        value = mem.get(name, _DEFAULTS["mem"][name])
        source = sources.get("mem." + name, mem_source)
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or not 0 <= value <= 100
        ):
            raise ValueError(
                "%s:1:1: mem.%s must be between 0 and 100" % (source, name)
            )
    for name in ("reclaim_max", "reclaim_minimum", "min_headroom", "floor"):
        value = mem.get(name, _DEFAULTS["mem"].get(name))
        if value is None:
            continue
        source = sources.get("mem." + name, mem_source)
        try:
            memory.size_bytes(value)
        except ValueError as error:
            raise ValueError(
                "%s:1:1: mem.%s must be a valid non-negative binary size"
                % (source, name)
            ) from error
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
    auto = profiles.get("auto", {})
    auto_source = sources.get("profile.auto", profile_source)
    if not isinstance(auto, dict):
        raise ValueError("%s:1:1: profile.auto must be a table" % auto_source)
    if "on_battery" in auto:
        battery = auto["on_battery"]
        if not isinstance(battery, str) or not isinstance(profiles.get(battery), dict):
            raise ValueError(
                "%s:1:1: profile.auto.on_battery must name a profile" % auto_source
            )
    running = auto.get("when_running", {})
    if not isinstance(running, dict) or any(
        not isinstance(comm, str) or not isinstance(profiles.get(name), dict)
        for comm, name in running.items()
    ):
        raise ValueError(
            "%s:1:1: profile.auto.when_running must map commands to profiles"
            % auto_source
        )
    windows = auto.get("time", [])
    if not isinstance(windows, list) or any(
        not isinstance(window, dict)
        or not isinstance(profiles.get(window.get("profile")), dict)
        or _parse_day_time(window.get("start")) is None
        or _parse_day_time(window.get("end")) is None
        or (
            window.get("days") is not None
            and (
                not isinstance(window.get("days"), list)
                or not window["days"]
                or any(
                    not isinstance(day, str)
                    or day.strip().lower()
                    not in ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
                    for day in window["days"]
                )
            )
        )
        for window in windows
    ):
        raise ValueError(
            "%s:1:1: profile.auto.time must list profile/start/end windows"
            % auto_source
        )


def read_power_supply(power_dir):
    """True when the machine runs on battery. Missing facts mean False."""
    try:
        entries = sorted(os.listdir(power_dir))
    except OSError:
        return False
    seen_ac = False
    for entry in entries:
        kind_path = os.path.join(power_dir, entry, "type")
        try:
            with open(kind_path, encoding="utf-8") as stream:
                kind = stream.read().strip()
        except OSError:
            continue
        if kind == "Mains":
            seen_ac = True
            try:
                with open(
                    os.path.join(power_dir, entry, "online"), encoding="utf-8"
                ) as stream:
                    if stream.read().strip() == "1":
                        return False
            except OSError:
                continue
    if seen_ac:
        return True
    for entry in entries:
        status_path = os.path.join(power_dir, entry, "status")
        try:
            with open(status_path, encoding="utf-8") as stream:
                if stream.read().strip() == "Discharging":
                    return True
        except OSError:
            continue
    return False


def _parse_day_time(value):
    match = re.fullmatch(r"(\d{2}):(\d{2})", str(value or ""))
    if not match:
        return None
    hour, minute = int(match.group(1)), int(match.group(2))
    if hour > 23 or minute > 59:
        return None
    return hour * 60 + minute


def _window_matches(window, now):
    local = _time.localtime(now)
    days = window.get("days")
    if days is not None:
        names = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
        wanted = {str(day).strip().lower() for day in days if isinstance(day, str)}
        if names[local.tm_wday] not in wanted:
            return False
    start = _parse_day_time(window.get("start"))
    end = _parse_day_time(window.get("end"))
    if start is None or end is None:
        return False
    current = local.tm_hour * 60 + local.tm_min
    if start <= end:
        return start <= current < end
    return current >= start or current < end


def select_auto_profile(cfg, *, on_battery, comms, now):
    """Pick the automatic profile, or None when a manual profile is active.

    Precedence: a running match, then a time window, then battery, then the
    default profile. Returns (name, reason).
    """
    profiles = cfg.get("profile", {})
    if profiles.get("active", "auto") != "auto":
        return None
    auto = profiles.get("auto", {})
    if not isinstance(auto, dict):
        auto = {}
    for comm, name in sorted((auto.get("when_running") or {}).items()):
        if comm in (comms or set()) and isinstance(profiles.get(name), dict):
            return name, "process %s is running" % comm
    for window in auto.get("time") or []:
        if not isinstance(window, dict):
            continue
        name = window.get("profile")
        if isinstance(profiles.get(name), dict) and _window_matches(window, now):
            return name, "time window %s-%s" % (window.get("start"), window.get("end"))
    if on_battery:
        name = auto.get("on_battery")
        if isinstance(name, str) and isinstance(profiles.get(name), dict):
            return name, "running on battery power"
    if isinstance(profiles.get("default"), dict):
        return "default", "no automatic rule matched"
    return None


def with_profile(cfg, name, reason):
    """Return cfg with the named profile overlay applied. The input is unchanged."""
    overlay = cfg["profile"][name]
    merged = merge(copy.deepcopy(cfg), copy.deepcopy(overlay))
    source_map = merged.setdefault("_source_map", {})
    source_map.update(_flatten_sources(overlay, "profile %s" % name))
    runtime_mode = merged.get("profile", {}).get("runtime_mode", "")
    if runtime_mode:
        merged["mode"] = runtime_mode
        source_map["mode"] = source_map.get(
            "profile.runtime_mode", "runtime mode override"
        )
    merged["_profile_name"] = name
    merged["_profile_reason"] = reason
    merged["_profile_suppress_stops"] = name == "quiet"
    merged["_source_map"] = source_map
    return merged


_UNIT_TABLES = {
    "unit": {
        "name",
        "kind",
        "stop_when_unneeded",
        "group_by_env",
        "group_by_qmp",
    },
    "match": {"exe", "comm", "cmdline_contains", "env_exclude"},
    "window": {"backend", "requires_window"},
    "desktop": {"app_id", "on_last_window"},
    "mem": {"class", "background", "save_state", "pause", "swap_max", "max"},
    "kill": {"graceful", "keep", "hook", "never_stop", "survive_logout"},
    "gc": {
        "keep_while_children",
        "no_attach_grace",
        "env_dir_missing",
        "socket_path",
        "socket_glob",
        "socket_env",
        "quit_process_missing",
        "qmp_socket",
    },
}
_CHILDREN_KEYS = {"name", "comm", "ancestor_comm", "binds_to", "same_env"}


#: Interpreter and shell comms that match far more than one app when used alone.
_GENERIC_COMMS = frozenset(
    {
        "node",
        "nodejs",
        "python",
        "python2",
        "python3",
        "java",
        "sh",
        "bash",
        "zsh",
        "fish",
        "dash",
        "electron",
        "ruby",
        "perl",
        "php",
        "deno",
        "bun",
    }
)


def validate_unit(unit, peaks=None):
    """Lint one parsed unit file. Returns a list of error strings.

    peaks optionally maps a unit name to its observed peak memory in
    bytes, letting the lint flag a [mem] max below what the app has
    already used.
    """
    errors = []
    if not isinstance(unit, dict):
        return ["unit must be a table"]
    for table in sorted(unit):
        if table in ("_file", "children"):
            continue
        if table not in _UNIT_TABLES:
            errors.append("unknown table [%s]" % table)
    for table, allowed in _UNIT_TABLES.items():
        section = unit.get(table)
        if section is None:
            continue
        if not isinstance(section, dict):
            errors.append("[%s] must be a table" % table)
            continue
        for key in sorted(section):
            if key not in allowed:
                errors.append("unknown key [%s] %s" % (table, key))
    head = unit.get("unit")
    if not isinstance(head, dict):
        errors.append("[unit] table is required")
        return errors
    name = head.get("name")
    if not isinstance(name, str) or not name:
        errors.append("[unit] name must be a non-empty string")
    kind = head.get("kind")
    if kind not in ("app", "scope"):
        errors.append('[unit] kind must be "app" or "scope"')
    for key in ("stop_when_unneeded", "group_by_qmp"):
        if key in head and not isinstance(head[key], bool):
            errors.append("[unit] %s must be true or false" % key)
    if "group_by_env" in head and not isinstance(head["group_by_env"], str):
        errors.append("[unit] group_by_env must be a string")
    match = unit.get("match", {})
    if kind == "app" and not any(
        key in match for key in ("exe", "comm", "cmdline_contains")
    ):
        errors.append("[match] needs one of exe, comm, cmdline_contains")
    for key in ("exe", "comm", "cmdline_contains"):
        if key in match and not isinstance(match[key], str):
            errors.append("[match] %s must be a string" % key)
    if "env_exclude" in match and not isinstance(match["env_exclude"], dict):
        errors.append("[match] env_exclude must be a table")
    if set(match) == {"comm"} and isinstance(match.get("comm"), str):
        comm = match["comm"].strip("*?[]").lower()
        if comm in _GENERIC_COMMS:
            errors.append(
                "[match] over-broad: comm %r alone matches every %s process; "
                "add exe or cmdline_contains" % (match["comm"], comm)
            )
    window = unit.get("window", {})
    if "backend" in window and (
        not isinstance(window["backend"], str) or not window["backend"]
    ):
        errors.append("[window] backend must be a non-empty string")
    if "requires_window" in window and not isinstance(window["requires_window"], bool):
        errors.append("[window] requires_window must be true or false")
    desk = unit.get("desktop", {})
    if not isinstance(desk, dict):
        errors.append("[desktop] must be a table")
        desk = {}
    if "app_id" in desk and not isinstance(desk["app_id"], str):
        errors.append("[desktop] app_id must be a string")
    if "on_last_window" in desk and desk["on_last_window"] not in (
        "ask",
        "quit",
        "keep",
    ):
        errors.append("[desktop] on_last_window must be ask, quit, or keep")
    kill = unit.get("kill", {})
    graceful = kill.get("graceful")
    if graceful is not None and (
        not isinstance(graceful, (int, float))
        or isinstance(graceful, bool)
        or graceful < 0
    ):
        errors.append("[kill] graceful must be a non-negative number of seconds")
    if "keep" in kill and (
        not isinstance(kill["keep"], list)
        or any(not isinstance(item, str) for item in kill["keep"])
    ):
        errors.append("[kill] keep must be a list of strings")
    if "hook" in kill and not isinstance(kill["hook"], str):
        errors.append("[kill] hook must be a string")
    hook = kill.get("hook")
    if isinstance(hook, str) and "/" in hook:
        hook_path = os.path.expanduser(hook)
        if not (os.path.isfile(hook_path) and os.access(hook_path, os.X_OK)):
            errors.append("[kill] hook %s is not executable" % hook)
    for key in ("never_stop", "survive_logout"):
        if key in kill and not isinstance(kill[key], bool):
            errors.append("[kill] %s must be true or false" % key)
    if kill.get("never_stop") is True and head.get("stop_when_unneeded") is True:
        errors.append(
            "[kill] never_stop contradicts [unit] stop_when_unneeded; "
            "the unit can never be stopped"
        )
    if (
        kill.get("survive_logout") is True
        and head.get("stop_when_unneeded") is not True
    ):
        errors.append(
            "[kill] survive_logout without stop_when_unneeded never stops; "
            "set [unit] stop_when_unneeded"
        )
    mem = unit.get("mem", {})
    if "background" in mem and not isinstance(mem["background"], bool):
        errors.append("[mem] background must be true or false")
    if "class" in mem and (not isinstance(mem["class"], str) or not mem["class"]):
        errors.append("[mem] class must be a non-empty string")
    if "swap_max" in mem and (
        not isinstance(mem["swap_max"], int)
        or isinstance(mem["swap_max"], bool)
        or mem["swap_max"] < 0
    ):
        errors.append("[mem] swap_max must be a non-negative integer")
    if "max" in mem and (
        not isinstance(mem["max"], int)
        or isinstance(mem["max"], bool)
        or mem["max"] < 0
    ):
        errors.append("[mem] max must be a non-negative integer")
    if peaks and isinstance(mem.get("max"), int) and not isinstance(mem["max"], bool):
        peak = peaks.get(name)
        if isinstance(peak, (int, float)) and mem["max"] < peak:
            errors.append(
                "[mem] max %d is below the observed peak %d for %s"
                % (mem["max"], int(peak), name)
            )
    for key in ("save_state", "pause"):
        if key in mem and not isinstance(mem[key], str):
            errors.append("[mem] %s must be a string" % key)
    gc = unit.get("gc", {})
    grace = gc.get("no_attach_grace")
    if grace is not None and (
        not isinstance(grace, (int, float)) or isinstance(grace, bool) or grace < 0
    ):
        errors.append("[gc] no_attach_grace must be a non-negative number of seconds")
    for key in ("keep_while_children", "quit_process_missing", "qmp_socket"):
        if key in gc and not isinstance(gc[key], bool):
            errors.append("[gc] %s must be true or false" % key)
    for key in ("env_dir_missing", "socket_path", "socket_glob", "socket_env"):
        if key in gc and not isinstance(gc[key], str):
            errors.append("[gc] %s must be a string" % key)
    children = unit.get("children", [])
    if not isinstance(children, list) or any(
        not isinstance(child, dict) for child in children
    ):
        errors.append("[[children]] must be a list of tables")
    else:
        for child in children:
            for key in sorted(child):
                if key not in _CHILDREN_KEYS:
                    errors.append("unknown key [[children]] %s" % key)
            if not isinstance(child.get("name"), str) or not child.get("name"):
                errors.append("[[children]] name must be a non-empty string")
            if "comm" not in child and "ancestor_comm" not in child:
                errors.append("[[children]] needs comm or ancestor_comm")
    return errors


def draft_unit(
    name, *, comm, exe, cmdline, cgroup, children=(), peak_bytes=None, app_id=None
):
    """Generate a unit file body from one running process's identity.

    children lists observed child comms, peak_bytes the scope's observed
    memory peak, and app_id the window app id when known; each becomes a
    suggestion in the drafted sections.
    """
    import json as _json

    lines = [
        "# Drafted from pid identity; adjust [match] before installing.",
        "# cmdline: %s" % " ".join(str(cmdline).split()),
        "# cgroup: %s" % cgroup,
        "[unit]",
        "name = %s" % _json.dumps(name),
        'kind = "app"',
        "",
        "[match]",
    ]
    if comm:
        lines.append("comm = %s" % _json.dumps(comm))
    if exe and os.path.isabs(exe):
        lines.append("exe = %s" % _json.dumps(exe))
    backend = "niri" if os.environ.get("NIRI_SOCKET") else "auto"
    lines.extend(
        [
            "",
            "[window]",
            "backend = %s" % _json.dumps(backend),
            "requires_window = true",
        ]
    )
    if app_id:
        lines.append("# window app id: %s" % app_id)
    kids = sorted({str(kid) for kid in children if kid})
    if kids:
        lines.append("")
        for kid in kids:
            lines.extend(
                [
                    "[[children]]",
                    "name = %s" % _json.dumps(kid),
                    "comm = %s" % _json.dumps(kid),
                    "",
                ]
            )
    else:
        lines.extend(
            [
                "",
                "# [[children]]",
                '# name = "helper"',
                '# comm = "helper"',
            ]
        )
    lines.extend(
        ["", "[gc]", "keep_while_children = %s" % ("true" if kids else "false")]
    )
    lines.extend(["", "[mem]", 'class = "app"'])
    if peak_bytes:
        lines.append("# observed peak %d bytes; set max above it" % int(peak_bytes))
        lines.append("max = %d" % int(peak_bytes * 1.25))
    lines.extend(
        [
            "",
            "# [qos] is profile-level; set the app's profile for QoS classes.",
            "",
            "[kill]",
            "graceful = 10",
            "",
        ]
    )
    return "\n".join(lines)


def read_unit_file(path):
    """Parse one unit file. Returns (unit, error)."""
    try:
        with open(path, "rb") as stream:
            unit = tomllib.load(stream)
    except FileNotFoundError:
        return None, "no such unit file: %s" % path
    except (OSError, tomllib.TOMLDecodeError) as error:
        return None, "could not parse %s: %s" % (path, error)
    if not isinstance(unit, dict):
        return None, "could not parse %s: not a table" % path
    return unit, None


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
        cfg = with_profile(cfg, active_profile, "manual profile selection")
        source_map = cfg["_source_map"]
    else:
        runtime_mode = cfg.get("profile", {}).get("runtime_mode", "")
        if runtime_mode:
            cfg["mode"] = runtime_mode
            source_map["mode"] = source_map.get(
                "profile.runtime_mode", "runtime mode override"
            )
        cfg["_profile_name"] = active_profile
        cfg["_profile_reason"] = "automatic profile selection"
        cfg["_profile_suppress_stops"] = False
        cfg["_source_map"] = source_map
    _validate_config(cfg, source_map)
    p = cfg["paths"]
    p.setdefault("session_cgroup", "auto")
    p.setdefault("state_dir", user_state_dir())
    p.setdefault("socket", "/run/user/%d/taema.sock" % os.getuid())
    p.setdefault("socket_fallback", os.path.join(expand(p["state_dir"]), "taema.sock"))
    p.setdefault("helper", HELPER)
    p.setdefault("hooks_dir", os.path.join(user_config_dir(), "hooks"))
    p.setdefault("power_supply", "/sys/class/power_supply")
    source_map = cfg["_source_map"]
    for key in (
        "session_cgroup",
        "state_dir",
        "socket",
        "socket_fallback",
        "helper",
        "hooks_dir",
        "power_supply",
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
    leaf = cgroup.base() + "/" + AGENT_LEAF
    if full == leaf or full.startswith(leaf + "/"):
        return "agent leaf"
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
