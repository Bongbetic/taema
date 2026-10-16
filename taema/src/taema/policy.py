"""Configuration and hard rules. Nothing in here is learnable.

Configuration is layered:
  /etc/taema/taema.toml              system defaults and hard rules (root owned)
  $XDG_CONFIG_HOME/taema/taema.toml  per-user overrides
A user file may change the mode, timers and seeds, and may add protected entries; it can
never remove a protected entry set by the system file. TAEMA_CONFIG names a single file
that replaces both layers (used by tests and isolated runs).
"""
import copy
import fnmatch
import os
import tomllib

from . import cgroup, inspect

SYSTEM_CONFIG = os.environ.get("TAEMA_SYSTEM_CONFIG", "/etc/taema/taema.toml")
SYSTEM_UNITS = "/etc/taema/units"
USERS_DIR = os.environ.get("TAEMA_USERSDIR", "/run/systemd/users")
HELPER = "/usr/libexec/taema/taema-attach"
MODES = ("observe", "adopt", "enforce")
PROTECTED_LISTS = ("comm", "cgroup_prefix")


def expand(p):
    return os.path.expanduser(p)


def xdg(var, fallback):
    return os.environ.get(var) or expand(fallback)


def user_config_dir():
    return os.path.join(xdg("XDG_CONFIG_HOME", "~/.config"), "taema")


def user_state_dir():
    return os.path.join(xdg("XDG_STATE_HOME", "~/.local/state"), "taema")


def _read(path):
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except FileNotFoundError:
        return {}


def merge(system, user):
    """Deep merge. Protected lists are unioned so a user file can only add to them."""
    out = copy.deepcopy(system)
    for k, v in user.items():
        if k == "protected" and isinstance(v, dict):
            prot = out.setdefault("protected", {})
            for pk, pv in v.items():
                if pk in PROTECTED_LISTS:
                    prot[pk] = list(dict.fromkeys(list(prot.get(pk, [])) + list(pv)))
                elif pk == "env_prefix":
                    env = prot.setdefault("env_prefix", {})
                    for var, prefixes in pv.items():
                        env[var] = list(dict.fromkeys(list(env.get(var, [])) + list(prefixes)))
            continue
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def load_config(path=None):
    path = path or os.environ.get("TAEMA_CONFIG")
    if path:
        with open(path, "rb") as f:
            cfg = tomllib.load(f)
        sources = [path]
    else:
        user_path = os.path.join(user_config_dir(), "taema.toml")
        cfg = merge(_read(SYSTEM_CONFIG), _read(user_path))
        sources = [p for p in (SYSTEM_CONFIG, user_path) if os.path.exists(p)]
    cfg["_sources"] = sources
    cfg.setdefault("mode", "observe")
    if cfg["mode"] not in MODES:
        raise ValueError("mode must be one of %s" % (MODES,))
    for k in ("paths", "timers", "protected", "seeds"):
        cfg.setdefault(k, {})
    p = cfg["paths"]
    p.setdefault("session_cgroup", "auto")
    p.setdefault("state_dir", user_state_dir())
    p.setdefault("socket", "/run/user/%d/taema.sock" % os.getuid())
    p.setdefault("socket_fallback", os.path.join(expand(p["state_dir"]), "taema.sock"))
    p.setdefault("helper", HELPER)
    p.setdefault("hooks_dir", os.path.join(user_config_dir(), "hooks"))
    return cfg


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


def load_units(cfg):
    by_name = {}
    for d in units_dirs(cfg):
        if not os.path.isdir(d):
            continue
        for fn in sorted(os.listdir(d)):
            if fn.endswith(".toml"):
                with open(os.path.join(d, fn), "rb") as f:
                    u = tomllib.load(f)
                u["_file"] = os.path.join(d, fn)
                by_name[fn] = u
    return [by_name[k] for k in sorted(by_name)]


def unit_for_scope(units, leaf_name):
    for u in units:
        if u.get("unit", {}).get("name") == leaf_name:
            return u
    return None


def hook_for(cfg, leaf_name):
    """$hooks_dir/<name>.stop for scope-<name>, if it exists."""
    h = os.path.join(expand(cfg["paths"]["hooks_dir"]), leaf_name.replace("scope-", "", 1) + ".stop")
    return h if os.path.exists(h) else None


def session_dirs(cfg):
    """Candidate login session cgroups, without looking inside: the pinned path, or every
    top-level numeric cgroup (elogind names them after the session id)."""
    sc = cfg["paths"].get("session_cgroup", "auto")
    if sc != "auto":
        return [sc] if os.path.isdir(sc) else []
    return [d for d in cgroup.subdirs(cgroup.CG) if os.path.basename(d).isdigit()]


def session_cgroups(cfg, uid=None):
    """Login session cgroups that hold this user's processes. 'auto' means every top-level
    numeric cgroup with at least one process of uid."""
    uid = os.getuid() if uid is None else uid
    if cfg["paths"].get("session_cgroup", "auto") != "auto":
        return session_dirs(cfg)
    return [d for d in session_dirs(cfg) if any(inspect.uid_of(p) == uid for p in cgroup.procs(d))]


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
    """Learning key: exe basename, else comm."""
    e = inspect.exe(pid)
    return os.path.basename(e) if e else inspect.comm(pid)


def env_excluded(env, rules):
    for k, pat in (rules or {}).items():
        if fnmatch.fnmatch(env.get(k, ""), pat):
            return True
    return False
