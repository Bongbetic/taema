"""Read-only checks that explain whether tæma can run safely on this machine."""

import os
import sqlite3
import stat
import subprocess
from urllib.parse import quote

from .config import policy
from .core import cgroup, process
from .store import db

_CONFIG_KEYS = set(policy._DEFAULTS) | {
    "_sources",
    "_source_map",
    "_unit_errors",
    "_profile_name",
    "_profile_reason",
    "_profile_suppress_stops",
}
_PATH_KEYS = {
    "session_cgroup",
    "state_dir",
    "socket",
    "socket_fallback",
    "helper",
    "hooks_dir",
    "units_dir",
}
_TIMER_KEYS = {
    "adopt_interval",
    "gc_interval",
    "idle_grace",
    "leftover_expire_days",
    "graceful_timeout",
    "respawn_window",
}
_PROTECTED_KEYS = {"comm", "cgroup_prefix", "env_prefix"}
_SEED_KEYS = {"share", "persist", "kill"}


def fallback_config():
    """Return built-in defaults so doctor can still report other checks after a parse error."""
    state_dir = policy.user_state_dir()
    return {
        "mode": "observe",
        "paths": {
            "session_cgroup": "auto",
            "state_dir": state_dir,
            "socket": "/run/user/%d/taema.sock" % os.getuid(),
            "socket_fallback": os.path.join(state_dir, "taema.sock"),
            "helper": policy.HELPER,
            "hooks_dir": os.path.join(policy.user_config_dir(), "hooks"),
        },
        "timers": {},
        "protected": {},
        "seeds": {},
        "learner": {},
        "_sources": [],
    }


def _check(name, status, message, fix="No action required."):
    return {"name": name, "status": status, "message": str(message), "fix": str(fix)}


def _rooted(root, path):
    return os.path.join(root, path.lstrip("/")) if root != "/" else path


def _read(path):
    try:
        with open(path, encoding="utf-8") as stream:
            return stream.read()
    except OSError:
        return None


def _tokens(path):
    value = _read(path)
    return set(value.split()) if value is not None else set()


def _unknown_config(cfg):
    unknown = sorted(set(cfg) - _CONFIG_KEYS)

    def check_table(section, value, schema):
        if not isinstance(value, dict):
            unknown.append(section + " (expected a table)")
            return
        base_section = section.rsplit(".", 1)[-1]
        allowed = dict(schema)
        if base_section == "paths":
            allowed.update(dict.fromkeys(_PATH_KEYS))
        elif base_section == "timers":
            allowed.update(dict.fromkeys(_TIMER_KEYS))
        elif base_section == "learn":
            allowed["authority"] = None
        elif base_section == "protected":
            allowed.update(dict.fromkeys(_PROTECTED_KEYS))
        elif base_section == "seeds":
            allowed.update(dict.fromkeys(_SEED_KEYS))
        elif base_section == "learner":
            allowed["deny_owners"] = []
        for key, child in value.items():
            path = section + "." + key
            if section == "profile":
                if key in {"active", "runtime_mode"}:
                    continue
                if key == "auto":
                    if not isinstance(child, dict):
                        unknown.append(path + " (expected a table)")
                    else:
                        unknown.extend(
                            path + "." + item
                            for item in child
                            if item not in {"on_battery", "when_running"}
                        )
                        if "when_running" in child and not isinstance(
                            child["when_running"], dict
                        ):
                            unknown.append(path + ".when_running (expected a table)")
                    continue
                if not isinstance(child, dict):
                    unknown.append(path + " (expected a table)")
                    continue
                for setting, override in child.items():
                    setting_schema = policy._DEFAULTS.get(setting)
                    setting_path = path + "." + setting
                    if setting == "mode":
                        continue
                    if not isinstance(setting_schema, dict):
                        unknown.append(setting_path)
                    else:
                        check_table(setting_path, override, setting_schema)
                continue
            if section == "protected" and key == "env_prefix":
                if not isinstance(child, dict):
                    unknown.append(path + " (expected a table)")
                continue
            if key not in allowed:
                unknown.append(path)
            elif isinstance(allowed[key], dict):
                check_table(path, child, allowed[key])

    for section, schema in policy._DEFAULTS.items():
        value = cfg.get(section, schema)
        if isinstance(schema, dict):
            check_table(section, value, schema)
    # Legacy keys remain accepted while the old learner section is phased out.
    for section, allowed in (
        ("paths", _PATH_KEYS),
        ("timers", _TIMER_KEYS),
        ("protected", _PROTECTED_KEYS),
        ("seeds", _SEED_KEYS),
        ("learner", {"deny_owners"}),
    ):
        value = cfg.get(section, {})
        if isinstance(value, dict):
            unknown.extend(
                section + "." + key
                for key in value
                if key not in allowed
                and key not in policy._DEFAULTS.get(section, {})
                and not (section == "protected" and key == "env_prefix")
            )
    return sorted(set(unknown))


def _config_check(cfg, config_error):
    if config_error:
        return _check(
            "configuration",
            "fail",
            "configuration could not be loaded: %s" % config_error,
            "Fix the reported TOML or mode error, then run taema doctor again.",
        )
    unknown = _unknown_config(cfg)
    if unknown:
        return _check(
            "configuration",
            "warn",
            "unknown configuration keys: %s" % ", ".join(unknown),
            "Correct or remove unknown keys; see taema(5) for supported settings.",
        )
    return _check("configuration", "ok", "configuration loaded without unknown keys")


def _identity(system_root, uid):
    passwd = _read(_rooted(system_root, "/etc/passwd"))
    if passwd is None:
        return None
    for line in passwd.splitlines():
        fields = line.split(":")
        if len(fields) >= 4 and fields[2].isdigit() and int(fields[2]) == uid:
            return fields[0], int(fields[3]) if fields[3].isdigit() else -1
    return None


def _group_check(system_root, uid, group_ids=None):
    if uid == 0:
        return _check(
            "group membership",
            "fail",
            "tæma must run as an unprivileged user",
            "Run taema as your desktop user, not as root.",
        )
    groups = _read(_rooted(system_root, "/etc/group"))
    identity = _identity(system_root, uid)
    if groups is None or identity is None:
        return _check(
            "group membership",
            "fail",
            "could not read the user or group database",
            "Restore readable /etc/passwd and /etc/group entries, then retry.",
        )
    username, primary_gid = identity
    record = next(
        (line.split(":") for line in groups.splitlines() if line.startswith("taema:")),
        None,
    )
    if record is None or len(record) < 4 or not record[2].isdigit():
        return _check(
            "group membership",
            "fail",
            "the taema group does not exist",
            "Create it with: sudo groupadd --system taema.",
        )
    members = {member for member in record[3].split(",") if member}
    group_id = int(record[2])
    if primary_gid == group_id:
        return _check("group membership", "ok", "%s belongs to taema" % username)
    if username in members:
        active_groups = set(os.getgroups() if group_ids is None else group_ids)
        if group_id in active_groups:
            return _check("group membership", "ok", "%s belongs to taema" % username)
        return _check(
            "group membership",
            "warn",
            "%s is listed in taema but this login has not picked up the group"
            % username,
            "Log out and back in so the taema group is active in this session.",
        )
    return _check(
        "group membership",
        "warn",
        "%s is not a member of taema" % username,
        "Add the user with: sudo usermod -aG taema %s; then log in again." % username,
    )


def _helper_check(cfg, system_root):
    path_cfg = cfg.get("paths", {})
    if not isinstance(path_cfg, dict):
        path_cfg = {}
    helper_value = path_cfg.get("helper", policy.HELPER)
    if not isinstance(helper_value, str):
        return _check(
            "sudo helper",
            "fail",
            "paths.helper must be a string",
            "Set paths.helper to the absolute taema-attach executable path.",
        )
    helper = policy.expand(helper_value)
    helper_path = _rooted(system_root, helper)
    rule_path = _rooted(system_root, "/etc/sudoers.d/taema")
    if not os.path.isfile(helper_path) or not os.access(helper_path, os.X_OK):
        return _check(
            "sudo helper",
            "fail",
            "the taema-attach helper is missing or not executable",
            "Reinstall the taema package so /usr/libexec/taema/taema-attach is executable.",
        )
    rule = _read(rule_path)
    if rule is None:
        try:
            result = subprocess.run(
                ["sudo", "-n", "-ll", helper],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
        except FileNotFoundError:
            return _check(
                "sudo helper",
                "warn",
                "sudo is unavailable, so the helper permission could not be verified",
                "Install sudo and verify the taema-attach NOPASSWD rule.",
            )
        except (OSError, subprocess.TimeoutExpired):
            return _check(
                "sudo helper",
                "warn",
                "the sudo helper permission check did not complete",
                "Run sudo -l %s and verify a NOPASSWD rule." % helper,
            )
        listing = result.stdout + result.stderr
        no_auth = "NOPASSWD:" in listing or "!authenticate" in listing
        if result.returncode == 0 and no_auth and helper in listing:
            return _check(
                "sudo helper", "ok", "sudo grants passwordless access to taema-attach"
            )
        if result.returncode == 0 and helper in listing:
            return _check(
                "sudo helper",
                "warn",
                "sudo lists the helper but did not reveal whether authentication is required",
                "Confirm that the taema-attach rule includes NOPASSWD.",
            )
        return _check(
            "sudo helper",
            "fail",
            "sudo does not grant passwordless access to taema-attach",
            "Install /etc/sudoers.d/taema and validate it with visudo.",
        )
    if "%taema" not in rule or "NOPASSWD:" not in rule or helper not in rule:
        return _check(
            "sudo helper",
            "fail",
            "the sudoers rule for taema-attach is missing or incomplete",
            "Install /etc/sudoers.d/taema from the taema package and validate it with visudo.",
        )
    return _check(
        "sudo helper", "ok", "the executable helper has a matching NOPASSWD rule"
    )


def _runit_check(system_root):
    service = _rooted(system_root, "/etc/sv/taema")
    run_script = os.path.join(service, "run")
    active = _rooted(system_root, "/var/service/taema")
    if not os.path.isfile(run_script) or not os.access(run_script, os.X_OK):
        return _check(
            "runit service",
            "fail",
            "the taema runit service is not installed",
            "Reinstall the taema package, then enable it with sudo ln -s /etc/sv/taema /var/service/taema.",
        )
    if not os.path.lexists(active):
        return _check(
            "runit service",
            "warn",
            "the service is installed but not enabled",
            "Enable it with: sudo ln -s /etc/sv/taema /var/service/taema.",
        )
    if not os.path.isdir(os.path.join(active, "supervise")):
        return _check(
            "runit service",
            "warn",
            "the service is enabled but runsv is not supervising it",
            "Start it with: sudo sv up taema.",
        )
    return _check("runit service", "ok", "taema is enabled under runit")


def _cgroup_checks(uid):
    root = cgroup.CG
    controllers_path = os.path.join(root, "cgroup.controllers")
    if not os.path.isfile(controllers_path):
        cgroup_check = _check(
            "cgroup v2",
            "fail",
            "the unified cgroup v2 hierarchy is not mounted at %s" % root,
            "Mount cgroup v2 at /sys/fs/cgroup and check the kernel configuration.",
        )
        controllers = set()
    else:
        cgroup_check = _check(
            "cgroup v2", "ok", "the unified cgroup hierarchy is mounted"
        )
        controllers = _tokens(controllers_path)

    base = cgroup.base(uid)
    if not os.path.isdir(base):
        delegated = _check(
            "delegation",
            "fail",
            "the user cgroup subtree %s is missing" % base,
            "Start the taema runit service and check its delegation log.",
        )
        available = set()
    else:
        try:
            owner = os.stat(base).st_uid
        except OSError:
            owner = -1
        available = _tokens(os.path.join(base, "cgroup.controllers"))
        if owner != uid or not os.access(base, os.W_OK):
            delegated = _check(
                "delegation",
                "fail",
                "the user cgroup subtree is not writable by its owner",
                "Restart the taema service and verify ownership of %s." % base,
            )
        else:
            missing = sorted({"cpu", "io", "memory", "pids"} - available)
            if missing:
                delegated = _check(
                    "delegation",
                    "warn",
                    "delegated controllers are unavailable: %s" % ", ".join(missing),
                    "Check TAEMA_CONTROLLERS and restart the taema runit service.",
                )
            else:
                delegated = _check(
                    "delegation", "ok", "the user subtree is writable and delegated"
                )

    pids = cgroup.tree_procs(base) if os.path.isdir(base) else []
    foreign, unreadable = [], []
    for pid in pids:
        owner = process.uid_of(pid)
        if owner == -1:
            unreadable.append(pid)
        elif owner != uid:
            foreign.append(pid)
    if foreign:
        ownership = _check(
            "process ownership",
            "fail",
            "foreign-uid processes are present in the delegated subtree: %s"
            % ", ".join(map(str, foreign[:8])),
            "Stop the foreign processes and verify the taema cgroup delegation boundary.",
        )
    elif unreadable:
        ownership = _check(
            "process ownership",
            "warn",
            "some processes exited before their ownership could be checked",
            "Retry doctor; no process was acted on.",
        )
    else:
        ownership = _check(
            "process ownership",
            "ok",
            "all processes in the delegated subtree belong to this user",
        )
    return base, controllers, available, [cgroup_check, delegated, ownership]


def _feature_check(name, path, controllers, required_controller=None):
    if required_controller and required_controller not in controllers:
        return _check(
            name,
            "warn",
            "%s controller is unavailable" % required_controller,
            "The kernel or parent cgroup does not expose this optional control; taema will skip it.",
        )
    if not os.path.isfile(path):
        return _check(
            name,
            "warn",
            "the kernel does not expose %s" % os.path.basename(path),
            "This kernel feature is optional; taema will skip it.",
        )
    return _check(name, "ok", "%s is available" % os.path.basename(path))


def _kernel_checks(base, controllers, system_root):
    checks = [
        _feature_check(
            "memory accounting",
            os.path.join(base, "memory.current"),
            controllers,
            "memory",
        ),
        _feature_check(
            "memory reclaim",
            os.path.join(base, "memory.reclaim"),
            controllers,
            "memory",
        ),
        _feature_check(
            "memory PSI", os.path.join(base, "memory.pressure"), controllers, "memory"
        ),
        _feature_check(
            "cgroup freeze", os.path.join(base, "cgroup.freeze"), controllers
        ),
        _feature_check("cpu.idle", os.path.join(base, "cpu.idle"), controllers, "cpu"),
        _feature_check("io.weight", os.path.join(base, "io.weight"), controllers, "io"),
        _feature_check(
            "swap accounting",
            os.path.join(base, "memory.swap.current"),
            controllers,
            "memory",
        ),
    ]
    zswap_paths = (
        "/sys/module/zswap/parameters/enabled",
        "/sys/kernel/mm/zswap/enabled",
    )
    zswap_path = next(
        (
            _rooted(system_root, path)
            for path in zswap_paths
            if os.path.isfile(_rooted(system_root, path))
        ),
        None,
    )
    if zswap_path is None:
        checks.append(
            _check(
                "zswap",
                "warn",
                "the kernel does not expose zswap state",
                "Zswap is optional; enable it only if desired in kernel configuration.",
            )
        )
    elif (_read(zswap_path) or "").strip().lower() in ("y", "1", "yes"):
        checks.append(_check("zswap", "ok", "zswap is enabled"))
    else:
        checks.append(
            _check(
                "zswap",
                "warn",
                "zswap is available but disabled",
                "Enable zswap only if desired.",
            )
        )
    return checks


def _socket_check(cfg, uid):
    paths = cfg.get("paths", {})
    if not isinstance(paths, dict):
        paths = {}
    candidates = [
        os.path.expanduser(paths.get(key, ""))
        for key in ("socket", "socket_fallback")
        if isinstance(paths.get(key), str) and paths.get(key)
    ]
    found = []
    invalid = []
    for path in candidates:
        try:
            info = os.stat(path)
        except OSError:
            continue
        mode = stat.S_IMODE(info.st_mode)
        if (
            not stat.S_ISSOCK(info.st_mode)
            or info.st_uid != uid
            or mode & 0o077
            or not mode & stat.S_IWUSR
        ):
            invalid.append(path)
        else:
            found.append(path)
    if found:
        return _check(
            "socket", "ok", "a private user socket is available at %s" % found[0]
        )
    if invalid:
        return _check(
            "socket",
            "fail",
            "socket path has the wrong type, owner, or permissions: %s" % invalid[0],
            "Restart taemad so it recreates a same-user socket with mode 0600.",
        )
    return _check(
        "socket",
        "warn",
        "neither configured daemon socket is present",
        "Start the taema runit service with: sudo sv up taema.",
    )


def _store_checks(cfg, store, store_error):
    path_cfg = cfg.get("paths", {})
    if not isinstance(path_cfg, dict):
        path_cfg = {}
    state_dir_value = path_cfg.get("state_dir", "")
    if not isinstance(state_dir_value, str):
        store_check = _check(
            "store integrity",
            "fail",
            "paths.state_dir must be a string",
            "Set paths.state_dir to a writable directory owned by the user.",
        )
        state_dir = ""
    else:
        store_check = None
        state_dir = policy.expand(state_dir_value)
    path = os.path.join(state_dir, "state.db")
    if store_check is None and store_error:
        store_check = _check(
            "store integrity",
            "fail",
            "the state store could not be loaded: %s" % store_error,
            "Back up the state directory, then inspect or recover state.db before restarting taema.",
        )
    elif store_check is None and not os.path.isfile(path):
        legacy = os.path.join(state_dir, "knowledge.json")
        if os.path.isfile(legacy):
            store_check = _check(
                "store integrity",
                "warn",
                "legacy knowledge exists and will be imported by the daemon",
                "Start taema once to complete the state migration.",
            )
        else:
            store_check = _check(
                "store integrity", "ok", "no state database exists yet"
            )
    elif store_check is None:
        try:
            uri = "file:%s?mode=ro" % quote(os.path.abspath(path))
            connection = sqlite3.connect(uri, uri=True)
            try:
                result = connection.execute("PRAGMA integrity_check").fetchone()[0]
                version = connection.execute("PRAGMA user_version").fetchone()[0]
            finally:
                connection.close()
            if result != "ok":
                store_check = _check(
                    "store integrity",
                    "fail",
                    "SQLite reports: %s" % result,
                    "Back up state.db and restore it from the newest valid state export.",
                )
            elif version > db.SCHEMA_VERSION:
                store_check = _check(
                    "store integrity",
                    "fail",
                    "database schema %d is newer than supported schema %d"
                    % (version, db.SCHEMA_VERSION),
                    "Use a taema version that supports this schema; do not edit state.db by hand.",
                )
            elif version < db.SCHEMA_VERSION:
                store_check = _check(
                    "store integrity",
                    "warn",
                    "database schema %d will migrate to schema %d"
                    % (version, db.SCHEMA_VERSION),
                    "Start the daemon to apply the supported schema migration.",
                )
            else:
                store_check = _check(
                    "store integrity",
                    "ok",
                    "SQLite integrity and schema version are valid",
                )
        except (OSError, sqlite3.Error, TypeError, IndexError) as error:
            store_check = _check(
                "store integrity",
                "fail",
                "state.db could not be checked: %s" % error,
                "Back up state.db and inspect it before restarting taema.",
            )

    if store_error:
        recovery = _check(
            "store recovery",
            "warn",
            "recovery status is unavailable because the store could not be loaded",
            "Resolve the store integrity issue first.",
        )
    elif store is not None and store.recovery:
        recovery = _check(
            "store recovery",
            "warn",
            "state was recovered from %s" % store.recovery.get("source", "a backup"),
            "Review the recovery export and keep a backup until the recovered state is verified.",
        )
    else:
        recovery = _check("store recovery", "ok", "no recovery is pending")
    return [store_check, recovery]


def diagnose(
    cfg,
    store=None,
    units=None,
    *,
    config_error=None,
    units_error=None,
    store_error=None,
    system_root="/",
    uid=None,
    group_ids=None,
):
    """Build a stable, read-only diagnostic result shared by the CLI and daemon."""
    uid = os.getuid() if uid is None else uid
    checks = [_config_check(cfg, config_error)]
    if units_error:
        checks.append(
            _check(
                "unit files",
                "fail",
                "unit configuration could not be parsed: %s" % units_error,
                "Fix the reported TOML error in the unit file, then run taema doctor again.",
            )
        )
    elif units is None:
        checks.append(
            _check(
                "unit files",
                "warn",
                "unit files were not checked because configuration is unavailable",
                "Fix configuration first, then run taema doctor again.",
            )
        )
    elif cfg.get("_unit_errors"):
        checks.append(
            _check(
                "unit files",
                "warn",
                "invalid unit files were skipped: %s" % "; ".join(cfg["_unit_errors"]),
                "Fix the malformed unit files, then run taema doctor again.",
            )
        )
    else:
        checks.append(_check("unit files", "ok", "%d unit files parsed" % len(units)))
    checks.extend(
        (
            _group_check(system_root, uid, group_ids),
            _helper_check(cfg, system_root),
            _runit_check(system_root),
        )
    )
    base, _root_controllers, controllers, cgroup_results = _cgroup_checks(uid)
    checks.extend(cgroup_results)
    checks.extend(_kernel_checks(base, controllers, system_root))
    checks.append(_socket_check(cfg, uid))
    checks.extend(_store_checks(cfg, store, store_error))
    mode = cfg.get("mode")
    if mode not in policy.MODES:
        checks.append(
            _check(
                "mode and hold",
                "fail",
                "configured mode is not supported",
                "Choose one of observe, adopt, enforce, or auto.",
            )
        )
    elif store is not None:
        hold = store.hold_reason()
        if hold:
            checks.append(
                _check(
                    "mode and hold",
                    "warn",
                    "mode is %s; actions are held: %s" % (mode, hold),
                    "Resume taema only when you are ready for actions to continue.",
                )
            )
        else:
            checks.append(
                _check("mode and hold", "ok", "mode is %s and no hold is active" % mode)
            )
    else:
        checks.append(
            _check(
                "mode and hold",
                "warn",
                "mode is %s; hold state could not be read" % mode,
                "Check the state store before relying on hold status.",
            )
        )
    checks.append(
        _check(
            "adopt behavior",
            "ok",
            "taema 0.3.0 adopts eligible apps and reviews unknown leftovers before stopping them",
        )
    )
    statuses = {item["status"] for item in checks}
    overall = "fail" if "fail" in statuses else "warn" if "warn" in statuses else "ok"
    return {"schema": "taema.doctor.v1", "status": overall, "checks": checks}


def render(report):
    """Render one status/message/fix line for each check."""
    lines = ["doctor: %s" % report["status"]]
    for item in report["checks"]:
        lines.append(
            "[%s] %s: %s — fix: %s"
            % (item["status"], item["name"], item["message"], item["fix"])
        )
    return "\n".join(lines) + "\n"
