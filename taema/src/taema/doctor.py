"""Read-only checks that explain whether tæma can run safely on this machine."""

import json
import os
import re
import shlex
import sqlite3
import stat
import subprocess
import time
from urllib.parse import quote

from .config import policy
from .core import cgroup, memory, oom, process
from .governor import guard as pressure_guard
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
    "power_supply",
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


def _agent_check(agents):
    """Session-agent liveness from the daemon's live report."""
    if not agents:
        return _check(
            "session agent",
            "warn",
            "no session agent is registered; desktop facts are unavailable",
            "Start taema agent from the graphical session autostart.",
        )
    down = sorted(
        session for session, info in agents.items() if info.get("state") != "up"
    )
    if down:
        return _check(
            "session agent",
            "warn",
            "session agent down for %s; the daemon decides on process data only"
            % ", ".join(down),
            "Restart taema agent in the affected session.",
        )
    return _check(
        "session agent",
        "ok",
        "session agent up for %s" % ", ".join(sorted(agents)),
    )


def _notify_check(cfg, notify):
    """Active notification backend and the server's capabilities."""
    if notify is None:
        from . import notify as notify_mod

        try:
            configured = (cfg.get("notify") or {}).get("backend", "auto")
            backend = notify_mod.select_backend(configured)
            notify = {
                "backend": backend.name,
                "capabilities": backend.server_capabilities(),
            }
        except Exception:
            notify = {"backend": "unknown", "capabilities": []}
    backend = notify.get("backend", "unknown")
    if backend in ("null", "unknown"):
        return _check(
            "notifications",
            "warn",
            "no notification backend is available; reviews wait for the shell",
            "Install libnotify (notify-send) for desktop notifications.",
        )
    caps = ", ".join(notify.get("capabilities", ())) or "capabilities unknown"
    return _check(
        "notifications",
        "ok",
        "backend %s; server capabilities: %s" % (backend, caps),
    )


def _desktop_check(cfg):
    """Wrapped launcher entries, and whether their sources drifted behind them."""
    from . import desktop as desktop_mod

    try:
        items = desktop_mod.list_wraps()
    except Exception:
        return _check(
            "desktop entries",
            "warn",
            "wrapped launcher entries could not be listed",
            "Check %s for overrides taema cannot read." % desktop_mod.user_dir(),
        )
    drifted = [item for item in items if item["drifted"]]
    if drifted:
        names = ", ".join(sorted(os.path.basename(item["file"]) for item in drifted))
        return _check(
            "desktop entries",
            "warn",
            "package update changed the source behind: %s" % names,
            "Run taema desktop wrap NAME.desktop again to rewrap.",
        )
    if not items:
        return _check("desktop entries", "ok", "no wrapped launcher entries")
    return _check(
        "desktop entries",
        "ok",
        "%d wrapped launcher entries match their sources" % len(items),
    )


def _rooted(root, path):
    return os.path.join(root, path.lstrip("/")) if root != "/" else path


def _rooted_config_path(root, path):
    """Root an external config path without allowing it to escape a test/system root."""
    if root == "/":
        return path if os.path.isabs(path) else None
    root_path = os.path.abspath(root)
    candidate = os.path.abspath(os.path.join(root_path, path.lstrip("/")))
    try:
        if os.path.commonpath((root_path, candidate)) == root_path:
            return candidate
    except ValueError:
        pass
    return None


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
                            if item not in {"on_battery", "when_running", "time"}
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


def _process_oom_score_check(system_root):
    name = "process OOM score adjustment"
    path = "/proc/self/oom_score_adj"
    raw = _read(_rooted(system_root, path))
    if raw is None:
        return _check(
            name,
            "warn",
            "%s is absent or unreadable" % path,
            "Check that procfs is readable; taema skips per-process OOM score "
            "adjustments when it cannot read a valid score.",
        )

    value = raw.strip()
    digits = value[1:] if value.startswith("-") else value
    try:
        score = int(value) if digits and digits.isdecimal() else None
    except ValueError:
        score = None
    if score is None or not oom.MIN_SCORE <= score <= oom.MAX_SCORE:
        return _check(
            name,
            "warn",
            "%s has an invalid value; expected an integer from %d to %d"
            % (path, oom.MIN_SCORE, oom.MAX_SCORE),
            "Check the procfs value; taema skips per-process OOM score "
            "adjustments when it cannot read a valid score.",
        )
    return _check(
        name,
        "ok",
        "%s is readable and valid (%d)" % (path, score),
    )


def _memory_oom_group_check(base, controllers):
    name = "memory OOM group kill"
    if "memory" not in controllers:
        return _check(
            name,
            "warn",
            "the memory controller is unavailable; delegated memory.oom.group is unsupported",
            "Enable the delegated memory controller; per-process OOM score "
            "adjustment remains available where configured.",
        )

    path = os.path.join(base, "memory.oom.group")
    raw = _read(path)
    if raw is None:
        return _check(
            name,
            "warn",
            "delegated memory.oom.group is absent or unreadable; group-wide OOM handling will be skipped",
            "Expose the optional memory.oom.group control; per-process OOM score "
            "adjustment remains available where configured.",
        )
    value = raw.strip()
    if value not in ("0", "1"):
        return _check(
            name,
            "warn",
            "delegated memory.oom.group has an invalid value; group-wide OOM handling will be skipped",
            "Expose a readable memory.oom.group control; per-process OOM score "
            "adjustment remains available where configured.",
        )
    return _check(
        name,
        "ok",
        "delegated memory.oom.group is readable and supported (value %s)" % value,
    )


def _guard_psi_trigger_check(cfg, base, system_root):
    """Probe writable guard triggers in delegated cgroup and host PSI, in that order."""
    guard_cfg = cfg.get("guard", {}) if isinstance(cfg, dict) else {}
    if not isinstance(guard_cfg, dict):
        guard_cfg = {}
    settings = {
        "some": guard_cfg.get("psi_some", policy._DEFAULTS["guard"]["psi_some"]),
        "full": guard_cfg.get("psi_full", policy._DEFAULTS["guard"]["psi_full"]),
    }
    sources = pressure_guard.psi_trigger_sources(
        os.path.join(base, "memory.pressure"),
        proc_root=_rooted(system_root, "/proc"),
    )
    attempts = []
    for source, path in sources:
        monitor = pressure_guard.PsiTriggerMonitor()
        try:
            failures = monitor.open_triggers(path, settings)
            metrics = tuple(monitor.metrics)
        except Exception as error:  # diagnostics should keep reporting other features
            failures = ["%s: %s" % (type(error).__name__, error)]
            metrics = ()
        finally:
            try:
                monitor.close()
            except OSError:
                pass
        attempts.append(
            {
                "source": source,
                "path": path,
                "metrics": list(metrics),
                "failures": list(failures),
            }
        )
        if metrics:
            required = set(settings)
            writable = required.issubset(metrics)
            failed_sources = attempts[:-1]
            message = "writable PSI trigger source=%s path=%s metrics=%s" % (
                source,
                path,
                ",".join(metrics),
            )
            if failed_sources:
                message += "; delegated trigger unavailable, using host PSI fallback"
            if failures:
                message += "; unavailable metrics: %s" % ", ".join(failures)
            return _check(
                "guard PSI triggers",
                "ok" if writable else "warn",
                message,
                "No action required; host-wide PSI is a labeled fallback."
                if source == "host-proc"
                else "A writable trigger is active for each configured PSI metric."
                if writable
                else "The daemon will monitor only metrics with writable PSI triggers.",
            )
    summary = "; ".join(
        "%s %s: %s"
        % (
            attempt["source"],
            attempt["path"],
            ", ".join(attempt["failures"]) or "no configured metric is writable",
        )
        for attempt in attempts
    )
    return _check(
        "guard PSI triggers",
        "warn",
        "no writable PSI trigger source: %s" % summary,
        "Guard floor sampling remains available; enable writable PSI triggers for earlier pressure actions.",
    )


def _kernel_checks(base, controllers, system_root, cfg=None):
    proc_swaps_path = _rooted(system_root, "/proc/swaps")
    proc_swaps = _read(proc_swaps_path)
    swap_devices = []
    if proc_swaps is not None:
        swap_devices = [
            fields[0]
            for line in proc_swaps.splitlines()[1:]
            if (fields := line.split())
        ]
    if proc_swaps is None:
        checks = [
            _check(
                "swap devices",
                "warn",
                "/proc/swaps is unavailable",
                "Make /proc readable to inspect active swap devices.",
            )
        ]
    elif swap_devices:
        checks = [
            _check(
                "swap devices",
                "ok",
                "active swap devices: %s" % ", ".join(swap_devices),
            )
        ]
    else:
        checks = [
            _check(
                "swap devices",
                "warn",
                "no active swap devices were found",
                "Configure an appropriate swap device before enabling anonymous reclaim.",
            )
        ]
    sys_block = _rooted(system_root, "/sys/block")
    try:
        zram_devices = sorted(
            name for name in os.listdir(sys_block) if name.startswith("zram")
        )
    except OSError:
        zram_devices = None
    if zram_devices is None:
        checks.append(
            _check(
                "zram devices",
                "warn",
                "/sys/block could not be read for zram devices",
                "Make sysfs readable to inspect zram devices.",
            )
        )
    else:
        checks.append(
            _check(
                "zram devices",
                "ok",
                "zram devices: %s"
                % (", ".join(zram_devices) if zram_devices else "none"),
            )
        )
    checks.append(_process_oom_score_check(system_root))
    memory_features = {
        "memory accounting": "memory.current and memory.stat",
        "memory.stat breakdown": "memory.stat anon, file, inactive_file, shmem, and slab fields",
        "memory peak usage": "memory.peak",
        "memory pressure": "memory.pressure or /proc/pressure/memory",
        "guard PSI triggers": "writable memory PSI trigger on cgroup or host source",
        "memory reclaim": "memory.reclaim or memory.high fallback",
        "memory low reservation": "memory.low",
        "memory OOM group kill": "memory.oom.group",
        "memory soft cap": "memory.high",
        "memory low protection": "memory.low",
        "memory hard cap": "memory.max",
        "memory OOM group": "memory.oom.group",
        "swap accounting": "memory.swap.current and memory.swap.max",
        "zswap accounting": "memory.zswap.current",
        "memory OOM events": "memory.events or memory.events.local",
        "memory high events": "memory.events high counter",
        "memory max events": "memory.events max counter",
    }
    if not memory.enabled(cfg):
        checks.extend(
            _check(
                name,
                "warn",
                "%s is not probed because memory collection is disabled" % feature,
                "Enable memory collection to inspect this kernel feature.",
            )
            for name, feature in memory_features.items()
        )
    else:
        if "memory" not in controllers:
            checks.append(
                _check(
                    "memory accounting",
                    "warn",
                    "the memory controller is unavailable; scope memory is unsupported",
                    "Enable the delegated memory controller; host memory remains readable.",
                )
            )
        elif all(
            os.path.isfile(os.path.join(base, name))
            for name in ("memory.current", "memory.stat")
        ):
            checks.append(
                _check(
                    "memory accounting",
                    "ok",
                    "memory.current and memory.stat are available",
                )
            )
        else:
            checks.append(
                _check(
                    "memory accounting",
                    "warn",
                    "memory.current or memory.stat is unavailable",
                    "Scope accounting is unsupported on this cgroup; host metrics remain available.",
                )
            )

        stat_path = os.path.join(base, "memory.stat")
        stat_text = _read(stat_path)
        stat_fields = {
            fields[0]
            for line in (stat_text or "").splitlines()
            if len(fields := line.split()) >= 2
        }
        required_stat = {"anon", "file", "inactive_file", "shmem", "slab"}
        missing_stat = sorted(required_stat - stat_fields)
        checks.append(
            _check(
                "memory.stat breakdown",
                "ok",
                "memory.stat reports anon, file, inactive_file, shmem, and slab",
            )
            if not missing_stat
            else _check(
                "memory.stat breakdown",
                "warn",
                "memory.stat is missing fields: %s" % ", ".join(missing_stat),
                "Kernel memory.stat fields vary; missing breakdowns remain unknown.",
            )
        )

        peak_path = os.path.join(base, "memory.peak")
        checks.append(
            _check("memory peak usage", "ok", "memory.peak is available")
            if os.path.isfile(peak_path)
            else _check(
                "memory peak usage",
                "warn",
                "memory.peak is unsupported; the daemon samples max(memory.current)",
                "No action required; sampled maxima are used as the fallback.",
            )
        )

        pressure_path = os.path.join(base, "memory.pressure")
        proc_pressure = _rooted(system_root, "/proc/pressure/memory")
        checks.append(
            _check("memory pressure", "ok", "cgroup memory.pressure is available")
            if os.path.isfile(pressure_path)
            else _check(
                "memory pressure",
                "ok" if os.path.isfile(proc_pressure) else "warn",
                "host PSI fallback /proc/pressure/memory is available"
                if os.path.isfile(proc_pressure)
                else "memory.pressure and host PSI are unsupported; scope PSI is unknown",
                "No action required; host-wide PSI is labeled as a fallback."
                if os.path.isfile(proc_pressure)
                else "Enable PSI in the kernel to report pressure.",
            )
        )
        checks.append(_guard_psi_trigger_check(cfg, base, system_root))

        reclaim_path = os.path.join(base, "memory.reclaim")
        high_path = os.path.join(base, "memory.high")
        checks.append(
            _feature_check("memory reclaim", reclaim_path, controllers, "memory")
            if os.path.isfile(reclaim_path) or "memory" not in controllers
            else _check(
                "memory reclaim",
                "warn",
                "memory.reclaim is unsupported; memory.high pulse is the available fallback"
                if os.path.isfile(high_path)
                else "memory.reclaim is unsupported; no targeted reclaim fallback is available",
                "The daemon will use the memory.high fallback when configured."
                if os.path.isfile(high_path)
                else "No targeted reclaim operation is available on this kernel.",
            )
        )
        checks.extend(
            _feature_check(name, os.path.join(base, filename), controllers, "memory")
            for name, filename in (
                ("memory low reservation", "memory.low"),
                ("memory soft cap", "memory.high"),
                ("memory hard cap", "memory.max"),
            )
        )
        checks.append(
            _feature_check(
                "memory low protection",
                os.path.join(base, "memory.low"),
                controllers,
                "memory",
            )
        )
        checks.append(
            _feature_check(
                "memory OOM group",
                os.path.join(base, "memory.oom.group"),
                controllers,
                "memory",
            )
        )
        checks.append(
            _check(
                "swap accounting",
                "ok",
                "memory.swap.current and memory.swap.max are available",
            )
            if all(
                os.path.isfile(os.path.join(base, filename))
                for filename in ("memory.swap.current", "memory.swap.max")
            )
            else _check(
                "swap accounting",
                "warn",
                "cgroup swap accounting is unsupported; host swap remains available",
                "Enable cgroup swap accounting to report per-scope swap use.",
            )
        )
        zswap_current = os.path.join(base, "memory.zswap.current")
        checks.append(
            _feature_check("zswap accounting", zswap_current, controllers, "memory")
            if os.path.isfile(zswap_current) or "memory" not in controllers
            else _check(
                "zswap accounting",
                "warn",
                "memory.zswap.current is unsupported; report swap use where available",
                "Cgroup swap accounting remains the fallback for compressed swap.",
            )
        )
        event_fields = set()
        for filename in ("memory.events.local", "memory.events"):
            event_text = _read(os.path.join(base, filename))
            if event_text is None:
                continue
            event_fields.update(
                fields[0]
                for line in event_text.splitlines()
                if len(fields := line.split()) >= 2
            )
        checks.append(
            _check(
                "memory OOM events",
                "ok",
                "memory.events reports oom and oom_kill counters",
            )
            if {"oom", "oom_kill"} <= event_fields
            else _check(
                "memory OOM events",
                "warn",
                "memory.events oom or oom_kill counters are unavailable",
                "No action required; process exits remain observable.",
            )
        )
        checks.append(
            _check(
                "memory high events",
                "ok",
                "memory.events reports the high counter",
            )
            if "high" in event_fields
            else _check(
                "memory high events",
                "warn",
                "memory.events high counter is unavailable",
                "Kernel high-event accounting is optional; pressure reporting remains available.",
            )
        )
        checks.append(
            _check(
                "memory max events",
                "ok",
                "memory.events reports the max counter",
            )
            if "max" in event_fields
            else _check(
                "memory max events",
                "warn",
                "memory.events max counter is unavailable",
                "Kernel limit-event accounting is optional; process exits remain observable.",
            )
        )
        checks.append(_memory_oom_group_check(base, controllers))

    checks.extend(
        [
            _feature_check(
                "cgroup freeze", os.path.join(base, "cgroup.freeze"), controllers
            ),
            _feature_check(
                "cpu.idle", os.path.join(base, "cpu.idle"), controllers, "cpu"
            ),
            _feature_check(
                "CPU weight fallback",
                os.path.join(base, "cpu.weight"),
                controllers,
                "cpu",
            ),
            _feature_check(
                "io.weight", os.path.join(base, "io.weight"), controllers, "io"
            ),
        ]
    )
    oom_score_path = _rooted(system_root, "/proc/self/oom_score_adj")
    oom_score = _read(oom_score_path)
    try:
        score_value = int((oom_score or "").strip())
        score_supported = -1000 <= score_value <= 1000
    except ValueError:
        score_supported = False
    checks.append(
        _check(
            "OOM score adjustment",
            "ok",
            "the current process exposes a readable oom_score_adj value",
        )
        if score_supported
        else _check(
            "OOM score adjustment",
            "warn",
            "/proc/self/oom_score_adj is unavailable or unreadable",
            "OOM priority adjustment is skipped when the procfs control is unavailable.",
        )
    )

    paths = cfg.get("paths", {})
    helper_value = (
        paths.get("helper", policy.HELPER) if isinstance(paths, dict) else None
    )
    helper_path = (
        _rooted(system_root, policy.expand(helper_value))
        if isinstance(helper_value, str)
        else None
    )
    helper_text = _read(helper_path) if helper_path else None
    helper_has_restore = (
        helper_text is not None
        and "oom-restore" in helper_text
        and "oom-record" in helper_text
    )
    checks.append(
        _check(
            "OOM restore helper",
            "ok",
            "taema-attach provides oom-record and oom-restore operations",
        )
        if helper_has_restore
        else _check(
            "OOM restore helper",
            "warn",
            "taema-attach oom-record or oom-restore is unavailable",
            "Reinstall the taema helper to record and restore managed OOM adjustments.",
        )
    )
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
        fix = "Enable for this boot: sudo sh -c 'echo Y > /sys/module/zswap/parameters/enabled'; persist by adding zswap.enabled=1 to the kernel command line."
        if swap_devices:
            fix = "Swap is active but uncompressed. " + fix
        checks.append(
            _check(
                "zswap",
                "warn",
                "zswap is available but disabled",
                fix,
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


def _foreground_prefer_matches(pattern, units, system_root, uid):
    """Find current processes in explicitly foreground-classified unit scopes."""
    try:
        expression = re.compile(pattern)
    except re.error:
        return []
    foreground_units = {}
    for item in units or ():
        metadata = item.get("unit", {}) if isinstance(item, dict) else {}
        mem = item.get("mem", {}) if isinstance(item, dict) else {}
        if not isinstance(metadata, dict):
            metadata = {}
        if not isinstance(mem, dict):
            mem = {}
        name = metadata.get("name")
        resource_class = mem.get(
            "class",
            metadata.get("mem_class", metadata.get("qos_class", metadata.get("class"))),
        )
        if isinstance(name, str) and resource_class in ("foreground", "interactive"):
            foreground_units[name] = resource_class

    base = cgroup.base(uid)
    matches = []
    pending = list(cgroup.subdirs(base))
    while pending:
        path = pending.pop()
        pending.extend(cgroup.subdirs(path))
        scope = cgroup.rel(path, uid)
        unit_name = os.path.basename(path)
        if unit_name not in foreground_units:
            continue
        for pid in cgroup.tree_procs(path):
            comm = _read(_rooted(system_root, "/proc/%d/comm" % pid))
            if comm and expression.search(comm.strip()):
                matches.append((scope, int(pid), comm.strip()))
    return matches


def _handler_option(argv, names):
    for index, token in enumerate(argv[1:], 1):
        for name in names:
            if token == name and index + 1 < len(argv):
                return argv[index + 1]
            if token.startswith(name + "="):
                return token.split("=", 1)[1]
    return None


def _nohang_settings(handler, system_root):
    config = _handler_option(handler.argv, ("-c", "--config"))
    candidates = (
        [config]
        if config
        else (
            "/etc/nohang/nohang.conf",
            "/etc/nohang/nohang-desktop.conf",
            "/usr/local/etc/nohang/nohang.conf",
            "/usr/local/etc/nohang/nohang-desktop.conf",
        )
    )
    keys = {
        "psi_checking_enabled",
        "psi_path",
        "psi_metrics",
        "psi_excess_duration",
        "psi_post_action_delay",
        "soft_threshold_min_mem",
        "soft_threshold_min_swap",
        "soft_threshold_max_psi",
        "hard_threshold_min_mem",
        "hard_threshold_min_swap",
        "hard_threshold_max_psi",
    }
    selected = None
    selected_path = None
    for path in candidates:
        rooted_path = _rooted_config_path(system_root, path)
        text = _read(rooted_path) if rooted_path is not None else None
        if text is None:
            continue
        values = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "@")) or "=" not in line:
                continue
            key, value = (part.strip() for part in line.split("=", 1))
            if key in keys:
                values.append((key, value))
        selected, selected_path = values, path
        break
    if selected_path is None:
        return "config=%s; no settings file found" % (config or "default")
    settings = ", ".join("%s=%s" % item for item in selected) or "no pressure settings"
    return "config=%s; %s" % (selected_path, settings)


def _systemd_oomd_settings(system_root):
    directories = (
        "/etc/systemd",
        "/run/systemd",
        "/usr/local/lib/systemd",
        "/usr/lib/systemd",
    )
    paths = []
    for directory in directories:
        main = directory + "/oomd.conf"
        if os.path.isfile(_rooted(system_root, main)):
            paths.append(main)
        dropin = _rooted(system_root, directory + "/oomd.conf.d")
        try:
            paths.extend(
                directory + "/oomd.conf.d/" + name
                for name in sorted(os.listdir(dropin))
                if name.endswith(".conf")
            )
        except OSError:
            pass
    keys = {
        "SwapUsedLimit",
        "DefaultMemoryPressureLimit",
        "DefaultMemoryPressureDurationSec",
        "PrekillHookTimeoutSec",
    }
    settings = []
    for path in paths:
        text = _read(_rooted(system_root, path))
        if text is None:
            continue
        section = ""
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("[") and line.endswith("]"):
                section = line[1:-1]
                continue
            if section != "OOM" or not line or line.startswith(("#", ";")):
                continue
            key, separator, value = line.partition("=")
            if separator and key.strip() in keys:
                settings.append("%s:%s=%s" % (path, key.strip(), value.strip()))
    return ", ".join(settings) if settings else "no explicit oomd.conf settings found"


def _oom_handler_check(units, system_root, uid):
    handlers = pressure_guard.detect_oom_handlers(_rooted(system_root, "/proc"))
    descriptions = []
    warnings = []
    for name in ("earlyoom", "nohang", "systemd-oomd"):
        for handler in handlers[name]:
            if name == "earlyoom":
                settings = pressure_guard.display_earlyoom(handler)
                descriptions.append("earlyoom pid %d: %s" % (handler.pid, settings))
                pattern = handler.option("--prefer")
                if pattern:
                    for scope, pid, comm in _foreground_prefer_matches(
                        pattern, units, system_root, uid
                    ):
                        warnings.append(
                            "earlyoom --prefer %r matches foreground scope %s "
                            "process %s (pid %d)" % (pattern, scope, comm, pid)
                        )
            else:
                if name == "nohang":
                    details = _nohang_settings(handler, system_root)
                else:
                    details = _systemd_oomd_settings(system_root)
                descriptions.append("%s pid %d: %s" % (name, handler.pid, details))
    if not descriptions:
        descriptions.append("no earlyoom, nohang, or systemd-oomd process detected")
    if warnings:
        return _check(
            "OOM handlers",
            "warn",
            "; ".join(descriptions + warnings),
            "Narrow earlyoom --prefer so it does not select a foreground workload; tæma never edits OOM-handler configuration.",
        )
    return _check(
        "OOM handlers",
        "ok",
        "; ".join(descriptions),
        "tæma reports external OOM handlers and never edits their configuration.",
    )


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
    agents=None,
    notify=None,
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
    checks.extend(_kernel_checks(base, controllers, system_root, cfg))
    checks.append(_oom_handler_check(units, system_root, uid))
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
    if agents is not None:
        checks.append(_agent_check(agents))
    checks.append(_notify_check(cfg, notify))
    checks.append(_desktop_check(cfg))
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


def _repair_dirs(cfg, fixes):
    """Create missing state/config/hooks directories and enforce their modes."""
    paths = cfg.get("paths", {})
    if not isinstance(paths, dict):
        paths = {}
    targets = []
    state_dir = paths.get("state_dir")
    if isinstance(state_dir, str) and state_dir:
        targets.append((policy.expand(state_dir), 0o700, "state dir"))
    config_dir = policy.user_config_dir()
    targets.append((config_dir, 0o700, "config dir"))
    hooks_dir = paths.get("hooks_dir")
    if isinstance(hooks_dir, str) and hooks_dir:
        targets.append((policy.expand(hooks_dir), 0o755, "hooks dir"))
    for path, mode, name in targets:
        try:
            if not os.path.isdir(path):
                os.makedirs(path, mode=mode, exist_ok=True)
                os.chmod(path, mode)
                fixes.append(
                    {"name": name, "status": "fixed", "message": "created %s" % path}
                )
            elif stat.S_IMODE(os.stat(path).st_mode) != mode:
                os.chmod(path, mode)
                fixes.append(
                    {
                        "name": name,
                        "status": "fixed",
                        "message": "set mode %04o on %s" % (mode, path),
                    }
                )
            else:
                fixes.append(
                    {
                        "name": name,
                        "status": "skipped",
                        "message": "%s already present with mode %04o" % (path, mode),
                    }
                )
        except OSError as error:
            fixes.append({"name": name, "status": "fail", "message": str(error)})


_DESIRED_CONTROLLERS = ("cpu", "io", "memory", "pids")


def _legacy_marker_present(dbpath):
    try:
        uri = "file:%s?mode=ro" % quote(os.path.abspath(dbpath))
        connection = sqlite3.connect(uri, uri=True)
        try:
            row = connection.execute(
                "SELECT value FROM meta WHERE key = 'migration.legacy_import'"
            ).fetchone()
        finally:
            connection.close()
        return row is not None
    except (OSError, sqlite3.Error, TypeError, IndexError):
        return False


def _schema_version(dbpath):
    try:
        uri = "file:%s?mode=ro" % quote(os.path.abspath(dbpath))
        connection = sqlite3.connect(uri, uri=True)
        try:
            row = connection.execute("PRAGMA user_version").fetchone()
        finally:
            connection.close()
        return row[0] if row else None
    except (OSError, sqlite3.Error, TypeError, IndexError):
        return None


def _repair_store(cfg, fixes):
    from .store import db as db_mod
    from .store import knowledge as knowledge_mod

    paths = cfg.get("paths", {})
    if not isinstance(paths, dict):
        paths = {}
    state_dir_value = paths.get("state_dir")
    if not isinstance(state_dir_value, str) or not state_dir_value:
        fixes.append(
            {
                "name": "store migration",
                "status": "skipped",
                "message": "no state dir configured; nothing to migrate",
            }
        )
        return None
    state_dir = policy.expand(state_dir_value)
    legacy = os.path.join(state_dir, "knowledge.json")
    dbpath = os.path.join(state_dir, "state.db")
    if _legacy_marker_present(dbpath):
        fixes.append(
            {
                "name": "store migration",
                "status": "skipped",
                "message": "legacy store already imported",
            }
        )
        return state_dir
    version = _schema_version(dbpath) if os.path.isfile(dbpath) else None
    if (
        not os.path.isfile(legacy)
        and version is not None
        and version >= db_mod.SCHEMA_VERSION
    ):
        fixes.append(
            {
                "name": "store migration",
                "status": "skipped",
                "message": "store schema is current; nothing to migrate",
            }
        )
        return state_dir
    try:
        knowledge_mod.Store(state_dir, cfg.get("seeds") or {})
    except Exception as error:
        fixes.append(
            {"name": "store migration", "status": "fail", "message": str(error)}
        )
        return None
    fixes.append(
        {
            "name": "store migration",
            "status": "fixed",
            "message": "opened the store so pending migrations apply",
        }
    )
    return state_dir


def _runtime_hold_marker():
    runtime = os.environ.get("XDG_RUNTIME_DIR") or "/run/user/%d" % os.getuid()
    return os.path.join(runtime, "taema", "HOLD")


def _repair_stale_flags(state_dir, store, fixes):
    removed = []
    failed = []
    if state_dir is not None:
        try:
            exports = sorted(
                name
                for name in os.listdir(state_dir)
                if name.startswith("state-export-") and name.endswith(".json")
            )
        except OSError:
            exports = []
        for name in exports[:-3]:
            path = os.path.join(state_dir, name)
            try:
                os.unlink(path)
                removed.append(name)
            except OSError as error:
                failed.append("%s: %s" % (name, error))
    marker = _runtime_hold_marker()
    marker_handled = False
    try:
        with open(marker, encoding="utf-8") as stream:
            marker_value = stream.read()
    except FileNotFoundError:
        marker_value = None
    except OSError:
        marker_value = "unreadable"
    if marker_value is None:
        pass
    elif marker_value == "unreadable":
        fixes.append(
            {
                "name": "stale flags",
                "status": "skipped",
                "message": "hold marker is unreadable; left in place",
            }
        )
        marker_handled = True
    else:
        try:
            claimed = json.loads(marker_value) if marker_value else {}
        except ValueError:
            claimed = {}
        active_claim = (
            claimed.get("held") is True if isinstance(claimed, dict) else True
        )
        if isinstance(claimed, dict):
            snooze = claimed.get("snooze_until")
            if (
                isinstance(snooze, (int, float))
                and not isinstance(snooze, bool)
                and snooze > time.time()
            ):
                active_claim = True
        hold_active = False
        if active_claim:
            if store is not None:
                try:
                    hold_active = bool(store.hold_reason())
                except Exception:
                    hold_active = True
            else:
                hold_active = True
        if hold_active:
            fixes.append(
                {
                    "name": "stale flags",
                    "status": "skipped",
                    "message": "hold marker reflects an active hold; left in place",
                }
            )
            marker_handled = True
        else:
            try:
                os.unlink(marker)
                removed.append("hold marker")
            except OSError as error:
                failed.append("hold marker: %s" % error)
    if failed:
        fixes.append(
            {
                "name": "stale flags",
                "status": "fail",
                "message": "; ".join(failed),
            }
        )
    elif removed:
        fixes.append(
            {
                "name": "stale flags",
                "status": "fixed",
                "message": "removed %s" % ", ".join(sorted(removed)),
            }
        )
    elif not marker_handled:
        fixes.append(
            {
                "name": "stale flags",
                "status": "skipped",
                "message": "no stale exports or hold markers",
            }
        )


def _repair_autostart(fixes, system_root):
    from . import desktop as desktop_mod

    config_home = policy.xdg("XDG_CONFIG_HOME", "~/.config")
    status, message = desktop_mod.ensure_agent_autostart(
        system_root=system_root, config_home=config_home
    )
    if status == "skipped" and message == "packaged autostart snippet not found":
        message = "packaged autostart snippet not found; install the taema package"
    fixes.append({"name": "agent autostart", "status": status, "message": message})


def _default_runner(argv):
    return subprocess.run(argv, capture_output=True, text=True, timeout=30)


def _repair_controllers(uid, fixes, sudo, runner):
    from .core import cgroup as cgroup_mod

    resolved = os.getuid() if uid is None else uid
    control = os.path.join(cgroup_mod.base(resolved), "cgroup.subtree_control")
    try:
        with open(control, encoding="utf-8") as stream:
            enabled = {token.lstrip("+") for token in stream.read().split() if token}
    except OSError:
        fixes.append(
            {
                "name": "controllers",
                "status": "skipped",
                "message": "user subtree has no subtree_control; start the service first",
            }
        )
        return
    missing = [name for name in _DESIRED_CONTROLLERS if name not in enabled]
    if not missing:
        fixes.append(
            {
                "name": "controllers",
                "status": "skipped",
                "message": "delegated controllers already include %s"
                % " ".join(_DESIRED_CONTROLLERS),
            }
        )
        return
    fragment = " ".join("+" + name for name in missing)
    command = ["sudo", "sh", "-c", "echo '%s' > %s" % (fragment, control)]
    try:
        with open(control, "w", encoding="utf-8") as stream:
            stream.write(
                " ".join(
                    "+" + name for name in sorted(enabled | set(missing), key=str.lower)
                )
                + "\n"
            )
    except OSError:
        if sudo:
            run = runner or _default_runner
            try:
                result = run(command)
            except (OSError, subprocess.SubprocessError) as error:
                fixes.append(
                    {"name": "controllers", "status": "fail", "message": str(error)}
                )
                return
            if getattr(result, "returncode", 1) == 0:
                fixes.append(
                    {
                        "name": "controllers",
                        "status": "fixed",
                        "message": "enabled %s via %s"
                        % (" ".join(missing), shlex.join(command)),
                    }
                )
            else:
                fixes.append(
                    {
                        "name": "controllers",
                        "status": "fail",
                        "message": "root command exited %s"
                        % getattr(result, "returncode", "?"),
                        "command": command,
                    }
                )
        else:
            fixes.append(
                {
                    "name": "controllers",
                    "status": "needs-root",
                    "message": "subtree_control is not writable; enable %s"
                    % " ".join(missing),
                    "command": command,
                }
            )
        return
    fixes.append(
        {
            "name": "controllers",
            "status": "fixed",
            "message": "enabled %s on the delegated subtree" % " ".join(missing),
        }
    )


def repair(cfg, store=None, *, system_root="/", uid=None, sudo=False, runner=None):
    """Apply the safe subset of doctor fixes and report each one.

    Read-only checks stay untouched: this only creates missing directories,
    repairs ownership-safe permissions, enables delegated controllers where
    writable, installs the session-agent autostart entry, opens the store so
    pending migrations apply, and prunes stale state exports and hold
    markers. Anything needing root is reported with its command and runs
    only when ``sudo`` is true. Every entry is ``{"name", "status",
    "message"[, "command"]}`` with status one of ``fixed``, ``skipped``,
    ``needs-root``, or ``fail``. Running repair twice changes nothing the
    second time.
    """
    fixes = []
    _repair_dirs(cfg, fixes)
    _repair_controllers(uid, fixes, sudo, runner)
    _repair_autostart(fixes, system_root)
    state_dir = _repair_store(cfg, fixes)
    _repair_stale_flags(state_dir, store, fixes)
    return fixes


def render_repair(fixes):
    """Render one line per applied or pending fix."""
    lines = ["doctor --fix: %d action(s)" % len(fixes)]
    for item in fixes:
        line = "[%s] %s: %s" % (
            item["status"],
            item["name"],
            item["message"],
        )
        if item["status"] == "needs-root" and item.get("command"):
            command = item["command"]
            if not isinstance(command, str):
                command = shlex.join(command)
            line += " — run: %s" % command
        lines.append(line)
    return "\n".join(lines) + "\n"
