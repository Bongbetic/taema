"""One-shot first-run wizard: `taema setup` (issue #81)."""

import os
import shutil

SETUP_DROPIN_NAME = "40-setup.toml"
SETUP_HEADER = (
    "# managed by taema setup; edit with `taema config` to keep changes validated\n"
)

AUTO_BLURB = (
    "auto cleans up idle leftovers on its own once learning has answered pairs. "
    "It only acts with an authorization reason and never stops unlearned leftovers silently."
)
ADOPT_BLURB = (
    "adopt contains every eligible app and asks before stopping anything unknown. "
    "It is the cautious default: nothing is stopped without your explicit answer."
)


def _ask_choice(prompt, options, default, yes, input_fn):
    if yes:
        return default
    ask = input_fn or input
    try:
        answer = ask("%s [%s] (default: %s): " % (prompt, "/".join(options), default))
    except (EOFError, OSError):
        return default
    answer = (answer or "").strip().lower()
    return answer if answer in options else default


def _ask_yes_no(prompt, default_yes, yes, input_fn):
    if yes:
        return default_yes
    ask = input_fn or input
    hint = "Y/n" if default_yes else "y/N"
    try:
        answer = ask("%s [%s]: " % (prompt, hint)).strip().lower()
    except (EOFError, OSError):
        return default_yes
    if not answer:
        return default_yes
    return answer in ("y", "yes")


RUNTIME_PACKS = (
    ("podman", "podman"),
    ("docker", "docker-rootless"),
    ("virsh", "libvirt-qemu"),
    ("qemu-system-x86_64", "libvirt-qemu"),
    ("incus", "incus"),
    ("VBoxManage", "virtualbox"),
    ("steam", "steam"),
    ("discord", "discord"),
    ("emulator", "android-emulator"),
    ("code", "vscode"),
)


def run_setup(
    cfg,
    store,
    *,
    system_root="/",
    proc_root=None,
    yes=False,
    input_fn=None,
    which=None,
    backend=None,
):
    """Walk a new user to a working setup; return a step report.

    Writes only the setup drop-in, user units, and autostart entries.
    Root-only actions are printed, never run. Idempotent: a second run
    with the same answers changes nothing.
    """
    from .config import policy as policy_mod

    report = {"steps": [], "wrote": [], "root_commands": []}

    _step_doctor(cfg, report, system_root)
    _step_mode(cfg, report, yes, input_fn, policy_mod)
    _step_runtimes(cfg, report, yes, input_fn, policy_mod, which)
    _step_desktop(cfg, store, report, yes, input_fn, policy_mod, which)
    _step_hooks(cfg, report, system_root)
    _step_notify(cfg, report, yes, backend)
    _step_memory(cfg, report, system_root, proc_root)
    _step_oom(cfg, report, proc_root)
    return report


def _read_text(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as stream:
            return stream.read()
    except OSError:
        return None


def _step_memory(cfg, report, system_root, proc_root):
    del cfg
    from .governor import guard as guard_mod

    available, total = guard_mod.host_memory(proc_root)
    swaps_text = _read_text(os.path.join(system_root, "proc", "swaps"))
    swaps = (
        [line.split()[0] for line in swaps_text.splitlines()[1:] if line.split()]
        if swaps_text is not None
        else []
    )
    zswap = None
    for candidate in (
        "sys/module/zswap/parameters/enabled",
        "sys/kernel/mm/zswap/enabled",
    ):
        text = _read_text(os.path.join(system_root, candidate))
        if text is not None:
            zswap = text.strip().lower() in ("y", "1", "yes")
            break
    parts = []
    if total:
        parts.append(
            "RAM total %d GiB, available %d GiB"
            % (total // 2**30, (available or 0) // 2**30)
        )
    else:
        parts.append("RAM size unreadable")
    parts.append("swap: %s" % (", ".join(swaps) if swaps else "none"))
    parts.append(
        "zswap: %s" % ("on" if zswap else "off" if zswap is False else "unknown")
    )
    if swaps and zswap is False:
        report["root_commands"].append(
            "sudo sh -c 'echo Y > /sys/module/zswap/parameters/enabled'"
        )
        parts.append(
            "enable zswap to compress swap before it hits disk (see root command)"
        )
    report["steps"].append(
        {"name": "memory", "status": "ok", "message": "; ".join(parts)}
    )


def _step_oom(cfg, report, proc_root):
    del cfg
    from .governor import guard as guard_mod

    try:
        handlers = guard_mod.detect_oom_handlers(proc_root)
    except Exception:
        handlers = {}
    earlyoom = handlers.get("earlyoom", [])
    lines = [
        "earlyoom kills the largest process when memory runs out; "
        "taema downgrades and reclaims under pressure first so the killer stays idle"
    ]
    if not earlyoom:
        lines.append("no earlyoom process running")
    for handler in earlyoom:
        lines.append(
            "earlyoom pid %d kills below %s%% memory%s"
            % (
                handler.pid,
                handler.option("-m") or "?",
                (
                    "; --prefer %s keeps pressure kills off everything else"
                    % handler.option("--prefer")
                    if handler.option("--prefer")
                    else "; add --prefer for managed hogs to keep pressure kills narrow"
                ),
            )
        )
    report["steps"].append({"name": "oom", "status": "ok", "message": " ".join(lines)})


def _rooted(root, path):
    return os.path.join(root, path.lstrip("/"))


def _step_hooks(cfg, report, system_root):
    del cfg
    wanted = {
        "bash hook": "/etc/bash/bashrc.d/taema.sh",
        "fish hook": "/usr/share/fish/vendor_conf.d/taema.fish",
        "hook binary": "/usr/libexec/taema/taema-hook",
    }
    missing = [
        label
        for label, path in wanted.items()
        if not os.path.isfile(_rooted(system_root, path))
    ]
    if not missing:
        report["steps"].append(
            {"name": "hooks", "status": "ok", "message": "shell hooks installed"}
        )
        return
    report["steps"].append(
        {
            "name": "hooks",
            "status": "warn",
            "message": "missing system files: %s" % ", ".join(missing),
        }
    )
    report["root_commands"].append("sudo xbps-install -f taema")


def _step_notify(cfg, report, yes, backend):
    from . import notify as notify_mod

    configured = {}
    if isinstance(cfg, dict) and isinstance(cfg.get("notify"), dict):
        configured = cfg["notify"]
    if backend is None:
        try:
            backend = notify_mod.select_backend(configured.get("backend", "auto"))
        except Exception as error:
            report["steps"].append(
                {"name": "notify", "status": "fail", "message": str(error)}
            )
            return
    name = getattr(backend, "name", "?")
    if name == "null":
        report["steps"].append(
            {
                "name": "notify",
                "status": "skipped",
                "message": "no notification server found; install libnotify or start a desktop session",
            }
        )
        return
    try:
        receipt = backend.send(
            "taema setup",
            "Reply Stop to confirm setup notifications reach you.",
            actions=[("stop", "Stop"), ("ok", "Looks good")],
            wait=not yes,
        )
    except Exception as error:
        report["steps"].append(
            {"name": "notify", "status": "fail", "message": str(error)}
        )
        return
    if yes:
        report["steps"].append(
            {
                "name": "notify",
                "status": "fixed",
                "message": "test notification sent via %s; confirm it arrived" % name,
            }
        )
        return
    try:
        outcome, detail = backend.wait_for_action(receipt, 60)
    except Exception as error:
        report["steps"].append(
            {"name": "notify", "status": "fail", "message": str(error)}
        )
        return
    if outcome == "timeout":
        report["steps"].append(
            {
                "name": "notify",
                "status": "warn",
                "message": "test notification sent via %s but no reply in 60s" % name,
            }
        )
    else:
        report["steps"].append(
            {
                "name": "notify",
                "status": "fixed",
                "message": "test notification confirmed via %s (%s)" % (name, outcome),
            }
        )


def _detect_desktop():
    current = os.environ.get("XDG_CURRENT_DESKTOP", "")
    if current:
        return current.split(":")[0]
    if os.environ.get("NIRI_SOCKET") or "niri" in os.environ.get("WAYLAND_DISPLAY", ""):
        return "niri"
    return ""


def _widget_source():
    candidates = [
        "/usr/share/examples/taema/widgets",
        os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "..",
            "widgets",
            "taema-bar",
        ),
    ]
    for candidate in candidates:
        normalized = os.path.normpath(candidate)
        if os.path.isdir(normalized):
            return normalized
    return None


def _step_desktop(cfg, store, report, yes, input_fn, policy_mod, which):
    from . import desktop as desktop_mod
    from . import suggest as suggest_mod

    desktop = _detect_desktop()
    find = which or shutil.which
    config_home = policy_mod.xdg("XDG_CONFIG_HOME", "~/.config")
    if _ask_yes_no(
        "install the session-agent autostart entry%s"
        % (" for %s" % desktop if desktop else ""),
        True,
        yes,
        input_fn,
    ):
        status, message = desktop_mod.ensure_agent_autostart(config_home=config_home)
        report["steps"].append(
            {"name": "autostart", "status": status, "message": message}
        )
        if status == "fixed":
            report["wrote"].append(
                os.path.join(config_home, "autostart", desktop_mod.AUTOSTART_FILENAME)
            )
    else:
        report["steps"].append(
            {
                "name": "autostart",
                "status": "skipped",
                "message": "declined autostart install",
            }
        )
    if desktop.lower() == "niri":
        report["steps"].append(
            {
                "name": "autostart",
                "status": "skipped",
                "message": "niri: copy the spawn-at-startup line from the packaged niri-taema-agent.kdl into your niri config",
            }
        )
    try:
        quickshell = bool(find("quickshell"))
    except Exception:
        quickshell = False
    source = _widget_source()
    if (
        quickshell
        and source is not None
        and _ask_yes_no("show how to install the taema bar widget", True, yes, input_fn)
    ):
        target_dir = os.path.join(config_home, "quickshell", "taema")
        report["steps"].append(
            {
                "name": "widget",
                "status": "fixed",
                "message": "install the widget with: mkdir -p %s && cp %s/*.qml %s/"
                % (target_dir, source, target_dir),
            }
        )
    else:
        reason = "widget declined"
        if not quickshell:
            reason = "quickshell not found"
        elif source is None:
            reason = "widget sources not packaged"
        report["steps"].append(
            {"name": "widget", "status": "skipped", "message": reason}
        )
    try:
        candidates = [
            item for item in suggest_mod.rank(store, cfg) if item["kind"] == "wrap"
        ]
    except Exception:
        candidates = []
    candidates.sort(
        key=lambda item: item.get("payload", {}).get("launches", 0), reverse=True
    )
    top = candidates[:3]
    if top and _ask_yes_no(
        "wrap frequently launched apps (%s)"
        % ", ".join(item["payload"].get("app", "?") for item in top),
        True,
        yes,
        input_fn,
    ):
        for item in top:
            ok, message = suggest_mod.apply_suggestion(store, cfg, item)
            if ok:
                report["wrote"].append(item["payload"].get("file", ""))
            report["steps"].append(
                {
                    "name": "wrap",
                    "status": "fixed" if ok else "fail",
                    "message": message,
                }
            )
    else:
        report["steps"].append(
            {
                "name": "wrap",
                "status": "skipped",
                "message": "no wrappable apps or declined",
            }
        )


def _step_runtimes(cfg, report, yes, input_fn, policy_mod, which):
    find = which or shutil.which
    wanted = []
    for binary, pack in RUNTIME_PACKS:
        try:
            present = bool(find(binary))
        except Exception:
            present = False
        if present and pack not in wanted:
            wanted.append(pack)
    if not wanted:
        report["steps"].append(
            {
                "name": "runtimes",
                "status": "skipped",
                "message": "no supported runtimes found",
            }
        )
        return
    if not _ask_yes_no(
        "install units for detected runtimes (%s)" % ", ".join(wanted),
        True,
        yes,
        input_fn,
    ):
        report["steps"].append(
            {
                "name": "runtimes",
                "status": "skipped",
                "message": "declined pack install",
            }
        )
        return
    units_dir = os.path.join(policy_mod.user_config_dir(), "units")
    installed = []
    for pack in wanted:
        source = policy_mod.pack_source(pack)
        if source is None:
            report["steps"].append(
                {
                    "name": "runtimes",
                    "status": "fail",
                    "message": "pack missing: %s" % pack,
                }
            )
            continue
        ok, message, target = policy_mod.install_pack_file(source, units_dir, pack)
        if ok:
            installed.append(target)
            report["wrote"].append(target)
        elif "already exists" in message or "exists:" in message:
            pass
        else:
            report["steps"].append(
                {"name": "runtimes", "status": "fail", "message": message}
            )
    if installed:
        report["steps"].append(
            {
                "name": "runtimes",
                "status": "fixed",
                "message": "installed units: %s" % ", ".join(installed),
            }
        )
    else:
        report["steps"].append(
            {
                "name": "runtimes",
                "status": "skipped",
                "message": "runtime units already installed",
            }
        )


def _step_doctor(cfg, report, system_root):
    from . import doctor as doctor_mod

    try:
        result = doctor_mod.diagnose(cfg, None, [], system_root=system_root)
    except Exception as error:
        report["steps"].append(
            {"name": "doctor", "status": "fail", "message": str(error)}
        )
        return
    bad = [item for item in result.get("checks", []) if item.get("status") != "ok"]
    if not bad:
        report["steps"].append(
            {"name": "doctor", "status": "ok", "message": "all checks pass"}
        )
        return
    lines = "; ".join(
        "%s: %s (fix: %s)" % (item["name"], item["message"], item["fix"])
        for item in bad
    )
    report["steps"].append({"name": "doctor", "status": "warn", "message": lines})


def _step_mode(cfg, report, yes, input_fn, policy_mod):
    dropin_dir = os.path.join(policy_mod.user_config_dir(), "taema.d")
    target = os.path.join(dropin_dir, SETUP_DROPIN_NAME)
    if os.path.isfile(target):
        report["steps"].append(
            {
                "name": "mode",
                "status": "skipped",
                "message": "setup drop-in already present",
            }
        )
        return
    choice = _ask_choice(
        "mode (%s. %s)" % (AUTO_BLURB, ADOPT_BLURB),
        ("auto", "adopt"),
        "adopt",
        yes,
        input_fn,
    )
    try:
        os.makedirs(dropin_dir, mode=0o700, exist_ok=True)
        os.chmod(dropin_dir, 0o700)
        with open(target, "w", encoding="utf-8") as stream:
            stream.write(SETUP_HEADER)
            stream.write('mode = "%s"\n' % choice)
        os.chmod(target, 0o600)
    except OSError as error:
        report["steps"].append(
            {"name": "mode", "status": "fail", "message": str(error)}
        )
        return
    report["wrote"].append(target)
    report["steps"].append(
        {"name": "mode", "status": "fixed", "message": "chose mode %s" % choice}
    )
