"""Stable application identities resolved from process evidence.

Identity keys are authority-bearing: display names are metadata and never substitute for the
executable, script, runtime, or unit evidence that created the key.
"""

from dataclasses import dataclass
import hashlib
import os
import re

_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_NUMERIC = re.compile(r"^[0-9]")
_INTERPRETERS = (
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
_INTERP_PREFIXES = ("python", "lua", "php")
_VERSIONED = re.compile(r"^(python3?|lua|php|nodejs)[0-9.]*$")
_SHELLS = {"sh", "bash", "dash", "zsh", "fish"}
_TRIVIAL = {"sleep", "cat", "head", "sort", "grep", "true"}
_THREAD_NAMES = {"MainThread", "GC", "Finalizer"}
_JAVA_VALUE_OPTS = {"-cp", "-classpath", "--class-path", "-p", "--module-path"}
_CONTAINER_CGROUP = re.compile(
    r"(?:libpod|docker|cri-containerd|crio)[-/]([0-9a-f]{12,64})(?:\.scope)?",
    re.IGNORECASE,
)
_QEMU_EXE = re.compile(r"^qemu-system(?:-|$)")


@dataclass(frozen=True)
class IdentityHints:
    """Optional names supplied by a future desktop agent or launch integration."""

    desktop_id: str | None = None
    launch_name: str | None = None

    @property
    def display_name(self):
        return _clean_name(self.launch_name or self.desktop_id)


@dataclass(frozen=True)
class ProcessFacts:
    """Evidence needed by the pure identity resolver; paths are never persisted verbatim."""

    comm: str = ""
    exe: str = ""
    device: int | None = None
    inode: int | None = None
    argv: tuple[str, ...] = ()
    cwd: str = ""
    cgroup: str = ""
    sockets: tuple[str, ...] = ()
    unit: str | None = None
    runtime_class: str | None = None
    runtime_id: str | None = None


@dataclass(frozen=True)
class AppIdentity:
    key: str
    display: str
    kind: str
    exe: str = ""
    device: int | None = None
    inode: int | None = None
    desktop_id: str | None = None
    unit: str | None = None
    runtime: str | None = None
    validated: bool = True
    reason: str = ""
    launch_name: str | None = None


def _clean_name(value, limit=128):
    if not isinstance(value, str):
        return ""
    return _CONTROL.sub("", value).strip()[:limit]


def _canonical_interpreter(base):
    if base in _INTERPRETERS:
        return "node" if base == "nodejs" else base
    if base.startswith(_INTERP_PREFIXES):
        match = _VERSIONED.fullmatch(base)
        if match:
            return {"nodejs": "node"}.get(match.group(1), match.group(1))
    return None


def _script_of(interpreter, argv):
    args = list(argv[1:]) if argv else []
    index = 0
    while index < len(args):
        value = args[index]
        if value in ("-c", "-e", "--eval", "-p", "--print") and interpreter != "java":
            return ""
        if value == "-m" and interpreter.startswith("python"):
            return "module:" + args[index + 1] if index + 1 < len(args) else ""
        if (
            value.startswith("-m")
            and interpreter.startswith("python")
            and len(value) > 2
            and not value.startswith("--")
        ):
            return "module:" + value[2:]
        if value == "-jar" and interpreter == "java":
            return args[index + 1] if index + 1 < len(args) else ""
        if interpreter == "java" and value in _JAVA_VALUE_OPTS:
            index += 2
            continue
        if value.startswith("-"):
            index += 1
            continue
        return value
    return ""


def _script_identity(interpreter, script, cwd):
    if not script:
        return "", ""
    if script.startswith("module:"):
        location = "%s@%s" % (script, os.path.realpath(cwd or "."))
    elif interpreter == "java" and "." in script and not script.endswith(".jar"):
        location = "class:%s@%s" % (script, os.path.realpath(cwd or "."))
    else:
        path = script if os.path.isabs(script) else os.path.join(cwd or ".", script)
        location = os.path.realpath(path)
    label = os.path.basename(script.rstrip("/")) or script
    if label.startswith("module:"):
        label = label.partition(":")[2]
    if interpreter == "java" and "." in script and not script.endswith(".jar"):
        label = script.rsplit(".", 1)[-1]
    digest = hashlib.sha256(location.encode("utf-8", errors="replace")).hexdigest()[:12]
    return label[:96], digest


def _runtime(facts, base):
    runtime = _clean_name(facts.runtime_class, 32).lower()
    locator = _clean_name(facts.runtime_id, 256)
    cgroup = facts.cgroup or ""
    sockets = tuple(_clean_name(path, 512) for path in facts.sockets if path)

    if not runtime:
        match = _CONTAINER_CGROUP.search(cgroup)
        if match:
            runtime, locator = "container", match.group(1).lower()
        elif base == "conmon":
            runtime = "container"
            for index, arg in enumerate(facts.argv):
                if arg in ("-c", "--cid") and index + 1 < len(facts.argv):
                    locator = facts.argv[index + 1]
                    break
        elif (
            _QEMU_EXE.match(base)
            or "libvirt/qemu" in cgroup
            or "machine.slice" in cgroup
        ):
            runtime = "qemu"

    if not runtime:
        return None
    if not locator:
        locator = next(
            (
                arg.split("unix:", 1)[1].split(",", 1)[0]
                for index, arg in enumerate(facts.argv)
                if arg in ("-qmp", "-monitor")
                and index + 1 < len(facts.argv)
                and "unix:" in facts.argv[index + 1]
            ),
            "",
        )
    if not locator:
        locator = next(
            (
                path
                for path in sockets
                if any(
                    term in path.lower()
                    for term in ("qmp", "qemu", "libvirt", "podman", "docker")
                )
            ),
            "",
        )
    if not locator and cgroup:
        locator = cgroup
    if not locator:
        return None

    digest = hashlib.sha256((runtime + "\0" + locator).encode()).hexdigest()[:16]
    leaf = os.path.basename(locator.rstrip("/"))
    if locator.startswith("/") and leaf:
        label = "%s:%s" % (runtime, leaf[:64])
    else:
        label = "%s:%s" % (runtime, locator[:64])
    return runtime, digest, label


def _is_owner_name(comm, exe_base, has_script):
    name = _clean_name(comm, 128)
    base = exe_base.lower()
    if not name or len(name) > 15:
        return "missing or overlong comm"
    if _NUMERIC.match(name):
        return "name starts with a digit"
    if name in _THREAD_NAMES or name.startswith(("Thread-", "pool-")):
        return "generic thread name %s" % name
    if name in _SHELLS:
        return "shell %s" % name
    if name in _TRIVIAL:
        return "trivial command %s" % name
    interpreter = _canonical_interpreter(name)
    if interpreter and not has_script:
        return "interpreter %s without a script" % (base or name)
    return ""


def _decorated_key(key, hints):
    if not hints:
        return key
    name = _clean_name(hints.desktop_id or hints.launch_name, 96)
    if not name:
        return key
    source = "desktop" if hints.desktop_id else "launch"
    return "%s:%s|%s" % (source, name.replace("|", "")[:96], key)


def resolve_identity(facts, hints=None):
    """Resolve immutable process evidence into one stable identity and display name."""
    hints = hints or IdentityHints()
    exe_path = (facts.exe or "").removesuffix(" (deleted)")
    base = os.path.basename(exe_path)
    comm = _clean_name(facts.comm)
    display_hint = hints.display_name
    desktop_id = _clean_name(hints.desktop_id, 128) or None

    # An explicit unit is the strongest application identity and deliberately keeps its name.
    if facts.unit:
        unit = _clean_name(facts.unit, 256)
        if unit:
            return AppIdentity(
                "unit:" + unit,
                display_hint or unit,
                "unit",
                base,
                facts.device,
                facts.inode,
                desktop_id,
                unit,
                launch_name=_clean_name(hints.launch_name, 128) or None,
            )

    interpreter = _canonical_interpreter(base)
    script = _script_of(interpreter, facts.argv) if interpreter else ""
    # Interpreter identities include resolved project location, so equal basenames do not collide.
    if interpreter and script:
        label, digest = _script_identity(interpreter, script, facts.cwd)
        key = "script:%s:%s:%s" % (interpreter, label, digest)
        invalid = _is_owner_name(comm, base, True)
        if invalid:
            key = "invalid:" + key
        return AppIdentity(
            _decorated_key(key, hints),
            display_hint or label or base or comm,
            "script",
            base,
            facts.device,
            facts.inode,
            desktop_id,
            validated=not invalid,
            reason=invalid,
            launch_name=_clean_name(hints.launch_name, 128) or None,
        )

    if interpreter and not script and comm and comm != base[:15]:
        invalid = _is_owner_name(comm, base, False)
        key = comm if not invalid else "invalid:comm:" + comm
        return AppIdentity(
            _decorated_key(key, hints),
            display_hint or comm,
            "comm",
            base,
            facts.device,
            facts.inode,
            desktop_id,
            validated=not invalid,
            reason=invalid,
            launch_name=_clean_name(hints.launch_name, 128) or None,
        )

    runtime = _runtime(facts, base)
    if runtime:
        runtime_name, digest, label = runtime
        key = "runtime:%s:%s" % (runtime_name, digest)
        invalid = _is_owner_name(comm, base, False)
        if invalid:
            key = "invalid:" + key
        return AppIdentity(
            _decorated_key(key, hints),
            display_hint or label,
            "runtime",
            base,
            facts.device,
            facts.inode,
            desktop_id,
            runtime=runtime_name,
            validated=not invalid,
            reason=invalid,
            launch_name=_clean_name(hints.launch_name, 128) or None,
        )

    if base and facts.device is not None and facts.inode is not None:
        key = "exe:%s:%d:%d" % (base[:96], facts.device, facts.inode)
        invalid = _is_owner_name(comm, base, False)
        if invalid:
            key = "invalid:" + key
        return AppIdentity(
            _decorated_key(key, hints),
            display_hint or base,
            "exe",
            base,
            facts.device,
            facts.inode,
            desktop_id,
            validated=not invalid,
            reason=invalid,
            launch_name=_clean_name(hints.launch_name, 128) or None,
        )

    invalid = _is_owner_name(comm, base, False)
    key = comm or "unknown"
    if invalid:
        key = "invalid:comm:" + key
    return AppIdentity(
        _decorated_key(key, hints),
        display_hint or comm or base or "unknown",
        "comm",
        base,
        facts.device,
        facts.inode,
        desktop_id,
        validated=not invalid,
        reason=invalid,
        launch_name=_clean_name(hints.launch_name, 128) or None,
    )


def _matching_unit(cgroup, units):
    leaf = os.path.basename((cgroup or "").rstrip("/"))
    for item in units or ():
        unit = item.get("unit") or {}
        name = unit.get("name")
        if (
            isinstance(name, str)
            and name
            and (
                leaf == name
                or (unit.get("kind") == "app" and leaf.startswith(name + "-"))
            )
        ):
            return name
    return None


def resolve_process(pid, units=(), hints=None):
    """Collect bounded /proc facts and resolve a process without invoking runtime CLIs."""
    from . import cgroup, process

    exe_path = process.exe(pid)
    stat = None
    try:
        stat = os.stat("%s/%d/exe" % (process.PROC, pid))
    except OSError:
        pass
    argv = tuple(
        item.decode(errors="replace")
        for item in process.read(pid, "cmdline").split(b"\0")
        if item
    )
    try:
        cwd = os.readlink("%s/%d/cwd" % (process.PROC, pid))
    except OSError:
        cwd = ""
    cgroup_path = cgroup.proc_cgroup(pid) or ""
    base = os.path.basename(exe_path)
    if (
        _QEMU_EXE.match(base)
        or "conmon" in base
        or any(
            marker in cgroup_path.lower()
            for marker in ("libpod", "docker", "libvirt", "machine.slice")
        )
    ):
        sockets = tuple(process.unix_socket_paths(pid))
    else:
        sockets = ()
    facts = ProcessFacts(
        comm=process.comm(pid),
        exe=exe_path,
        device=stat.st_dev if stat else None,
        inode=stat.st_ino if stat else None,
        argv=argv,
        cwd=cwd,
        cgroup=cgroup_path,
        sockets=sockets,
        unit=_matching_unit(cgroup_path, units),
    )
    return resolve_identity(facts, hints)
