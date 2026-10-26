"""Small, reversible cgroup-v2 CPU and IO priority operations."""

import os
from dataclasses import dataclass


DEBOUNCE_SECONDS = 2.0
BACKGROUND_SAMPLE_SECONDS = 5.0
BACKGROUND_CPU_PERCENT = 1.0
CONTROLLER_RETRY_SECONDS = 15.0
CONTROLLERS = ("cpu", "io")


@dataclass(frozen=True, slots=True)
class ResourceWrite:
    name: str
    value: str
    original: str


@dataclass(frozen=True, slots=True)
class QoSPlan:
    writes: tuple[ResourceWrite, ...]
    available: tuple[str, ...]


def classify(scope, idle_since, now):
    """Return the resource class warranted by a managed cgroup's current evidence."""
    if scope.startswith("leftover/"):
        return "leftover"
    if scope.startswith("shared/"):
        return "shared"
    if "/" not in scope and scope.startswith(("app-", "scope-")):
        first_idle = idle_since.get(scope)
        if first_idle is not None and now - first_idle >= DEBOUNCE_SECONDS:
            return "background"
    return None


def _read(path):
    with open(path, encoding="ascii") as source:
        return source.read()


def _default_io_weight(value):
    for line in value.splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[0] == "default" and fields[1].isdecimal():
            weight = int(fields[1])
            if 1 <= weight <= 10000:
                return weight
    return None


def _with_default_io_weight(value, weight):
    if _default_io_weight(value) is None:
        return None
    # io.weight is a command interface: each write accepts one command. Writing a
    # reconstructed file would send device overrides as one malformed command.
    return "default %d" % weight


def _targets(scope_class, path, focus_weight=None):
    targets = []
    cpu_idle = os.path.join(path, "cpu.idle")
    cpu_weight = os.path.join(path, "cpu.weight")
    if scope_class == "foreground":
        if focus_weight is not None and os.path.isfile(cpu_weight):
            targets.append(("cpu.weight", str(focus_weight)))
        return tuple(targets)
    if scope_class == "leftover":
        if os.path.isfile(cpu_idle):
            targets.append(("cpu.idle", "1"))
        elif os.path.isfile(cpu_weight):
            targets.append(("cpu.weight", "10"))
        io_weight = 10
    elif scope_class in ("shared", "background"):
        if os.path.isfile(cpu_weight):
            targets.append(("cpu.weight", "50"))
        io_weight = 50
    else:
        return ()

    io_path = os.path.join(path, "io.weight")
    if os.path.isfile(io_path):
        try:
            current = _read(io_path)
        except OSError:
            current = None
        if current is not None and _default_io_weight(current) is not None:
            desired = _with_default_io_weight(current, io_weight)
            if desired is not None:
                targets.append(("io.weight", desired))
    return tuple(targets)


def plan(path, scope_class, focus_weight=None):
    """Build writes from currently exposed controls, retaining exact original values."""
    writes = []
    available = []
    for name, desired in _targets(scope_class, path, focus_weight):
        try:
            current = _read(os.path.join(path, name))
        except OSError:
            continue
        if name == "io.weight":
            current_weight = _default_io_weight(current)
            if current_weight is None:
                continue
            current = "default %d" % current_weight
        available.append(name)
        if current.strip() == desired:
            continue
        original = current.strip()
        writes.append(ResourceWrite(name, desired, original))
    return QoSPlan(tuple(writes), tuple(available))


def apply(path, plan):
    """Apply one already-validated plan; a failure leaves rollback to the caller."""
    for item in plan.writes:
        write_control(path, item.name, item.value)


def write_control(path, name, value):
    """Write one cgroup control command, preserving command-style pseudo-file semantics."""
    with open(os.path.join(path, name), "w", encoding="ascii") as target:
        target.write(value.rstrip() + "\n")


def enable_controllers(parent, required=CONTROLLERS):
    """Enable available delegated controllers on one user-owned parent, if needed.

    Returns ``None`` on success or a concise explanation when the parent cannot expose the
    requested controls. The caller supplies paths below its delegated cgroup boundary.
    """
    controllers_path = os.path.join(parent, "cgroup.controllers")
    subtree_path = os.path.join(parent, "cgroup.subtree_control")
    procs_path = os.path.join(parent, "cgroup.procs")
    try:
        available = set(_read(controllers_path).split())
        active = {item.lstrip("+") for item in _read(subtree_path).split()}
    except OSError:
        return "controller controls are unavailable"
    required = set(required)
    missing = sorted(required - available)
    enable = sorted((required & available) - active)
    if enable:
        try:
            if _read(procs_path).split():
                return "parent contains processes"
            with open(subtree_path, "w", encoding="ascii") as target:
                target.write(" ".join("+" + item for item in enable) + "\n")
        except OSError as error:
            return str(error)
    if missing:
        return "delegated controllers unavailable: %s" % ", ".join(missing)
    return None
