"""Safe target discovery, resolution, and interactive selection for the CLI."""

from dataclasses import dataclass
import os
import subprocess
import sys


@dataclass(frozen=True)
class Target:
    kind: str
    value: str
    label: str
    scope: str | None = None
    pid: int | None = None
    start: int | None = None
    desktop_id: str | None = None
    app_key: str | None = None


class TargetError(ValueError):
    """A target could not be resolved safely."""


class TargetNotFound(TargetError):
    """No live candidate matched the user's target."""


class TargetAmbiguous(TargetError):
    """More than one candidate matched the user's target."""

    def __init__(self, query, candidates):
        self.query = query
        self.candidates = tuple(candidates)
        super().__init__(query)


def _desktop_id(environment):
    value = (
        environment.get("TAEMA_DESKTOP_ID")
        or environment.get("XDG_DESKTOP_FILE_NAME")
        or environment.get("GIO_LAUNCHED_DESKTOP_FILE")
    )
    if not value:
        return None
    return os.path.basename(value)


def live_targets(base=None, include_desktop=True):
    """Return managed scopes and live app, desktop-id, and pid targets."""
    from ..config import policy
    from ..core import cgroup, process

    base = base or cgroup.base()
    if not os.path.isdir(base):
        return []
    targets = []
    seen = set()

    def add(target):
        identity = (target.kind, target.value, target.scope, target.pid, target.start)
        if identity not in seen:
            seen.add(identity)
            targets.append(target)

    def walk(path, managed):
        rel = cgroup.rel(path)
        name = os.path.basename(path)
        is_container = name in ("leftover", "shared")
        managed = managed or is_container or name.startswith(("app-", "scope-"))
        if managed and not is_container:
            add(Target("scope", rel, "scope:" + rel, scope=rel))
            for pid in cgroup.procs(path):
                start = process.starttime(pid)
                if start is None or process.uid_of(pid) != os.getuid():
                    continue
                key = policy.app_key(pid)
                add(
                    Target(
                        "pid",
                        str(pid),
                        "pid:%d (%s in %s)" % (pid, key or process.comm(pid), rel),
                        scope=rel,
                        pid=pid,
                        start=start,
                        app_key=key or None,
                    )
                )
                if key:
                    add(
                        Target(
                            "app",
                            key,
                            "app:%s (%s)" % (key, rel),
                            scope=rel,
                            app_key=key,
                        )
                    )
                if include_desktop:
                    desktop = _desktop_id(process.environ(pid))
                    if desktop:
                        add(
                            Target(
                                "desktop",
                                desktop,
                                "desktop:%s (%s)" % (desktop, rel),
                                scope=rel,
                                desktop_id=desktop,
                                app_key=key or None,
                            )
                        )
        for child in cgroup.subdirs(path):
            walk(child, managed)

    for path in cgroup.subdirs(base):
        walk(path, os.path.basename(path) != "manager")
    return sorted(
        targets, key=lambda item: (item.kind, item.value.casefold(), item.scope or "")
    )


def process_target(value):
    """Build a same-uid PID target with its current start time and managed scope, if any."""
    from ..core import cgroup, process

    try:
        pid = int(value)
    except (TypeError, ValueError):
        raise TargetNotFound(value) from None
    start = process.starttime(pid)
    if pid <= 1 or start is None or process.uid_of(pid) != os.getuid():
        raise TargetNotFound(value)
    cgroup_path = cgroup.proc_cgroup(pid) or ""
    base_path = cgroup.base()
    base_rel = (
        base_path[len(cgroup.CG) :] if base_path.startswith(cgroup.CG) else base_path
    )
    scope = None
    if cgroup_path == base_rel or cgroup_path.startswith(base_rel.rstrip("/") + "/"):
        scope = cgroup_path[len(base_rel) :].lstrip("/") or None
    return Target(
        "pid",
        str(pid),
        "pid:%d (%s)" % (pid, process.comm(pid)),
        scope=scope,
        pid=pid,
        start=start,
    )


def known_app_targets(store):
    """Return learned app keys for explain and shell completion, whether live or not."""
    values = set(store.data.get("standalone", {}))
    for pair in store.data.get("pairs", {}):
        if not isinstance(pair, str) or "\0" not in pair:
            continue
        owner, leftover = pair.split("\0", 1)
        values.update((owner, leftover))
    return [
        Target("app", value, "app:" + value, app_key=value)
        for value in sorted(values, key=str.casefold)
        if value
    ]


def _aliases(target):
    aliases = {target.value.casefold()}
    if target.kind == "scope":
        name = target.value.rsplit("/", 1)[-1]
        aliases.add(name.casefold())
        for prefix in ("scope-", "app-"):
            if name.startswith(prefix):
                aliases.add(name[len(prefix) :].casefold())
    if target.kind == "desktop" and target.value.endswith(".desktop"):
        aliases.add(target.value[: -len(".desktop")].casefold())
    return aliases


def matching_targets(query, candidates):
    """Return exact or substring matches, respecting optional kind prefixes."""
    if not isinstance(query, str) or not query.strip():
        return []
    value = query.strip()
    kind = None
    if ":" in value:
        prefix, remainder = value.split(":", 1)
        if prefix in ("scope", "app", "pid", "desktop"):
            kind, value = prefix, remainder
    folded = value.casefold()
    available = [item for item in candidates if kind is None or item.kind == kind]
    if kind == "pid" or (kind is None and value.isdigit()):
        available = [item for item in available if item.kind == "pid"]
    exact = [item for item in available if folded in _aliases(item)]
    if exact:
        return exact
    # PIDs are identifiers, not fuzzy names. In particular, "42" must never
    # select a live process such as 8942 when PID 42 is absent.
    if kind == "pid" or (kind is None and value.isdigit()):
        return []
    return [
        item
        for item in available
        if folded in item.value.casefold() or folded in item.label.casefold()
    ]


def resolve_target(query, candidates):
    matches = matching_targets(query, candidates)
    if not matches:
        raise TargetNotFound(query)
    if len(matches) > 1:
        raise TargetAmbiguous(query, matches)
    return matches[0]


def select_target(
    query,
    candidates,
    *,
    pick=False,
    interactive=None,
    input_fn=input,
    output=None,
):
    """Resolve a unique target or ask an interactive user to choose among matches."""
    matches = matching_targets(query, candidates)
    if not matches:
        raise TargetNotFound(query)
    return select_candidates(
        query,
        matches,
        pick=pick,
        interactive=interactive,
        input_fn=input_fn,
        output=output,
    )


def select_candidates(
    label,
    matches,
    *,
    pick=False,
    interactive=None,
    input_fn=input,
    output=None,
):
    """Choose from a prefiltered candidate list, or raise a safe resolution error."""
    matches = list(matches)
    if not matches:
        raise TargetNotFound(label)
    if len(matches) == 1:
        return matches[0]
    if interactive is None:
        interactive = bool(sys.stdin.isatty())
    use_fzf = pick or os.environ.get("TAEMA_PICKER") == "fzf"
    if not interactive and not use_fzf:
        raise TargetAmbiguous(label, matches)
    output = sys.stderr if output is None else output
    if use_fzf:
        try:
            result = subprocess.run(
                ["fzf"],
                input="\n".join(item.label for item in matches) + "\n",
                text=True,
                capture_output=True,
                check=False,
            )
        except OSError as error:
            raise TargetError("fzf picker is unavailable: %s" % error) from error
        if result.returncode:
            return None
        selected = result.stdout.strip()
        return next((item for item in matches if item.label == selected), None)

    print("Choose %s:" % label, file=output)
    for number, item in enumerate(matches, 1):
        print("  %d) %s" % (number, item.label), file=output)
    print("Selection [1-%d]: " % len(matches), end="", file=output, flush=True)
    try:
        answer = input_fn().strip()
    except (EOFError, OSError):
        return None
    if not answer.isdigit() or not 1 <= int(answer) <= len(matches):
        return None
    return matches[int(answer) - 1]


def leftover_targets(candidates):
    return [
        item
        for item in candidates
        if item.kind == "scope" and item.value.startswith("leftover/")
    ]


def completion_values(candidates, reviews=()):
    """Names suitable for a shell completion reply, one per line."""
    values = {
        "%s:%s" % (item.kind, item.value)
        for item in candidates
        if item.kind in ("scope", "app", "pid", "desktop")
        and item.value
        and not any(char.isspace() for char in item.value)
    }
    values.update("review:%s" % item for item in reviews if str(item))
    return sorted(values, key=str.casefold)
