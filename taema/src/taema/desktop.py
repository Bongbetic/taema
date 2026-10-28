"""Reversible desktop entry wrapping (issue #63).

``wrap`` copies a system ``.desktop`` entry to the user applications
directory with its main ``Exec`` routed through ``taema launch``. The
override carries a marker comment recording the source path and hash,
so ``drifted`` (and doctor) notice when a package update changes the
original behind the wrapper. System entries are only ever read.
"""

from __future__ import annotations

import hashlib
import os
import re

__all__ = [
    "DesktopError",
    "MARKER_PREFIX",
    "app_of",
    "drifted",
    "find_source",
    "list_wraps",
    "read_marker",
    "system_dirs",
    "unwrap",
    "unwrap_all",
    "user_dir",
    "wrap",
]

MARKER_PREFIX = "# taema-wrap "
_NAME = re.compile(r"[A-Za-z0-9_@+. -]{1,124}\.desktop")


class DesktopError(Exception):
    """A wrap/unwrap request that cannot be honored."""


def user_dir():
    """The user applications directory, honoring XDG_DATA_HOME."""
    home = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
    return os.path.join(home, "applications")


def system_dirs():
    """System applications directories in lookup order."""
    raw = os.environ.get("XDG_DATA_DIRS") or "/usr/local/share:/usr/share"
    return [os.path.join(part, "applications") for part in raw.split(":") if part]


def _normalize(filename):
    if not isinstance(filename, str) or not filename:
        raise DesktopError("need a NAME.desktop entry")
    if not filename.endswith(".desktop"):
        filename += ".desktop"
    if "/" in filename or not _NAME.fullmatch(filename):
        raise DesktopError("bad desktop entry name: %r" % filename)
    return filename


def app_of(filename):
    """The sanitized `taema launch --app` name for one desktop file stem."""
    stem = filename[:-8] if filename.endswith(".desktop") else filename
    cleaned = re.sub(r"[^a-z0-9]+", "-", stem.lower()).strip("-")
    return (cleaned or "app")[:32]


def find_source(filename):
    """The first system copy of FILENAME, or None when there is none."""
    for directory in system_dirs():
        candidate = os.path.join(directory, filename)
        if os.path.isfile(candidate):
            return candidate
    return None


def read_marker(path):
    """Parse our override marker comment, or None when the file is not ours."""
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if not line.startswith(MARKER_PREFIX):
                    continue
                fields = {}
                for token in line[len(MARKER_PREFIX) :].split():
                    key, sep, value = token.partition("=")
                    if sep:
                        fields[key] = value
                if "source" in fields and "sha256" in fields:
                    return fields
                return None
    except OSError:
        return None
    return None


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _rewrite_exec(lines, app):
    """Route the [Desktop Entry] Exec through taema launch. Returns (lines, error)."""
    in_main, done = False, False
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_main = stripped == "[Desktop Entry]"
            continue
        if not in_main:
            continue
        if stripped == "DBusActivatable=true":
            return lines, "entry is DBus-activated; its Exec never runs"
        if not done and line.startswith("Exec="):
            original = line[len("Exec=") :].rstrip("\n")
            if not original:
                return lines, "entry has an empty Exec"
            lines[index] = "Exec=taema launch --app %s -- %s\n" % (app, original)
            done = True
    if not done:
        return lines, "entry has no Exec to wrap"
    return lines, ""


def wrap(filename):
    """Write (or refresh) the user override for one system desktop entry."""
    filename = _normalize(filename)
    source = find_source(filename)
    if source is None:
        raise DesktopError("no system entry named %s" % filename)
    digest = _sha256(source)
    target = os.path.join(user_dir(), filename)
    marker = read_marker(target) if os.path.exists(target) else None
    if os.path.exists(target) and marker is None:
        raise DesktopError("not ours, refusing to overwrite: %s" % target)
    if marker is not None and marker.get("sha256") == digest:
        return {
            "file": target,
            "source": marker.get("source", source),
            "app": app_of(filename),
            "sha256": digest,
            "updated": False,
        }
    with open(source, encoding="utf-8", errors="replace") as handle:
        lines, error = _rewrite_exec(
            handle.read().splitlines(keepends=True), app_of(filename)
        )
    if error:
        raise DesktopError(error)
    os.makedirs(user_dir(), exist_ok=True)
    body = "%ssource=%s sha256=%s\n" % (MARKER_PREFIX, source, digest)
    body += "".join(lines)
    tmp = target + ".tmp-%d" % os.getpid()
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write(body)
    os.replace(tmp, target)
    return {
        "file": target,
        "source": source,
        "app": app_of(filename),
        "sha256": digest,
        "updated": marker is not None,
    }


AUTOSTART_FILENAME = "taema-agent.desktop"


def _rooted(root, path):
    return os.path.join(root, path.lstrip("/"))


def autostart_source(system_root="/"):
    """The packaged agent autostart snippet, or None when not installed."""
    candidates = [
        _rooted(system_root, "/usr/share/examples/taema/autostart/" + AUTOSTART_FILENAME),
        os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "..",
            "examples",
            "autostart",
            AUTOSTART_FILENAME,
        ),
    ]
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate
    return None


def ensure_agent_autostart(system_root="/", config_home=None):
    """Install the session-agent autostart entry when missing.

    Returns (status, message) with status fixed, skipped, or fail. A
    customized entry is left in place; a missing snippet source is a skip.
    """
    if config_home is None:
        base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    else:
        base = config_home
    dest = os.path.join(base, "autostart", AUTOSTART_FILENAME)
    source = autostart_source(system_root)
    if source is None:
        return "skipped", "packaged autostart snippet not found"
    try:
        with open(source, encoding="utf-8") as stream:
            wanted = stream.read()
        if os.path.isfile(dest):
            with open(dest, encoding="utf-8") as stream:
                current = stream.read()
            if current == wanted:
                return "skipped", "%s already installed" % dest
            return "skipped", "%s is customized; left in place" % dest
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, "w", encoding="utf-8") as stream:
            stream.write(wanted)
        os.chmod(dest, 0o644)
        return "fixed", "installed %s" % dest
    except OSError as error:
        return "fail", str(error)


def unwrap(filename):
    """Remove our user override for one entry; foreign files are left alone."""
    filename = _normalize(filename)
    target = os.path.join(user_dir(), filename)
    if read_marker(target) is None:
        raise DesktopError("no taema wrapper for %s" % filename)
    os.remove(target)
    return {"file": target, "removed": True}


def _our_overrides():
    found = []
    try:
        names = sorted(os.listdir(user_dir()))
    except OSError:
        return found
    for name in names:
        if not name.endswith(".desktop"):
            continue
        path = os.path.join(user_dir(), name)
        marker = read_marker(path)
        if marker is not None:
            found.append((name, path, marker))
    return found


def list_wraps():
    """Every override we own, with drift status against its source."""
    items = []
    for name, path, marker in _our_overrides():
        source = marker.get("source", "")
        try:
            current = _sha256(source) if source else ""
        except OSError:
            current = ""
        items.append(
            {
                "file": path,
                "app": app_of(name),
                "source": source,
                "sha256": marker.get("sha256", ""),
                "drifted": bool(current) and current != marker.get("sha256"),
            }
        )
    return items


def drifted():
    """Overrides whose source changed behind the wrapper."""
    return [item for item in list_wraps() if item["drifted"]]


def unwrap_all():
    """Remove every override we own."""
    removed = []
    for name, path, _marker in _our_overrides():
        os.remove(path)
        removed.append({"file": path, "removed": True})
    return removed
