"""Small, conservative editor for the CLI-managed TOML drop-in."""

import copy
import datetime
import json
import math
import os
import re
import shlex
import subprocess
import tempfile
import tomllib

from . import policy

_KEY = re.compile(r"^[A-Za-z0-9_-]+$")
HEADER = "# managed by taema; edit with `taema config` to keep changes validated\n"


def managed_path():
    return os.path.join(policy.user_config_dir(), "taema.d", "50-cli.toml")


def parse_key(key):
    parts = key.split(".")
    if not parts or any(not _KEY.fullmatch(part) for part in parts):
        raise ValueError("configuration key must be a dotted TOML key")
    return parts


def parse_value(value):
    try:
        return tomllib.loads("value = " + value)["value"]
    except (tomllib.TOMLDecodeError, TypeError) as error:
        raise ValueError(
            "value must be a TOML scalar, array, or inline table: %s" % error
        ) from error


def _toml_value(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("non-finite TOML numbers are not supported")
        return repr(value)
    if isinstance(value, (datetime.datetime, datetime.date, datetime.time)):
        return value.isoformat()
    if isinstance(value, list):
        return "[" + ", ".join(_toml_value(item) for item in value) + "]"
    if isinstance(value, dict):
        if any(not _KEY.fullmatch(str(key)) for key in value):
            raise ValueError("inline table keys must be simple TOML keys")
        return (
            "{ "
            + ", ".join(
                "%s = %s" % (key, _toml_value(value[key])) for key in sorted(value)
            )
            + " }"
        )
    raise ValueError("unsupported TOML value: %s" % type(value).__name__)


def dump_toml(data, header=""):
    """Write scalar, array, inline-table, and nested-table values deterministically."""
    lines = [header.rstrip()] if header else []

    def emit(table, prefix=()):
        scalars = [
            (key, value) for key, value in table.items() if not isinstance(value, dict)
        ]
        children = [
            (key, value) for key, value in table.items() if isinstance(value, dict)
        ]
        if prefix:
            if lines and lines[-1] != "":
                lines.append("")
            lines.append("[" + ".".join(prefix) + "]")
        for key, value in sorted(scalars):
            if not _KEY.fullmatch(str(key)):
                raise ValueError("TOML keys must be simple keys")
            lines.append("%s = %s" % (key, _toml_value(value)))
        for key, value in sorted(children):
            emit(value, prefix + (key,))

    emit(data)
    return "\n".join(lines).rstrip() + "\n"


def read_managed():
    path = managed_path()
    return policy._read(path)


def _write_bytes(path, content):
    directory = os.path.dirname(path)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    os.chmod(directory, 0o700)
    fd, temporary = tempfile.mkstemp(prefix=".50-cli.", dir=directory)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as target:
            target.write(content)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def write_managed(data):
    _write_bytes(managed_path(), dump_toml(data, HEADER).encode("utf-8"))


def _lookup(data, parts):
    value = data
    for part in parts:
        if not isinstance(value, dict) or part not in value:
            raise KeyError(".".join(parts))
        value = value[part]
    return value


def get_value(key, config_path=None):
    return _lookup(policy.load_config(path=config_path), parse_key(key))


def format_value(value):
    return _toml_value(value)


def _set(data, parts, value):
    table = data
    for part in parts[:-1]:
        child = table.setdefault(part, {})
        if not isinstance(child, dict):
            raise ValueError("%s is not a table" % part)
        table = child
    table[parts[-1]] = value


def _unset(data, parts):
    table = data
    parents = []
    for part in parts[:-1]:
        if not isinstance(table, dict) or part not in table:
            return
        parents.append((table, part))
        table = table[part]
    if isinstance(table, dict):
        table.pop(parts[-1], None)
        for parent, part in reversed(parents):
            if parent.get(part) == {}:
                parent.pop(part, None)
            else:
                break


def _validate_managed_edit(before):
    try:
        policy.load_config()
    except Exception:
        path = managed_path()
        if before is None:
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
        else:
            _write_bytes(path, before)
        raise


def set_value(key, literal):
    path = managed_path()
    try:
        with open(path, "rb") as source:
            before = source.read()
    except FileNotFoundError:
        before = None
    values = read_managed()
    _set(values, parse_key(key), parse_value(literal))
    write_managed(values)
    _validate_managed_edit(before)


def unset_value(key):
    path = managed_path()
    try:
        with open(path, "rb") as source:
            before = source.read()
    except FileNotFoundError:
        before = None
    values = read_managed()
    _unset(values, parse_key(key))
    write_managed(values)
    _validate_managed_edit(before)


def edit_managed():
    path = managed_path()
    editor = os.environ.get("EDITOR") or os.environ.get("VISUAL")
    if not editor:
        raise ValueError("set EDITOR to edit the managed configuration")
    try:
        with open(path, "rb") as source:
            before = source.read()
    except FileNotFoundError:
        before = None
        write_managed({})
    try:
        result = subprocess.run([*shlex.split(editor), path], check=False)
        if result.returncode:
            raise ValueError("editor exited with status %d" % result.returncode)
        policy.load_config()
        with open(path, "rb") as source:
            content = source.read()
        if not content.lower().startswith(b"# managed by taema"):
            _write_bytes(path, HEADER.encode("utf-8") + content)
        os.chmod(path, 0o600)
    except Exception:
        if before is None:
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
        else:
            _write_bytes(path, before)
        raise


def effective_toml(cfg):
    return dump_toml(
        {
            key: copy.deepcopy(value)
            for key, value in cfg.items()
            if not key.startswith("_")
        }
    )


def source_lines(cfg):
    return [
        "# source for %s: %s" % (key, source)
        for key, source in sorted(cfg.get("_source_map", {}).items())
    ]


def diff_text():
    import difflib

    base = policy.load_system_config()
    effective = policy.load_config()
    return "".join(
        difflib.unified_diff(
            dump_toml(
                {key: value for key, value in base.items() if not key.startswith("_")}
            ).splitlines(True),
            effective_toml(effective).splitlines(True),
            fromfile="system defaults",
            tofile="effective config",
        )
    )
