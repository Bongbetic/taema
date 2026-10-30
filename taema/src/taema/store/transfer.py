"""State backup, learning transfer, and scoped reset."""

import datetime
import json
import os
import sqlite3
import tempfile

from taema import __version__
from taema.config import policy


def _tarfile():
    import tarfile

    return tarfile


BACKUP_VERSION = 1
MAX_IMPORT_BYTES = 4 * 1024 * 1024
LEARN_FORMAT = "taema-learn"
LEARN_VERSION = 1
LEARN_CHOICES = ("stop", "keep", "standalone")
REDACTED_KEYS = frozenset(
    {"argv", "cwd", "title", "titles", "env", "environment", "cmdline"}
)


def export_learn(store, redacted=False, now=None):
    """Export explicit answers as a versioned, portable document."""
    import datetime as _datetime

    moment = now or _datetime.datetime.now(_datetime.timezone.utc)
    pairs = []
    for key, record in sorted(store.data.get("pairs", {}).items()):
        if not isinstance(record, dict) or record.get("ex_last") not in LEARN_CHOICES:
            continue
        owner, separator, leftover = key.partition("\x00")
        if not separator:
            continue
        pairs.append(
            {
                "owner": owner,
                "leftover": leftover,
                "sig": record.get("sig"),
                "ex_stop": float(record.get("ex_stop", 0.0)),
                "ex_keep": float(record.get("ex_keep", 0.0)),
                "ex_last": record.get("ex_last"),
                "from_source": record.get(
                    "source", record.get("ex_source", "observed")
                ),
            }
        )
    standalone = [
        {"key": key, "n": int(entry.get("n", 0))}
        for key, entry in sorted(store.data.get("standalone", {}).items())
        if isinstance(entry, dict)
    ]
    signatures = []
    for record in store.db.signatures(limit=100000):
        if not isinstance(record, dict) or record.get("ex_last") not in (
            "stop",
            "keep",
        ):
            continue
        signatures.append(
            {
                "id": record.get("id"),
                "owner": record.get("owner"),
                "members": record.get("members", []),
                "runtime": record.get("runtime"),
                "ex_stop": float(record.get("ex_stop", 0.0)),
                "ex_keep": float(record.get("ex_keep", 0.0)),
                "ex_last": record.get("ex_last"),
            }
        )
    document = {
        "format": LEARN_FORMAT,
        "version": LEARN_VERSION,
        "exported": moment.isoformat(),
        "taema": __version__,
        "redacted": bool(redacted),
        "pairs": pairs,
        "standalone": standalone,
        "signatures": signatures,
    }
    if redacted:
        document = _redact(document)
        document["redacted"] = True
    return document


def _redact(node):
    if isinstance(node, dict):
        return {
            key: _redact(value)
            for key, value in node.items()
            if key not in REDACTED_KEYS
        }
    if isinstance(node, list):
        return [_redact(item) for item in node]
    return node


def import_diff(store, document, mode="merge"):
    """Human-readable plan rows for an import that has not run yet."""
    rows = []
    pairs = store.data.get("pairs", {})
    standalone = store.data.get("standalone", {})
    for entry in document.get("pairs", []):
        key = "%s\x00%s" % (entry["owner"], entry["leftover"])
        label = "pair %s/%s" % (entry["owner"], entry["leftover"])
        existing = pairs.get(key)
        if mode == "replace" and (
            not isinstance(existing, dict)
            or existing.get("ex_last") not in LEARN_CHOICES
        ):
            rows.append("%s: add %s" % (label, entry["ex_last"]))
        elif isinstance(existing, dict) and existing.get("ex_last") in LEARN_CHOICES:
            if mode == "replace":
                rows.append(
                    "%s: replace %s with %s"
                    % (label, existing.get("ex_last"), entry["ex_last"])
                )
            else:
                rows.append("%s: keep local %s" % (label, existing.get("ex_last")))
        else:
            rows.append("%s: add %s" % (label, entry["ex_last"]))
    if mode == "replace":
        wanted = {
            "%s\x00%s" % (entry["owner"], entry["leftover"])
            for entry in document.get("pairs", [])
        }
        for key in sorted(pairs):
            if key not in wanted:
                owner, _, leftover = key.partition("\x00")
                rows.append("pair %s/%s: remove (replace)" % (owner, leftover))
    for entry in document.get("standalone", []):
        if entry["key"] not in standalone:
            rows.append("standalone %s: add" % entry["key"])
    return rows


def _safe_members(archive):
    """Member list, or an error when the tarball escapes its staging dir."""
    names = []
    for member in archive.getmembers():
        name = member.name
        if (
            not name
            or os.path.isabs(name)
            or ".." in name.split("/")
            or member.islnk()
            or member.issym()
        ):
            return None, "tarball escapes its directory: %r" % name
        names.append(name)
    return names, None


def stage_backup(tarball, staging):
    """Extract a backup tarball into staging. Returns an error string or None."""
    tarfile = _tarfile()
    try:
        archive = tarfile.open(tarball, "r:gz")
    except (OSError, tarfile.TarError) as error:
        return "could not read backup: %s" % error
    try:
        _names, problem = _safe_members(archive)
        if problem is not None:
            return problem
        archive.extractall(staging)
    except (OSError, tarfile.TarError) as error:
        return "could not unpack backup: %s" % error
    finally:
        archive.close()
    try:
        with open(os.path.join(staging, "manifest.json"), encoding="utf-8") as stream:
            manifest = json.load(stream)
    except (OSError, ValueError) as error:
        return "backup has no manifest: %s" % error
    if not isinstance(manifest, dict) or manifest.get("version") != BACKUP_VERSION:
        return "backup version is not %d" % BACKUP_VERSION
    return None


def restore_database(state_dir, staged_db):
    """Replace the live database file with a staged copy, online-safe."""
    live = os.path.join(state_dir, "state.db")
    if os.path.isfile(live):
        source = sqlite3.connect("file:%s?mode=ro" % staged_db, uri=True)
        try:
            dest = sqlite3.connect(live)
            try:
                source.backup(dest)
            finally:
                dest.close()
        finally:
            source.close()
    else:
        with open(staged_db, "rb") as origin, open(live, "wb") as target:
            target.write(origin.read())
        os.chmod(live, 0o600)


def _copy_tree(staging, arc_dir, dest_dir):
    count = 0
    origin = os.path.join(staging, arc_dir)
    if not os.path.isdir(origin):
        return 0
    for base, _dirs, leaves in os.walk(origin):
        for leaf in leaves:
            source = os.path.join(base, leaf)
            relative = os.path.relpath(source, origin)
            target = os.path.join(dest_dir, relative)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(source, "rb") as origin_stream:
                data = origin_stream.read()
            fd, temporary = tempfile.mkstemp(dir=os.path.dirname(target) or None)
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(data)
                os.replace(temporary, target)
                os.chmod(target, 0o600)
            except BaseException:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass
                raise
            count += 1
    return count


def apply_staged_backup(staging, state_dir):
    """Apply staged state, config, and units. Returns (summary, error)."""
    try:
        with open(os.path.join(staging, "manifest.json"), encoding="utf-8") as stream:
            manifest = json.load(stream)
    except (OSError, ValueError) as error:
        return None, "backup has no manifest: %s" % error
    if not isinstance(manifest, dict) or manifest.get("version") != BACKUP_VERSION:
        return None, "backup version is not %d" % BACKUP_VERSION
    summary = {"state": "absent", "config_files": 0, "units": 0}
    if manifest.get("state") == "present":
        staged_db = os.path.join(staging, "state", "state.db")
        if not os.path.isfile(staged_db):
            return None, "backup state is missing its database"
        try:
            restore_database(state_dir, staged_db)
        except (OSError, sqlite3.Error) as error:
            return None, "could not restore database: %s" % error
        summary["state"] = "present"
    layout = manifest.get("layout", {}) if isinstance(manifest, dict) else {}
    config_dir = layout.get("config_dir") or policy.user_config_dir()
    if not os.path.isdir(config_dir):
        config_dir = policy.user_config_dir()
    os.makedirs(config_dir, exist_ok=True)
    summary["config_files"] = _copy_tree(staging, "config", config_dir)
    unit_layout = layout.get("units", {})
    staged_units = os.path.join(staging, "units")
    if os.path.isdir(staged_units):
        fallback = os.path.join(policy.user_config_dir(), "units")
        for leaf in sorted(os.listdir(staged_units)):
            source = os.path.join(staged_units, leaf)
            if not os.path.isfile(source):
                continue
            dest_dir = unit_layout.get("units/" + leaf) or fallback
            if not os.path.isdir(dest_dir):
                dest_dir = fallback
            os.makedirs(dest_dir, exist_ok=True)
            with open(source, "rb") as origin_stream:
                data = origin_stream.read()
            target = os.path.join(dest_dir, leaf)
            fd, temporary = tempfile.mkstemp(dir=dest_dir)
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(data)
                os.replace(temporary, target)
                os.chmod(target, 0o600)
            except BaseException:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass
                raise
            summary["units"] += 1
    return summary, None


def restore_plan(tarball):
    """Human-readable plan rows for a restore. Returns (rows, error)."""
    tarfile = _tarfile()
    try:
        archive = tarfile.open(tarball, "r:gz")
    except (OSError, tarfile.TarError) as error:
        return None, "could not read backup: %s" % error
    try:
        names, problem = _safe_members(archive)
        if problem is not None:
            return None, problem
        try:
            member = archive.getmember("manifest.json")
        except KeyError:
            return None, "backup has no manifest"
        manifest = json.loads(archive.extractfile(member).read().decode("utf-8"))
    except (OSError, tarfile.TarError, ValueError) as error:
        return None, "could not read backup: %s" % error
    finally:
        archive.close()
    if not isinstance(manifest, dict) or manifest.get("version") != BACKUP_VERSION:
        return None, "backup version is not %d" % BACKUP_VERSION
    rows = []
    if manifest.get("state") == "present":
        rows.append("state: restore the database")
    configs = sorted(name for name in names if name.startswith("config/"))
    units = sorted(name for name in names if name.startswith("units/"))
    if configs:
        rows.append("config: restore %d files" % len(configs))
    if units:
        rows.append("units: restore %d files" % len(units))
    return rows, None


def reset_plan(store, scope):
    """Human-readable plan rows for a reset that has not run yet."""
    counts = store.db.reset_counts()
    pairs = sum(
        1
        for record in store.data.get("pairs", {}).values()
        if isinstance(record, dict) and record.get("ex_last") in LEARN_CHOICES
    )
    rows = []
    if scope in ("learning", "all"):
        rows.append(
            "learning: remove %d pair answers, %d standalone, %d signatures"
            % (
                pairs,
                len(store.data.get("standalone", {})),
                counts["signatures"],
            )
        )
    if scope in ("vetoes", "all"):
        rows.append("vetoes: remove %d vetoes" % len(store.data.get("vetoes", [])))
    if scope in ("history", "all"):
        rows.append(
            "history: remove %d decisions, %d events, %d automatic actions"
            % (
                counts["decisions"],
                counts["events"],
                len(store.data.get("auto_actions", [])),
            )
        )
    return rows


def validate_learn_document(document):
    """Return an error string for a bad learn document, else None."""
    if not isinstance(document, dict):
        return "document must be an object"
    if document.get("format") != LEARN_FORMAT:
        return "format must be %r" % LEARN_FORMAT
    if document.get("version") != LEARN_VERSION:
        return "version must be %d" % LEARN_VERSION
    for key in ("pairs", "standalone", "signatures"):
        if not isinstance(document.get(key), list):
            return "%s must be a list" % key

    def _name(value):
        return isinstance(value, str) and 0 < len(value) <= 256 and "\x00" not in value

    for entry in document["pairs"]:
        if not isinstance(entry, dict):
            return "pair must be an object"
        if not _name(entry.get("owner")):
            return "pair owner must be a 1..256 character string"
        if not _name(entry.get("leftover")):
            return "pair leftover must be a 1..256 character string"
        if entry.get("ex_last") not in LEARN_CHOICES:
            return "pair ex_last must be one of stop, keep, standalone"
        for field in ("ex_stop", "ex_keep"):
            value = entry.get(field)
            if not isinstance(value, (int, float)) or value < 0:
                return "pair %s must be a non-negative number" % field
    for entry in document["standalone"]:
        if not isinstance(entry, dict) or not _name(entry.get("key")):
            return "standalone key must be a 1..256 character string"
    for entry in document["signatures"]:
        if not isinstance(entry, dict):
            return "signature must be an object"
        if not _name(entry.get("id")):
            return "signature id must be a 1..256 character string"
        if not _name(entry.get("owner")):
            return "signature owner must be a 1..256 character string"
        if not isinstance(entry.get("members"), list):
            return "signature members must be a list"
        if entry.get("ex_last") not in ("stop", "keep"):
            return "signature ex_last must be stop or keep"
    return None


def default_backup_path(state_dir, now=None):
    """Timestamped tarball path under the state's backups directory."""
    moment = now or datetime.datetime.now(datetime.timezone.utc)
    name = "taema-backup-%s.tar.gz" % moment.strftime("%Y%m%dT%H%M%SZ")
    return os.path.join(state_dir, "backups", name)


def sqlite_backup_copy(db_path, dest_path):
    """Copy a live database file with the online backup API."""
    source = sqlite3.connect("file:%s?mode=ro" % db_path, uri=True)
    try:
        dest = sqlite3.connect(dest_path)
        try:
            source.backup(dest)
        finally:
            dest.close()
    finally:
        source.close()


def _user_config_files():
    """User-owned config layer as (arcname, path) pairs."""
    user_dir = policy.user_config_dir()
    found = []
    main = os.path.join(user_dir, "taema.toml")
    if os.path.isfile(main):
        found.append(("config/taema.toml", main))
    dropins = os.path.join(user_dir, "taema.d")
    if os.path.isdir(dropins):
        for leaf in sorted(os.listdir(dropins)):
            if leaf.endswith(".toml"):
                path = os.path.join(dropins, leaf)
                if os.path.isfile(path):
                    found.append(("config/taema.d/" + leaf, path))
    return found


def _user_unit_files(cfg):
    """User-owned unit files as (arcname, path) pairs, later dirs win."""
    found = {}
    for directory in policy.units_dirs(cfg):
        if os.path.abspath(directory) == os.path.abspath(policy.SYSTEM_UNITS):
            continue
        if not os.path.isdir(directory):
            continue
        for leaf in sorted(os.listdir(directory)):
            if leaf.endswith(".toml"):
                path = os.path.join(directory, leaf)
                if os.path.isfile(path):
                    found[leaf] = path
    return [("units/" + leaf, found[leaf]) for leaf in sorted(found)]


def create_backup(cfg, target=None, now=None):
    """Write a tarball with the database, user config, and user units."""
    state_dir = policy.state_dir(cfg)
    if target is None:
        target = default_backup_path(state_dir, now)
    else:
        target = os.path.abspath(os.path.expanduser(target))
    directory = os.path.dirname(target)
    if directory:
        os.makedirs(directory, exist_ok=True)
    moment = now or datetime.datetime.now(datetime.timezone.utc)
    with tempfile.TemporaryDirectory(prefix="taema-backup-") as staging:
        members = []
        db_path = os.path.join(state_dir, "state.db")
        state = "absent"
        if os.path.isfile(db_path):
            staged_db = os.path.join(staging, "state.db")
            sqlite_backup_copy(db_path, staged_db)
            members.append(("state/state.db", staged_db))
            state = "present"
        config_members = _user_config_files()
        unit_members = _user_unit_files(cfg)
        members.extend(config_members)
        members.extend(unit_members)
        manifest = {
            "version": BACKUP_VERSION,
            "created": moment.isoformat(),
            "taema": __version__,
            "state": state,
            "layout": {
                "config_dir": policy.user_config_dir(),
                "units": {
                    arcname: os.path.dirname(path) for arcname, path in unit_members
                },
            },
        }
        manifest_path = os.path.join(staging, "manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as stream:
            json.dump(manifest, stream, indent=2, sort_keys=True)
            stream.write("\n")
        members.append(("manifest.json", manifest_path))
        fd, temporary = tempfile.mkstemp(
            prefix=".taema-backup-", suffix=".tar.gz", dir=directory or None
        )
        try:
            os.close(fd)
            with _tarfile().open(temporary, "w:gz") as archive:
                for arcname, path in members:
                    info = archive.gettarinfo(path, arcname)
                    info.mode = 0o600
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    with open(path, "rb") as stream:
                        archive.addfile(info, stream)
            os.replace(temporary, target)
            os.chmod(target, 0o600)
        except BaseException:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise
    return target
