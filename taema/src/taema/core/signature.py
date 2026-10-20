"""Canonical survivor signatures used by the learning store.

Signatures describe a survivor group, not process instances. Only resolved member keys and
counts, the runtime-directory hash, tty state, and owner affect the identifier.
"""

from collections import Counter
import hashlib
import json
import os


def runtime_dir_hash(path=None):
    """Return a stable, non-reversible hash of the runtime directory path."""
    path = os.environ.get("XDG_RUNTIME_DIR", "") if path is None else path
    if not isinstance(path, str) or not path:
        return ""
    canonical = os.path.realpath(path)
    return hashlib.sha256(canonical.encode("utf-8", errors="replace")).hexdigest()[:16]


def signature(owner, members, runtime_hash="", runtime_class="", tty=False):
    """Build a stable signature descriptor from member dictionaries or keys.

    PID and start-time fields are intentionally ignored. Duplicate keys are represented as
    counts and member ordering has no effect.
    """
    if not isinstance(owner, str) or not owner:
        raise ValueError("signature owner must be a non-empty string")
    counts = Counter()
    for member in members:
        key = member.get("key") if isinstance(member, dict) else member
        if not isinstance(key, str) or not key:
            raise ValueError("signature members must have non-empty keys")
        count = member.get("count", 1) if isinstance(member, dict) else 1
        if not isinstance(count, int) or isinstance(count, bool) or count < 1:
            raise ValueError("signature member counts must be positive integers")
        counts[key] += count
    if not counts:
        raise ValueError("signature requires at least one member")
    normalized = [{"key": key, "count": counts[key]} for key in sorted(counts)]
    runtime_hash = runtime_hash if isinstance(runtime_hash, str) else ""
    runtime_class = runtime_class if isinstance(runtime_class, str) else ""
    tty = bool(tty)
    material = json.dumps(
        [
            owner,
            [[item["key"], item["count"]] for item in normalized],
            runtime_hash,
            tty,
        ],
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    identifier = hashlib.sha256(material).hexdigest()[:16]
    return {
        "id": identifier,
        "owner": owner,
        "members": normalized,
        "runtime_hash": runtime_hash,
        "runtime_class": runtime_class,
        "tty": tty,
    }


def member_counts(members):
    """Normalize a stored member list, returning ``{key: count}`` or an empty mapping."""
    if not isinstance(members, list):
        return {}
    counts = {}
    for item in members:
        if not isinstance(item, dict):
            return {}
        key, count = item.get("key"), item.get("count")
        if (
            not isinstance(key, str)
            or not key
            or not isinstance(count, int)
            or isinstance(count, bool)
            or count < 1
        ):
            return {}
        counts[key] = count
    return counts
