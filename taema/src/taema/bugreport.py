"""Sanitized bug-report bundle for `taema bug-report` (issue #83).

Tarball contents:
  versions.json   taema/python/kernel/xbps versions
  doctor.json     `doctor --json` equivalent (diagnose report)
  config.redacted.toml  effective config with sensitive values stripped
  units.json      unit names (not contents)
  metrics.json    self-metrics: status reply minus sensitive fields, redacted
  events.json     last 500 audit events, redacted

Redaction strips argv, cwd, titles, and environment values. Reuses the
transfer.REDACTED_KEYS set plus path-like extras, and never fails the
bundle on one bad source: failures become {"error": ...} entries.
"""

import json
import os
import platform
import tarfile
import tempfile
import time

from taema import __version__
from taema.store import transfer

EXTRA_REDACT_KEYS = frozenset(
    {"socket", "state_dir", "helper", "hooks_dir", "units_dir"}
)


def _redact_node(node):
    if isinstance(node, dict):
        out = {}
        for key, value in node.items():
            if key in transfer.REDACTED_KEYS:
                continue
            if key in EXTRA_REDACT_KEYS and isinstance(value, str):
                out[key] = "[redacted]"
                continue
            out[key] = _redact_node(value)
        return out
    if isinstance(node, list):
        return [_redact_node(item) for item in node]
    return node


def redact_event(event):
    if not isinstance(event, dict):
        return event
    event = dict(event)
    data = event.get("data")
    if isinstance(data, dict):
        event["data"] = _redact_node(data)
    for key in ("argv", "cwd", "title", "titles"):
        event.pop(key, None)
    return event


def collect_versions():
    versions = {
        "taema": __version__,
        "python": platform.python_version(),
        "kernel": platform.release(),
    }
    try:
        import subprocess

        probe = subprocess.run(
            ["xbps-query", "-S", "taema"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if probe.returncode == 0:
            for line in probe.stdout.splitlines():
                if line.startswith("version:"):
                    versions["xbps"] = line.split(":", 1)[1].strip()
                    break
    except Exception:
        pass
    return versions


def collect_doctor(cfg, store, units):
    from taema import doctor as doctor_mod

    try:
        report = doctor_mod.diagnose(cfg, store, units)
    except Exception as error:
        report = {"schema": "taema.doctor.v1", "status": "fail", "error": str(error)}
    return report


def collect_redacted_config(cfg):
    from taema.config import management

    try:
        effective = {
            key: value for key, value in cfg.items() if not key.startswith("_")
        }
        redacted = _redact_node(effective)
        return management.dump_toml(redacted)
    except Exception as error:
        return "# could not render config: %s\n" % error


def collect_unit_names(units):
    names = []
    for unit in units or []:
        if isinstance(unit, dict):
            name = (
                unit.get("unit", {}).get("name")
                if isinstance(unit.get("unit"), dict)
                else None
            )
            if name:
                names.append(name)
    return sorted(set(names))


def collect_metrics(cfg, store):
    try:
        from taema.cli import commands as commands_mod

        reply = commands_mod.ask(cfg, {"cmd": "status"})
        if isinstance(reply, dict) and "error" not in reply:
            return _redact_node(reply)
    except Exception:
        pass
    metrics = {}
    if store is not None:
        try:
            metrics["decisions"] = (
                len(store.data.get("decisions", []))
                if isinstance(store.data.get("decisions"), list)
                else 0
            )
        except Exception:
            pass
        try:
            metrics["events"] = store.db.events_since(0, 1).get("latest_seq", 0)
        except Exception:
            pass
    metrics["taema"] = __version__
    metrics["time"] = int(time.time())
    return _redact_node(metrics)


def collect_events(store, limit=500):
    if store is None:
        return {"events": [], "note": "store unavailable"}
    try:
        window = store.events_since(0, limit)
        events = [redact_event(event) for event in window.get("events", [])[-limit:]]
        return {"events": events, "latest_seq": window.get("latest_seq", 0)}
    except Exception as error:
        return {"events": [], "error": str(error)}


def create_bundle(cfg, store, units, target=None):
    """Write the tarball. Returns the absolute path."""
    versions = collect_versions()
    doctor_report = collect_doctor(cfg, store, units)
    config_text = collect_redacted_config(cfg)
    unit_names = collect_unit_names(units)
    metrics = collect_metrics(cfg, store)
    events = collect_events(store)
    if target is None:
        state_dir = cfg.get("paths", {}).get("state_dir", "/tmp")
        try:
            from taema.config import policy

            state_dir = policy.state_dir(cfg)
        except Exception:
            pass
        name = "taema-bug-report-%s.tar.gz" % time.strftime(
            "%Y%m%dT%H%M%SZ", time.gmtime()
        )
        target = os.path.join(state_dir, name)
    else:
        target = os.path.abspath(os.path.expanduser(target))
    directory = os.path.dirname(target)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="taema-bug-report-") as staging:
        parts = {
            "versions.json": json.dumps(versions, indent=2, sort_keys=True) + "\n",
            "doctor.json": json.dumps(doctor_report, indent=2, sort_keys=True) + "\n",
            "config.redacted.toml": config_text,
            "units.json": json.dumps({"units": unit_names}, indent=2, sort_keys=True)
            + "\n",
            "metrics.json": json.dumps(metrics, indent=2, sort_keys=True) + "\n",
            "events.json": json.dumps(events, indent=2, sort_keys=True) + "\n",
        }
        staged = []
        for arcname, text in parts.items():
            path = os.path.join(staging, arcname)
            with open(path, "w", encoding="utf-8") as stream:
                stream.write(text)
            staged.append((arcname, path))
        fd, temporary = tempfile.mkstemp(
            prefix=".taema-bug-report-", suffix=".tar.gz", dir=directory or None
        )
        try:
            os.close(fd)
            with tarfile.open(temporary, "w:gz") as archive:
                for arcname, path in staged:
                    archive.add(path, arcname=arcname)
            os.replace(temporary, target)
            os.chmod(target, 0o600)
        except BaseException:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise
    return target
