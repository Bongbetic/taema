"""`taema bug-report` bundle contents and redaction (issue #83)."""

import json
import os
import tarfile
import tempfile
import unittest
from types import SimpleNamespace

from taema import bugreport


def sensitive_events(n):
    return [
        {
            "seq": i,
            "ts": 1700000000 + i,
            "event": "stop",
            "decision_id": None,
            "data": {
                "scope": "scope-x",
                "argv": ["vim", "/home/user/secret.txt"],
                "cwd": "/home/user",
                "title": "Secret Window",
                "titles": ["a", "b"],
                "env": {"HOME": "/home/user", "TOKEN": "abc"},
                "environment": {"X": "y"},
                "cmdline": "vim secret",
            },
        }
        for i in range(1, n + 1)
    ]


def fake_store(events):
    return SimpleNamespace(
        events_since=lambda since, limit: {
            "events": [e for e in events if e["seq"] > since][:limit],
            "latest_seq": len(events),
        },
        data={},
        db=None,
    )


def fake_cfg(state_dir):
    return {
        "mode": "observe",
        "paths": {
            "state_dir": state_dir,
            "socket": os.path.join(state_dir, "a.sock"),
            "socket_fallback": os.path.join(state_dir, "b.sock"),
        },
        "timers": {},
        "protected": {},
        "seeds": {},
        "_sources": [],
    }


class BugReportRedaction(unittest.TestCase):
    def test_redact_event_strips_sensitive_keys(self):
        event = bugreport.redact_event(sensitive_events(1)[0])
        blob = json.dumps(event)
        for key in (
            "argv",
            "cwd",
            "title",
            "titles",
            "env",
            "environment",
            "cmdline",
            "TOKEN",
            "secret",
        ):
            self.assertNotIn(key, blob)
        self.assertEqual(event["data"]["scope"], "scope-x")

    def test_collect_events_caps_at_500(self):
        window = bugreport.collect_events(fake_store(sensitive_events(600)))
        self.assertEqual(len(window["events"]), 500)

    def test_bundle_has_all_six_files_and_no_secrets(self):
        with tempfile.TemporaryDirectory() as state:
            target = os.path.join(state, "bug.tar.gz")
            path = bugreport.create_bundle(
                fake_cfg(state),
                fake_store(sensitive_events(10)),
                [{"unit": {"name": "app-x"}}, {"unit": {"name": "app-a"}}],
                target=target,
            )
            self.assertEqual(path, target)
            self.assertEqual(os.stat(target).st_mode & 0o777, 0o600)
            with tarfile.open(target, "r:gz") as archive:
                names = sorted(archive.getnames())
            self.assertEqual(
                names,
                [
                    "config.redacted.toml",
                    "doctor.json",
                    "events.json",
                    "metrics.json",
                    "units.json",
                    "versions.json",
                ],
            )
            with tarfile.open(target, "r:gz") as archive:
                blob = b"".join(
                    archive.extractfile(name).read() for name in names
                ).decode("utf-8", "replace")
            for key in (
                "secret.txt",
                "Secret Window",
                "TOKEN",
                '"argv"',
                '"cwd"',
                '"titles"',
                '"env"',
            ):
                self.assertNotIn(key, blob)
            with tarfile.open(target, "r:gz") as archive:
                units = json.loads(archive.extractfile("units.json").read())
                doctor = json.loads(archive.extractfile("doctor.json").read())
                versions = json.loads(archive.extractfile("versions.json").read())
            self.assertEqual(units, {"units": ["app-a", "app-x"]})
            self.assertEqual(doctor["schema"], "taema.doctor.v1")
            self.assertIn("taema", versions)
