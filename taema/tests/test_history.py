"""History timelines, recent automatic actions, and reports."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace

from taema.cli import commands
from taema.store import knowledge


def run_cli(root, *argv):
    override = Path(root) / "taema.toml"
    override.write_text(
        '[paths]\nstate_dir = "%s"\n' % (Path(root) / "state"), encoding="utf-8"
    )
    dead_socket = str(Path(root) / "dead.sock")
    output = io.StringIO()
    with redirect_stdout(output):
        code = commands.main(
            ["--config", str(override), "--socket", dead_socket, *argv]
        )
    return code, output.getvalue()


def make_history(root, now=1_800_000_000.0):
    state_dir = Path(root) / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    tick = [now]

    def clock():
        tick[0] += 1.0
        return tick[0]

    store = knowledge.Store(str(state_dir), now=clock)
    identity = SimpleNamespace(
        key="code",
        display="Code",
        exe="/usr/bin/code",
        kind="comm",
        desktop_id=None,
        unit=None,
        runtime=None,
        validated=True,
        device=None,
        inode=None,
    )
    store.db.record_app_identities(
        [(identity, {"pid": 4242, "start": 7, "born": now + 1})], now=now + 1
    )
    with store.decision_context(
        "stop", scope="scope-code", owner="code", authority="pair", why="test stop"
    ) as decision:
        stop_id = decision["id"]
        store.log(event="freeze", scope="scope-code")
        store.log(event="thaw", scope="scope-code", source="undo")
    with store.decision_context(
        "answer", scope="scope-code", owner="code", authority="user", why="test answer"
    ):
        store.log(event="review_created", scope="scope-code")
    with store.decision_context(
        "auto_stop",
        scope="scope-other",
        owner="other",
        authority="mode",
        why="other stop",
    ):
        pass
    store.log(event="regret", scope="scope-code")
    store.save()
    return store, stop_id


class HistoryTests(unittest.TestCase):
    def test_history_shows_app_timeline(self):
        with tempfile.TemporaryDirectory() as root:
            _store, stop_id = make_history(root)
            code, output = run_cli(root, "history", "code")
            self.assertEqual(code, 0, output)
            for marker in ("launch", "stop", "freeze", "thaw", "review", "regret"):
                self.assertIn(marker, output)
            self.assertIn("#%s" % stop_id, output)
            self.assertNotIn("scope-other", output)

    def test_history_scope_prefix(self):
        with tempfile.TemporaryDirectory() as root:
            make_history(root)
            code, output = run_cli(root, "history", "scope:scope-code")
            self.assertEqual(code, 0, output)
            self.assertIn("stop", output)
            self.assertNotIn("scope-other", output)

    def test_history_since_filters(self):
        with tempfile.TemporaryDirectory() as root:
            make_history(root, now=1_800_000_000.0)
            code, output = run_cli(
                root, "history", "code", "--since", str(1_800_000_004.0)
            )
            self.assertEqual(code, 0, output)
            self.assertNotIn("launch", output)

    def test_history_json(self):
        with tempfile.TemporaryDirectory() as root:
            make_history(root)
            code, output = run_cli(root, "history", "code", "--json")
            self.assertEqual(code, 0, output)
            document = json.loads(output)
            self.assertEqual(document["target"], "code")
            kinds = {entry["kind"] for entry in document["entries"]}
            self.assertTrue({"launch", "stop", "freeze"} <= kinds)


def make_auto_actions(root):
    store = knowledge.Store(str(Path(root) / "state"))
    first = store.record_auto_action(
        "scope-code",
        "closed app code",
        pairs=[("code", "esbuild")],
        owner="code",
        restore={"argv": ["code", "file"], "cwd": "/home/u/proj"},
    )
    store.log(
        event="freed",
        scope="scope-code",
        freed_bytes=4096,
        decision_id=first["decision_id"],
    )
    second = store.record_auto_action(
        "scope-vlc", "idle leftover", pairs=[("vlc", "vlc")], owner="vlc"
    )
    store.save()
    return store, first, second


class RecentTests(unittest.TestCase):
    def test_recent_lists_actions_with_freed_and_restore(self):
        with tempfile.TemporaryDirectory() as root:
            _store, first, second = make_auto_actions(root)
            code, output = run_cli(root, "recent")
            self.assertEqual(code, 0, output)
            self.assertIn("scope-code", output)
            self.assertIn("#%s" % first["decision_id"], output)
            self.assertIn("4096", output)
            lines = output.splitlines()
            code_line = next(line for line in lines if "scope-code" in line)
            vlc_line = next(line for line in lines if "scope-vlc" in line)
            self.assertIn("restore=yes", code_line)
            self.assertIn("restore=no", vlc_line)
            self.assertLess(lines.index(vlc_line), lines.index(code_line))

    def test_recent_json(self):
        with tempfile.TemporaryDirectory() as root:
            make_auto_actions(root)
            code, output = run_cli(root, "recent", "--json")
            self.assertEqual(code, 0, output)
            document = json.loads(output)
            self.assertEqual(len(document["actions"]), 2)
            self.assertEqual(document["actions"][0]["scope"], "scope-vlc")
            self.assertTrue(document["actions"][1]["restore_possible"])
            self.assertEqual(document["actions"][1]["freed_bytes"], 4096)


def make_report_data(root, now):
    store = knowledge.Store(str(Path(root) / "state"))
    store.answer("code", "esbuild", "stop")
    store.answer("code", "rg", "keep")
    pair = store.data["pairs"]["code\x00esbuild"]
    pair["launches"] = 9
    with store.decision_context("auto_stop", scope="s1", owner="a", authority="mode"):
        pass
    with store.decision_context("stop", scope="s2", owner="b", authority="pair"):
        pass
    with store.decision_context("undo", scope="s2", owner="b", authority="user"):
        pass
    with store.decision_context("freeze", scope="fz", owner="c", authority="mode"):
        store.log(event="freeze", scope="fz")
    with store.decision_context("thaw", scope="fz", owner="c", authority="mode"):
        store.log(event="thaw", scope="fz", reason="connect")
    with store.decision_context("stop", scope="mem", owner="m", authority="mode"):
        store.log(event="freed", scope="mem", freed_bytes=1000)
    store.log(
        event="gc_quit",
        scope="mem",
        reclaim={"status": "ok", "reclaimed_bytes": 500},
    )
    store.log(event="regret", scope="s2")
    store.log(event="vetoed", scope="s2")
    store.log(event="review_expired")
    store.db.record_app_identities(
        [
            (
                SimpleNamespace(
                    key="code",
                    display="Code",
                    exe="/usr/bin/code",
                    kind="comm",
                    desktop_id=None,
                    unit=None,
                    runtime=None,
                    validated=True,
                    device=None,
                    inode=None,
                ),
                {"pid": 1, "start": 1, "born": now},
            )
        ],
        now=now,
    )
    store.save()
    review = {
        "id": 7,
        "kind": "close",
        "owner": "code",
        "scope": "scope-code",
        "state": "answered",
        "created": now,
        "expires": now + 60,
        "shown": now,
        "closed": now,
        "answer": "stop",
        "candidates": [],
        "survivors": [],
    }
    store.data["reviews"].append(review)
    store.save()
    return store


class ReportTests(unittest.TestCase):
    def test_report_day_json(self):
        import time as _time

        now = _time.time()
        with tempfile.TemporaryDirectory() as root:
            make_report_data(root, now)
            code, output = run_cli(root, "report", "--day", "--json")
            self.assertEqual(code, 0, output)
            document = json.loads(output)
            self.assertEqual(document["window"], "day")
            memory = document["memory_freed_bytes"]
            self.assertEqual(memory["stop"], 1000)
            self.assertEqual(memory["reclaim"], 500)
            self.assertEqual(document["stops"]["automatic"], 1)
            self.assertEqual(document["stops"]["answered"], 2)
            self.assertEqual(document["undos"], 1)
            self.assertEqual(document["regrets"], 1)
            self.assertEqual(document["reviews"]["answered"], 1)
            self.assertEqual(document["reviews"]["expired"], 1)
            self.assertGreaterEqual(document["guard_events"]["total"], 1)
            self.assertEqual(document["top_leftovers"][0]["leftover"], "esbuild")
            self.assertGreaterEqual(document["frozen"]["thaws"], 1)
            self.assertEqual(document["frozen"]["connection_thaws"], 1)

    def test_report_plain_and_windows(self):
        import time as _time

        now = _time.time()
        with tempfile.TemporaryDirectory() as root:
            make_report_data(root, now)
            code, output = run_cli(root, "report", "--day")
            self.assertEqual(code, 0, output)
            for marker in ("memory", "stops", "undos", "reviews", "leftover"):
                self.assertIn(marker, output)
            for flag in ("--week", "--month"):
                code, _output = run_cli(root, "report", flag, "--json")
                self.assertEqual(code, 0)

    def test_report_needs_one_window(self):
        with tempfile.TemporaryDirectory() as root:
            make_report_data(root, 1_800_000_000.0)
            code, _output = run_cli(root, "report", "--json")
            self.assertEqual(code, 2)


class ReportPerfTests(unittest.TestCase):
    def test_window_queries_stay_fast_with_50k_rows(self):
        import time as _time

        with tempfile.TemporaryDirectory() as root:
            state_dir = Path(root) / "state"
            state_dir.mkdir(parents=True, exist_ok=True)
            store = knowledge.Store(str(state_dir))
            now = _time.time()
            with store.db.connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.executemany(
                    "INSERT INTO decisions (id, ts, kind, scope, owner, authority, why)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?)",
                    [
                        (index, now - index, "stop", "s%d" % index, "o", "mode", "")
                        for index in range(1, 5001)
                    ],
                )
                connection.executemany(
                    "INSERT INTO events (seq, ts, event, decision_id, data)"
                    " VALUES (?, ?, ?, ?, ?)",
                    [
                        (
                            index,
                            now - (index % 5000),
                            "freed" if index % 10 == 0 else "gc_skip",
                            (index % 5000) + 1,
                            '{"freed_bytes": 10, "scope": "s1"}'
                            if index % 10 == 0
                            else '{"scope": "s1"}',
                        )
                        for index in range(1, 45001)
                    ],
                )
                connection.commit()
            budget = _time.time()
            report = store.report_window(now - 86400, now)
            timeline = store.db.history_timeline(owner="o", scope="o")
            recent = store.db.recent_auto_actions()
            elapsed = _time.time() - budget
            self.assertEqual(report["stops"]["answered"], 5000)
            self.assertTrue(timeline["decisions"])
            self.assertEqual(recent, [])
            self.assertLess(elapsed, 10.0, "window queries took %.1fs" % elapsed)


if __name__ == "__main__":
    unittest.main()
