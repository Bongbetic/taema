"""Top and tree views over process snapshots."""

import unittest
from types import SimpleNamespace

from taema.cli import view
from taema.core import process as inspect
from taema.core.process import Proc, ProcTable


def args(width=100):
    return SimpleNamespace(_width=width, _color=False, wide=False, plain=True)


def rows(*specs):
    return {pid: Proc(ppid, 0, 0, 0, 0, state, cpu) for pid, ppid, state, cpu in specs}


class TopModelTests(unittest.TestCase):
    def test_cpu_percent_and_sort(self):
        prev = rows((10, 1, "R", 100), (20, 1, "S", 100), (30, 1, "S", 100))
        curr = rows((10, 1, "R", 200), (20, 1, "S", 120), (30, 1, "S", 120))
        details = {
            10: {"scope": "s", "user": "u", "mem": 10, "threads": 1, "cmd": "a"},
            20: {"scope": "s", "user": "u", "mem": 50, "threads": 1, "cmd": "b"},
            30: {"scope": "s", "user": "u", "mem": 40, "threads": 1, "cmd": "c"},
        }
        model = view.top_model(prev, curr, 1.0, 100, details)
        self.assertEqual([row["pid"] for row in model], [10, 20, 30])
        self.assertAlmostEqual(model[0]["cpu"], 100.0)
        self.assertAlmostEqual(model[1]["cpu"], 20.0)

    def test_pid_desc_breaks_ties(self):
        prev = rows((5, 1, "S", 0), (9, 1, "S", 0))
        curr = rows((5, 1, "S", 10), (9, 1, "S", 10))
        details = {
            pid: {"scope": "s", "user": "u", "mem": 8, "threads": 1, "cmd": "x"}
            for pid in (5, 9)
        }
        model = view.top_model(prev, curr, 1.0, 100, details)
        self.assertEqual([row["pid"] for row in model], [9, 5])

    def test_new_and_gone_pids(self):
        prev = rows((1, 0, "S", 50))
        curr = rows((1, 0, "S", 60), (2, 1, "R", 0))
        details = {
            1: {"scope": "s", "user": "u", "mem": 8, "threads": 1, "cmd": "a"},
            2: {"scope": "s", "user": "u", "mem": 8, "threads": 1, "cmd": "b"},
        }
        model = view.top_model(prev, curr, 1.0, 100, details)
        by_pid = {row["pid"]: row for row in model}
        self.assertAlmostEqual(by_pid[1]["cpu"], 10.0)
        self.assertAlmostEqual(by_pid[2]["cpu"], 0.0)


class TopRenderTests(unittest.TestCase):
    def test_golden(self):
        model = [
            {
                "pid": 10,
                "scope": "scope-a",
                "user": "ada",
                "cpu": 100.0,
                "mem_pct": 12.5,
                "mem": 1536,
                "threads": 4,
                "state": "R",
                "cmd": "cc1 foo.c",
            },
            {
                "pid": 9,
                "scope": "scope-a",
                "user": "ada",
                "cpu": 2.5,
                "mem_pct": 4.2,
                "mem": 512,
                "threads": 1,
                "state": "S",
                "cmd": "sh",
            },
        ]
        self.assertEqual(
            view.render_top(model, args()),
            "PID SCOPE   USER %CPU %MEM RSS  THR S CMD\n"
            "10  scope-a ada  100.0 12.5 1.5K 4   R cc1 foo.c\n"
            "9   scope-a ada    2.5  4.2 512  1   S sh\n",
        )

    def test_truncates_to_width(self):
        model = [
            {
                "pid": 10,
                "scope": "scope-a",
                "user": "ada",
                "cpu": 1.0,
                "mem_pct": 0.1,
                "mem": 8,
                "threads": 1,
                "state": "R",
                "cmd": "x" * 200,
            }
        ]
        for line in view.render_top(model, args(width=40)).splitlines():
            self.assertLessEqual(len(line), 40)


class TreeModelTests(unittest.TestCase):
    def test_golden_grouped_tree(self):
        table = ProcTable(
            rows(
                (1, 0, "S", 0),
                (10, 1, "S", 0),
                (11, 10, "R", 0),
                (12, 10, "Z", 0),
                (20, 1, "S", 0),
            )
        )
        scopes = {
            1: "system",
            10: "scope-a",
            11: "scope-a",
            12: "scope-a",
            20: "scope-b",
        }
        self.assertEqual(
            view.render_tree(view.tree_model(table, scopes.get), args()),
            "scope-a\n"
            "└─ 10 (reaps 1 zombie)\n"
            "   ├─ 11 R\n"
            "   └─ 12 Z\n"
            "scope-b\n"
            "└─ 20\n"
            "system\n"
            "└─ 1\n",
        )

    def test_orphans_become_roots(self):
        table = ProcTable(rows((50, 999, "S", 0)))
        model = view.tree_model(table, lambda pid: "scope-x")
        self.assertEqual(
            view.render_tree(model, args()),
            "scope-x\n└─ 50\n",
        )


class ProcessHelpersTests(unittest.TestCase):
    def test_self_reads(self):
        import os

        pid = os.getpid()
        self.assertGreater(inspect.rss_bytes(pid), 0)
        self.assertGreaterEqual(inspect.thread_count(pid), 1)
        self.assertTrue(inspect.username(inspect.uid_of(pid)))

    def test_gone_pid(self):
        self.assertIsNone(inspect.rss_bytes(99999999))
        self.assertIsNone(inspect.thread_count(99999999))

    def test_mem_total(self):
        self.assertGreater(inspect.mem_total_bytes(), 0)


def run_cli(root, *argv):
    import io
    from contextlib import redirect_stdout
    from pathlib import Path

    from taema.cli import commands

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


class TopCliTests(unittest.TestCase):
    def test_json_single_snapshot(self):
        import json
        import tempfile

        with tempfile.TemporaryDirectory() as root:
            code, output = run_cli(root, "top", "--json", "--interval", "0.01")
            self.assertEqual(code, 0, output)
            document = json.loads(output)
            self.assertTrue(document["rows"])
            cpus = [row["cpu"] for row in document["rows"]]
            self.assertEqual(cpus, sorted(cpus, reverse=True))
            self.assertIn("scope", document["rows"][0])

    def test_count_limits_snapshots(self):
        import tempfile

        with tempfile.TemporaryDirectory() as root:
            code, output = run_cli(root, "top", "2", "--interval", "0.01")
            self.assertEqual(code, 0, output)
            self.assertEqual(output.count("PID SCOPE"), 2)

    def test_keypress_ends_live_mode(self):
        import sys
        import tempfile
        from unittest import mock

        with tempfile.TemporaryDirectory() as root:
            stdin = mock.Mock()
            stdin.isatty.return_value = True
            with (
                mock.patch.object(sys, "stdin", stdin),
                mock.patch("select.select", return_value=([stdin], [], [])),
                mock.patch("time.sleep", return_value=None),
            ):
                code, output = run_cli(root, "top", "--interval", "0.01")
            self.assertEqual(code, 0, output)
            self.assertIn("PID SCOPE", output)

    def test_piped_stdin_runs_once(self):
        import sys
        import tempfile
        from unittest import mock

        with tempfile.TemporaryDirectory() as root:
            stdin = mock.Mock()
            stdin.isatty.return_value = False
            with mock.patch.object(sys, "stdin", stdin):
                code, output = run_cli(root, "top", "--interval", "0.01")
            self.assertEqual(code, 0, output)
            self.assertEqual(output.count("PID SCOPE"), 1)


class TreeCliTests(unittest.TestCase):
    def test_plain_and_json(self):
        import json
        import os
        import tempfile

        with tempfile.TemporaryDirectory() as root:
            code, output = run_cli(root, "tree")
            self.assertEqual(code, 0, output)
            self.assertIn("└─", output)
            self.assertIn(str(os.getpid()), output)
            code, output = run_cli(root, "tree", "--json")
            self.assertEqual(code, 0, output)
            document = json.loads(output)
            self.assertTrue(document["groups"])


if __name__ == "__main__":
    unittest.main()
