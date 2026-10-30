"""Every read command's --json validates against its schema (issue #55).

The gate runs each read command (and read child) with --json against a
seeded fixture store and checks the output against read-v1.json. Live
daemon branches run only when a daemon answers.
"""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from taema.cli import commands
from taema.store import knowledge
from tests.test_history import make_history
from tests.test_ipc_v2 import matches

SCHEMA = json.loads(
    (Path(__file__).resolve().parents[1] / "schema/cli/read-v1.json").read_text()
)


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


def daemon_up():
    import socket

    from taema.cli.commands import sock_paths
    from taema.config import policy

    try:
        cfg = policy.load_config()
    except Exception:
        return False
    for path in sock_paths(cfg):
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            sock.connect(path)
            sock.close()
            return True
        except OSError:
            continue
    return False


DAEMON_UP = daemon_up()


def seed(root):
    make_history(root)
    store = knowledge.Store(str(Path(root) / "state"))
    store.record_auto_action(
        "scope-code",
        "closed app code",
        pairs=[("code", "esbuild")],
        owner="code",
    )
    store.log(event="gc_stopped", scope="scope-code")
    store.save()
    return store


class ReadJsonGate(unittest.TestCase):
    def _check(self, root, argv, ask_reply=None):
        if ask_reply == " passthrough ":
            code, output = run_cli(root, *argv)
        else:
            with mock.patch.object(commands, "ask", return_value=ask_reply):
                code, output = run_cli(root, *argv)
        document = json.loads(output)
        self.assertTrue(
            matches(document, SCHEMA, SCHEMA), "%s: %s" % (argv, output[:500])
        )
        return code, document

    def test_offline_read_commands_validate(self):
        from tests.test_bar import sample_status

        with tempfile.TemporaryDirectory() as root:
            seed(root)
            cases = [
                (["history", "app:code", "--json"], None),
                (["report", "--day", "--json"], None),
                (["recent", "--json"], None),
                (["events", "--json"], None),
                (["review", "--json"], None),
                (["explain", "--json"], None),
                (["learn", "show", "--json"], None),
                (["learn", "apps", "--json"], None),
                (["learn", "pairs", "--json"], None),
                (["learn", "signatures", "--json"], None),
                (["doctor", "--json"], None),
                (["status", "--json"], None),
                (["dash", "--json"], None),
                (["top", "--json", "--interval", "0.05"], None),
                (["tree", "--json"], None),
                (["ls", "--json"], None),
                (["gc", "--dry-run", "--json"], None),
                (["memory", "--json"], None),
                (["memory", "top", "--json"], None),
                (["memory", "pressure", "--json"], None),
                (
                    ["memory", "watch", "--json", "--count", "1", "--interval", "0.01"],
                    None,
                ),
            ]
            for argv, _ask in cases:
                with self.subTest(argv=argv):
                    self._check(root, argv, None)
            with self.subTest(argv=["bar", "--json"]):
                self._check(root, ["bar", "--json"], sample_status())
            with self.subTest(argv=["backup", "--json"]):
                target = str(Path(root) / "out.tar.gz")
                code, document = self._check(
                    root, ["backup", "--json", "--to", target], None
                )
                self.assertEqual(code, 0)
                self.assertEqual(document["path"], target)

    @unittest.skipUnless(DAEMON_UP, "live daemon needed")
    def test_live_branches_validate(self):
        from taema.cli.commands import sock_paths
        from taema.config import policy

        cfg = policy.load_config()
        socket_path = None
        for candidate in sock_paths(cfg):
            import os

            if os.path.exists(candidate):
                socket_path = candidate
                break
        self.assertIsNotNone(socket_path)
        base = ["--socket", socket_path]
        for argv in (
            ["status", "--json"],
            ["bar", "--json"],
            ["dash", "--json"],
            ["memory", "budget", "--json"],
        ):
            with self.subTest(argv=argv):
                output = io.StringIO()
                with redirect_stdout(output):
                    code = commands.main(base + argv)
                self.assertEqual(code, 0, output.getvalue()[:300])
                document = json.loads(output.getvalue())
                self.assertTrue(
                    matches(document, SCHEMA, SCHEMA),
                    "%s: %s" % (argv, output.getvalue()[:500]),
                )

    @unittest.skipUnless(DAEMON_UP, "live daemon needed")
    def test_live_reclaim_dry_run_validates(self):
        from taema.cli.commands import sock_paths
        from taema.config import policy
        from taema.core import cgroup

        try:
            leaves = cgroup.subdirs(cgroup.base())
        except OSError:
            self.skipTest("no cgroup base")
        if not leaves:
            self.skipTest("no scopes to reclaim")
        cfg = policy.load_config()
        socket_path = next(
            (c for c in sock_paths(cfg) if __import__("os").path.exists(c)), None
        )
        self.assertIsNotNone(socket_path)
        name = cgroup.rel(leaves[0])
        output = io.StringIO()
        with redirect_stdout(output):
            code = commands.main(
                [
                    "--socket",
                    socket_path,
                    "memory",
                    "reclaim",
                    "--dry-run",
                    name,
                    "--json",
                ]
            )
        self.assertIn(code, (0, 1, 4), output.getvalue()[:300])
        document = json.loads(output.getvalue())
        self.assertTrue(matches(document, SCHEMA, SCHEMA), output.getvalue()[:500])


class StatusCacheTest(unittest.TestCase):
    def test_status_reuses_reply_within_one_second(self):
        from tests.test_windows import make_daemon

        daemon = make_daemon()
        first = daemon.handle({"cmd": "status"})
        second = daemon.handle({"cmd": "status"})
        self.assertIs(first, second)

    def test_reload_invalidates_status_cache(self):
        from tests.test_windows import make_daemon

        daemon = make_daemon()
        first = daemon.handle({"cmd": "status"})
        daemon.reload_config("test", _preloaded=(daemon.cfg, daemon.units))
        second = daemon.handle({"cmd": "status"})
        self.assertIsNot(first, second)

    def test_expired_cache_rebuilds(self):
        import time as time_mod

        from tests.test_windows import make_daemon

        daemon = make_daemon()
        first = daemon.handle({"cmd": "status"})
        daemon._status_cache = (daemon._state_gen, time_mod.monotonic() - 2.0, first)
        second = daemon.handle({"cmd": "status"})
        self.assertIsNot(first, second)

    def test_mutating_command_invalidates_cache(self):
        from tests.test_windows import make_daemon

        daemon = make_daemon()
        first = daemon.handle({"cmd": "status"})
        daemon.handle({"cmd": "freeze"})
        second = daemon.handle({"cmd": "status"})
        self.assertIsNot(first, second)

    def test_pure_commands_keep_cache(self):
        from tests.test_windows import make_daemon

        daemon = make_daemon()
        first = daemon.handle({"cmd": "status"})
        daemon.handle({"cmd": "memory_budget"})
        second = daemon.handle({"cmd": "status"})
        self.assertIs(first, second)


class StatusMemoryTest(unittest.TestCase):
    def test_host_only_snapshot_skips_scope_walk(self):
        from taema.core import memory

        # Freeze one live host sample across both calls: host memory moves
        # under concurrent allocation, so two wall-clock samples race and
        # flake. Both paths must still report the same host source.
        real_host = memory._host
        samples = []

        def _frozen(*args, **kwargs):
            if not samples:
                samples.append(real_host(*args, **kwargs))
            return samples[0]

        with mock.patch.object(memory, "_host", side_effect=_frozen):
            full = memory.snapshot()
            host_only = memory.snapshot(include_scopes=False)
        self.assertEqual(host_only["host"], full["host"])
        self.assertEqual(host_only["scopes"], [])
        self.assertEqual(host_only["schema"], "taema.memory.v1")

    def test_human_status_keeps_memory_line(self):
        import io
        from contextlib import redirect_stdout

        import taema.cli.commands as cli

        output = io.StringIO()
        with redirect_stdout(output):
            rc = cli.main(["status"])
        self.assertIn(rc, (0, 3))
        self.assertIn("memory:", output.getvalue())


if __name__ == "__main__":
    unittest.main()
