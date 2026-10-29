"""Agent-leaf attach crosses cgroup boundaries via the privileged helper.

An agent started in a login session cannot write its own pid into the
agent leaf: the kernel's common-ancestor rule denies cross-subtree
cgroup.procs writes even when the destination file is user-writable.
The daemon must therefore fall back to the privileged helper (the same
path launch moves use) when the direct move is refused.
"""

import errno
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from taema.config import policy
from taema.core import cgroup
from taema.daemon import service
from taema.governor import engine
from tests.test_phase0 import FakeCg, make_cfg


def make_daemon(cfg):
    return SimpleNamespace(cfg=cfg, store=mock.Mock())


class AgentAttachTests(unittest.TestCase):
    def test_direct_move_used_inside_delegated_subtree(self):
        with tempfile.TemporaryDirectory() as state, FakeCg():
            daemon = make_daemon(make_cfg(state))
            with (
                mock.patch.object(cgroup, "move") as move,
                mock.patch.object(engine, "helper_move") as helper,
            ):
                result = service.Daemon.attach_agent(daemon, [1234])
            self.assertEqual(result, {"ok": True, "attached": [1234]})
            move.assert_called_once()
            helper.assert_not_called()

    def test_eacces_falls_back_to_helper(self):
        with tempfile.TemporaryDirectory() as state, FakeCg():
            daemon = make_daemon(make_cfg(state))
            denied = OSError(errno.EACCES, "Permission denied")
            with (
                mock.patch.object(cgroup, "move", side_effect=denied),
                mock.patch.object(engine, "helper_move") as helper,
            ):
                result = service.Daemon.attach_agent(daemon, [1234])
            self.assertEqual(result.get("attached"), [1234])
            self.assertNotIn("error", result)
            helper.assert_called_once()
            _, relpath, pids = helper.call_args[0]
            self.assertEqual(relpath, policy.AGENT_LEAF)
            self.assertEqual(list(pids), [1234])

    def test_helper_refusal_reports_error_with_partial_progress(self):
        with tempfile.TemporaryDirectory() as state, FakeCg():
            daemon = make_daemon(make_cfg(state))
            denied = OSError(errno.EACCES, "Permission denied")
            with (
                mock.patch.object(cgroup, "move", side_effect=denied),
                mock.patch.object(
                    engine, "helper_move", side_effect=engine.Refused("no sudo")
                ),
            ):
                result = service.Daemon.attach_agent(daemon, [1234])
            self.assertIn("error", result)
            self.assertEqual(result.get("attached"), [])


if __name__ == "__main__":
    unittest.main()
