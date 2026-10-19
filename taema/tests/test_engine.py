import tempfile
import unittest
from unittest import mock

from taema.governor import engine
from taema.store import knowledge


def decide(
    members,
    edges,
    protected=(),
    seed_share=(),
    comms=None,
    ppids=None,
    force=False,
    hard=False,
    keep=(),
):
    """Run plan_stop with a fake process world. members: pids in the scope."""
    comms = comms or {p: "proc%d" % p for p in members}
    store = knowledge.Store(tempfile.mkdtemp(), {"share": list(seed_share), "kill": []})
    pp = ppids or {p: 1 for p in members}
    with (
        mock.patch.object(engine.cgroup, "tree_procs", return_value=list(members)),
        mock.patch.object(
            engine.inspect.ProcTable,
            "scan",
            return_value=engine.inspect.ProcTable.from_ppid(pp),
        ),
        mock.patch.object(engine.inspect, "Snapshot", return_value=None),
        mock.patch.object(engine.inspect, "edges", return_value=edges),
        mock.patch.object(engine.inspect, "comm", side_effect=lambda p: comms[p]),
        mock.patch.object(engine.policy, "exe_key", side_effect=lambda p: comms[p]),
        mock.patch.object(
            engine.policy,
            "protected_reason",
            side_effect=lambda p, c, pp=None: "protected" if p in protected else None,
        ),
    ):
        plan = engine.plan_stop("/x", {}, store, None, force, hard, keep)
    return {d["pid"]: d["action"] for d in plan}


EDGE = [{"kind": "unix_server", "detail": "/s", "peers": [999]}]


class PlanStop(unittest.TestCase):
    def test_plain_members_are_killed(self):
        self.assertEqual(decide([10, 11], {}), {10: "kill", 11: "kill"})

    def test_member_with_outside_user_is_shared(self):
        self.assertEqual(decide([10, 11], {11: EDGE}), {10: "kill", 11: "share"})

    def test_protected_is_skipped_even_with_edges(self):
        self.assertEqual(decide([10], {10: EDGE}, protected={10}), {10: "skip"})

    def test_seed_share_defers_kill(self):
        self.assertEqual(decide([10], {}, seed_share=["proc10"]), {10: "share"})

    def test_force_ignores_seed_but_not_edges(self):
        self.assertEqual(
            decide([10], {}, seed_share=["proc10"], force=True), {10: "kill"}
        )
        self.assertEqual(decide([10], {10: EDGE}, force=True), {10: "share"})

    def test_hard_ignores_edges(self):
        self.assertEqual(decide([10], {10: EDGE}, hard=True), {10: "kill"})

    def test_keep_flag(self):
        self.assertEqual(decide([10], {}, keep=["proc10"]), {10: "share"})

    def test_descendant_of_shared_moves_with_it(self):
        self.assertEqual(
            decide([10, 11], {10: EDGE}, ppids={10: 1, 11: 10}),
            {10: "share", 11: "share"},
        )

    def test_child_of_killed_parent_is_independent(self):
        self.assertEqual(
            decide([10, 11], {11: EDGE}, ppids={10: 1, 11: 10}),
            {10: "kill", 11: "share"},
        )


if __name__ == "__main__":
    unittest.main()
