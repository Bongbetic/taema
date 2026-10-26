"""Actionable review notifications (issue #57).

Each new review produces one notification with Stop/Keep/Never/Details;
answers travel the same path as `taema answer`. Agent tests use a stub
notifier that prints scripted actions.
"""

import io
import os
import unittest
from contextlib import redirect_stdout
from unittest import mock

from taema import notifier
from tests.test_notifier import config, make_daemon, register


class StubNotifier:
    """Test notifier: prints sends, replays scripted actions."""

    name = "stub"

    def __init__(self, outcomes=(), caps=("send", "actions")):
        self._outcomes = list(outcomes)
        self._caps = set(caps)
        self.sent = []
        self.cancelled = []

    def capabilities(self):
        return set(self._caps)

    def server_capabilities(self):
        return ["actions", "body"]

    def send(self, summary, body, actions=(), **kwargs):
        print("notify: %s | %s" % (summary, ",".join(label for _key, label in actions)))
        self.sent.append((summary, body, list(actions), kwargs))
        return {"id": len(self.sent), "backend": "stub"}

    def wait_for_action(self, receipt, timeout):
        if self._outcomes:
            outcome = self._outcomes.pop(0)
        else:
            outcome = ("timeout", None)
        print("waited: %s" % (outcome[1] if outcome[0] == "action" else outcome[0],))
        return outcome

    def cancel_wait(self, receipt):
        self.cancelled.append(receipt)

    def close(self, nid):
        pass


class Clock:
    def __init__(self, now=2_000_000.0):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def make_review(store, owner="firefox"):
    review = store.add_review(
        owner,
        [{"key": "helper", "pid": 4242}],
        "leftover/firefox",
        memory=300 * 1024 * 1024,
    )
    assert review is not None
    return review


class ReviewJobTest(unittest.TestCase):
    def _poll(self, daemon, since=0):
        return daemon.handle(
            {
                "cmd": "notify_poll",
                "session": "s1",
                "pid": os.getpid(),
                "since_seq": since,
            }
        )

    def test_new_review_produces_one_notification(self):
        daemon = make_daemon()
        register(daemon)
        review = make_review(daemon.store)
        nonce = daemon._emit_review_job(review)
        self.assertIsNotNone(nonce)
        jobs = [job for job in self._poll(daemon)["jobs"] if job["kind"] == "review"]
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0]["nonce"], nonce)
        self.assertEqual(jobs[0]["review_id"], review["id"])
        self.assertEqual(jobs[0]["app"], "firefox")
        self.assertIn("helper", jobs[0]["detail"])

    def test_scope_reviews_are_not_notified(self):
        daemon = make_daemon()
        register(daemon)
        self.assertIsNone(daemon._emit_review_job({"kind": "scope", "state": "open"}))

    def test_no_jobs_when_notifications_are_off(self):
        from tests.test_phase0 import make_cfg, tmp
        from taema.daemon import service

        cfg = make_cfg(tmp(), mode="auto", notify={"enabled": False})
        daemon = service.Daemon(cfg)
        register(daemon)
        review = make_review(daemon.store)
        daemon._emit_review_job(review)
        self.assertEqual(self._poll(daemon)["jobs"], [])

    def test_no_jobs_without_an_agent(self):
        daemon = make_daemon()
        review = make_review(daemon.store)
        daemon._emit_review_job(review)
        self.assertEqual(daemon.notify_queues, {})

    def test_nonce_map_is_capped(self):
        daemon = make_daemon()
        register(daemon)
        for _ in range(130):
            review = make_review(daemon.store)
            daemon._emit_review_job(review)
        self.assertLessEqual(len(daemon.review_nonces), 128)


class ReviewResultTest(unittest.TestCase):
    def _answer(self, daemon, nonce, choice):
        return daemon.handle(
            {
                "cmd": "notify_result",
                "session": "s1",
                "pid": os.getpid(),
                "kind": "review",
                "nonce": nonce,
                "choice": choice,
            }
        )

    def test_review_answer_matches_taema_answer(self):
        daemon = make_daemon()
        register(daemon)
        review = make_review(daemon.store)
        nonce = daemon._emit_review_job(review)
        reply = self._answer(daemon, nonce, "stop")
        self.assertTrue(reply.get("ok"))
        resolved = next(
            r for r in daemon.store.data["reviews"] if r["id"] == review["id"]
        )
        self.assertEqual(resolved["state"], "answered")
        action, _conf, _why = daemon.store.pair_decision("firefox", "helper")
        self.assertEqual(action, "stop")

    def test_unknown_nonce_refused(self):
        daemon = make_daemon()
        register(daemon)
        self.assertIn("error", self._answer(daemon, "bogus", "keep"))

    def test_answered_review_refused(self):
        daemon = make_daemon()
        register(daemon)
        review = make_review(daemon.store)
        nonce = daemon._emit_review_job(review)
        self.assertTrue(self._answer(daemon, nonce, "keep").get("ok"))
        make_review(daemon.store)
        nonce2 = daemon._emit_review_job(daemon.store.data["reviews"][-1])
        # Answer the second review through the CLI path, then click its toast.
        daemon.handle(
            {
                "cmd": "feedback",
                "v": 2,
                "id": "cli-answer",
                "op": "review_answer",
                "review_id": daemon.store.data["reviews"][-1]["id"],
                "choice": "keep",
            }
        )
        self.assertIn("error", self._answer(daemon, nonce2, "keep"))

    def test_expired_review_refused(self):
        daemon = make_daemon()
        register(daemon)
        review = make_review(daemon.store)
        nonce = daemon._emit_review_job(review)
        for record in daemon.store.data["reviews"]:
            if record["id"] == review["id"]:
                record["expires"] = 1.0
        self.assertIn("error", self._answer(daemon, nonce, "keep"))

    def test_never_choice(self):
        daemon = make_daemon()
        register(daemon)
        review = make_review(daemon.store)
        nonce = daemon._emit_review_job(review)
        self.assertTrue(self._answer(daemon, nonce, "never").get("ok"))


class ReviewNotifyAgentTest(unittest.TestCase):
    def _handler(self, stub, now=2_000_000.0):
        clock = Clock(now)
        return notifier.JobHandler(
            {"notify": config()},
            stub,
            clock=clock,
            localtime=lambda now: (2026, 1, 1, 12, 0, 0, 0, 0, 0),
        )

    def _job(self, **fields):
        job = {
            "seq": 1,
            "created": 2_000_000.0,
            "ttl": 600,
            "kind": "review",
            "nonce": "n1",
            "review_id": 3,
            "app": "firefox",
            "detail": "helper x1 in leftover/firefox",
        }
        job.update(fields)
        return job

    def test_review_actions_and_wait(self):
        stub = StubNotifier(outcomes=[("action", "keep")])
        handler = self._handler(stub)
        reports = []
        output = io.StringIO()
        with redirect_stdout(output):
            handler.handle(
                [self._job()],
                "default",
                [],
                reports.append,
                keepalive=lambda: True,
            )
        text = output.getvalue()
        self.assertIn("Stop when it closes,Keep,Never,Details", text)
        self.assertIn("waited: keep", text)
        self.assertEqual(reports, [{"kind": "review", "nonce": "n1", "choice": "keep"}])

    def test_details_shows_detail_without_reporting(self):
        stub = StubNotifier(outcomes=[("action", "details")])
        handler = self._handler(stub)
        reports = []
        output = io.StringIO()
        with redirect_stdout(output):
            handler.handle(
                [self._job()],
                "default",
                [],
                reports.append,
                keepalive=lambda: True,
            )
        self.assertEqual(reports, [])
        self.assertIn("helper x1", stub.sent[1][1])

    def test_stale_click_shows_expired_toast(self):
        stub = StubNotifier(outcomes=[("action", "keep"), ("timeout", None)])
        handler = self._handler(stub)
        output = io.StringIO()
        with redirect_stdout(output):
            handler.handle(
                [self._job()],
                "default",
                [],
                lambda payload: {
                    "error": "review is missing, expired, or not answerable"
                },
                keepalive=lambda: True,
            )
        self.assertIn("question expired", output.getvalue())
        self.assertIn("Details", output.getvalue())

    def test_wait_slices_keepalive_and_abort_cancels(self):
        stub = StubNotifier(
            outcomes=[("timeout", None), ("timeout", None), ("action", "keep")]
        )
        handler = self._handler(stub)
        beats = []
        reports = []
        handler.handle(
            [self._job()],
            "default",
            [],
            reports.append,
            keepalive=lambda: beats.append(1) or True,
        )
        self.assertEqual(len(beats), 2)
        self.assertEqual(len(reports), 1)

        stub = StubNotifier(outcomes=[("timeout", None)])
        handler = self._handler(stub)
        handler.handle(
            [self._job()],
            "default",
            [],
            reports.append,
            keepalive=lambda: False,
        )
        self.assertEqual(len(stub.cancelled), 1)

    def test_no_actions_means_no_review_notification(self):
        stub = StubNotifier(caps=("send",))
        handler = self._handler(stub)
        handler.handle(
            [self._job()],
            "default",
            [],
            lambda payload: None,
            keepalive=lambda: True,
        )
        self.assertEqual(stub.sent, [])

    def test_muted_review_suppressed(self):
        stub = StubNotifier(outcomes=[("action", "keep")])
        handler = self._handler(stub)
        handler.handle(
            [self._job()],
            "default",
            ["firefox"],
            lambda payload: None,
            keepalive=lambda: True,
        )
        self.assertEqual(stub.sent, [])


class AgentReportTest(unittest.TestCase):
    def test_report_returns_the_daemon_reply(self):
        from taema import agent as agent_mod
        from tests.test_phase0 import make_cfg, tmp

        cfg = make_cfg(tmp(), notify={"backend": "null", "enabled": True})
        agent = agent_mod.Agent(cfg, "s1", backend=StubNotifier())
        with mock.patch.object(agent, "_ask", return_value={"ok": True}) as ask:
            self.assertEqual(agent._report({"kind": "undo"}), {"ok": True})
        self.assertEqual(ask.call_args[0][0]["cmd"], "notify_result")


if __name__ == "__main__":
    unittest.main()
