"""Tests for notification policy, batching, and rendering (issue #58).

Pure policy: quiet hours, profiles, mutes, close batching, hourly caps,
the 200 MB floor with its signature-repeat exception, error dedup, and
plain/markup rendering. The clock is injected; no daemon, no backend.
"""

import io
import os
import unittest
from contextlib import redirect_stdout
from unittest import mock

from taema import notifier
from taema.cli import commands as cli
from taema.cli import registry
from taema.daemon import service
from taema.store.knowledge import Store
from tests.test_phase0 import make_cfg, tmp


def config(**overrides):
    cfg = {
        "enabled": True,
        "batch_seconds": 60,
        "max_per_hour": 6,
        "min_mem": "200M",
        "quiet_hours": "22:00-08:00",
        "digest": "off",
    }
    cfg.update(overrides)
    return cfg


class Clock:
    def __init__(self, now=1_000_000.0):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class QuietHoursTest(unittest.TestCase):
    def test_inside_quiet_hours(self):
        policy = notifier.NotifyPolicy(config(), clock=Clock())
        # 23:30 local.
        self.assertTrue(policy.quiet_now(1_000_000.0, "default", (2026, 9, 9, 23, 30)))

    def test_outside_quiet_hours(self):
        policy = notifier.NotifyPolicy(config(), clock=Clock())
        self.assertFalse(policy.quiet_now(1_000_000.0, "default", (2026, 9, 9, 12, 0)))

    def test_quiet_hours_wrap_midnight(self):
        policy = notifier.NotifyPolicy(config(), clock=Clock())
        self.assertTrue(policy.quiet_now(1_000_000.0, "default", (2026, 9, 9, 7, 59)))
        self.assertFalse(policy.quiet_now(1_000_000.0, "default", (2026, 9, 9, 8, 0)))

    def test_game_and_quiet_profiles_are_quiet(self):
        policy = notifier.NotifyPolicy(config(), clock=Clock())
        noon = (2026, 9, 9, 12, 0)
        self.assertTrue(policy.quiet_now(1_000_000.0, "game", noon))
        self.assertTrue(policy.quiet_now(1_000_000.0, "quiet", noon))
        self.assertFalse(policy.quiet_now(1_000_000.0, "focus", noon))

    def test_disabled_means_quiet(self):
        policy = notifier.NotifyPolicy(config(enabled=False), clock=Clock())
        self.assertTrue(policy.quiet_now(1_000_000.0, "default", (2026, 9, 9, 12, 0)))

    def test_muted_app(self):
        policy = notifier.NotifyPolicy(config(), clock=Clock(), mutes=["firefox"])
        self.assertTrue(policy.muted("firefox"))
        self.assertFalse(policy.muted("foot"))


class CloseBatchingTest(unittest.TestCase):
    def test_first_close_opens_a_batch(self):
        clock = Clock()
        policy = notifier.NotifyPolicy(config(), clock=clock)
        verdict = policy.close_event("firefox", 300 * 1024 * 1024, 1, clock())
        self.assertEqual(verdict[0], "batch")
        self.assertEqual(policy.flush(clock()), [])

    def test_batch_flushes_after_window(self):
        clock = Clock()
        policy = notifier.NotifyPolicy(config(), clock=clock)
        policy.close_event("firefox", 300 * 1024 * 1024, 1, clock())
        policy.close_event("firefox", 100 * 1024 * 1024, 3, clock() + 10)
        flushed = policy.flush(clock() + 61)
        self.assertEqual(len(flushed), 1)
        self.assertEqual(flushed[0]["closes"], 2)
        self.assertEqual(flushed[0]["freed"], 400 * 1024 * 1024)

    def test_small_close_is_skipped(self):
        clock = Clock()
        policy = notifier.NotifyPolicy(config(), clock=clock)
        verdict = policy.close_event("foot", 50 * 1024 * 1024, 1, clock())
        self.assertEqual(verdict, ("skip", "under-200M"))
        self.assertEqual(policy.flush(clock() + 61), [])

    def test_repeated_signature_overrides_the_floor(self):
        clock = Clock()
        policy = notifier.NotifyPolicy(config(), clock=clock)
        verdict = policy.close_event("foot", 50 * 1024 * 1024, 3, clock())
        self.assertEqual(verdict[0], "batch")

    def test_hourly_cap(self):
        clock = Clock()
        policy = notifier.NotifyPolicy(config(), clock=clock)
        for index in range(6):
            policy.note_sent(clock() + index)
        self.assertFalse(policy.within_cap(clock() + 7))
        self.assertTrue(policy.within_cap(clock() + 3601))

    def test_capped_batch_is_dropped(self):
        clock = Clock()
        policy = notifier.NotifyPolicy(config(), clock=clock)
        for index in range(6):
            policy.note_sent(clock())
        policy.close_event("firefox", 300 * 1024 * 1024, 1, clock())
        self.assertEqual(policy.flush(clock() + 61), [])
        self.assertEqual(policy.dropped(), 1)

    def test_storm_of_50_closes_stays_within_caps(self):
        clock = Clock()
        policy = notifier.NotifyPolicy(config(), clock=clock)
        for index in range(50):
            policy.close_event(
                "app-%d" % (index % 5), 300 * 1024 * 1024, 1, clock() + index
            )
        shown = 0
        for tick in range(0, 3700, 61):
            for _batch in policy.flush(clock() + tick):
                if policy.within_cap(clock() + tick):
                    policy.note_sent(clock() + tick)
                    shown += 1
        self.assertLessEqual(shown, 6)


class ErrorDedupTest(unittest.TestCase):
    def test_once_per_day_per_kind(self):
        clock = Clock()
        policy = notifier.NotifyPolicy(config(), clock=clock)
        self.assertTrue(policy.error_allowed("store-recovery", clock()))
        policy.note_error("store-recovery", clock())
        self.assertFalse(policy.error_allowed("store-recovery", clock() + 100))
        self.assertTrue(policy.error_allowed("guard", clock() + 100))
        self.assertTrue(policy.error_allowed("store-recovery", clock() + 86401))


class RenderTest(unittest.TestCase):
    def test_close_batch_is_plain(self):
        summary, body, _actions = notifier.render_close_batch(
            "firefox", 3, 812 * 1024 * 1024, markup_ok=False
        )
        self.assertIn("firefox", summary)
        self.assertIn("3", summary)
        self.assertIn("812 MB", body)
        self.assertNotIn("<", summary + body)

    def test_markup_only_when_supported(self):
        plain = notifier.render_close_batch("x", 1, 10, markup_ok=False)
        rich = notifier.render_close_batch("x", 1, 10, markup_ok=True)
        self.assertNotIn("<b>", plain[0] + plain[1])
        self.assertIn("<b>", rich[0] + rich[1])

    def test_undo_toast(self):
        summary, _body, actions = notifier.render_undo(
            "stop", "firefox", 812 * 1024 * 1024, markup_ok=False
        )
        self.assertIn("812 MB", summary)
        self.assertEqual(actions, [("undo", "Undo")])

    def test_undo_freeze_names_the_scope(self):
        summary, _body, actions = notifier.render_undo(
            "freeze", "app-firefox", 0, markup_ok=False
        )
        self.assertIn("app-firefox", summary)
        self.assertEqual(actions, [("undo", "Undo")])

    def test_countdown(self):
        summary, body, actions = notifier.render_countdown(
            "firefox", 30, markup_ok=False
        )
        self.assertIn("firefox", summary)
        self.assertIn("30", body)
        self.assertEqual(actions, [("keep", "Keep"), ("stop", "Stop now")])

    def test_guard_notice(self):
        summary, body, actions = notifier.render_guard(
            "reclaimed 200 MB under pressure", markup_ok=False
        )
        self.assertIn("200 MB", summary + body)
        self.assertEqual(actions, [])

    def test_error_notice(self):
        summary, _body, _actions = notifier.render_error(
            "store-recovery", "state rebuilt from export", markup_ok=False
        )
        self.assertIn("store-recovery", summary)


class RenderDigestTest(unittest.TestCase):
    def test_digest_counts(self):
        summary, body, actions = notifier.render_digest(
            {"stops_24h": 3, "frozen": 1, "guard_bytes": 2048, "reviews": 2},
            markup_ok=False,
        )
        self.assertIn("digest", summary)
        self.assertIn("3", body)
        self.assertEqual(actions, [])

    def test_digest_markup(self):
        _summary, body, _actions = notifier.render_digest(
            {"stops_24h": 0, "frozen": 0, "guard_bytes": 0, "reviews": 0},
            markup_ok=True,
        )
        self.assertIn("<b>", body)


class FakeBackend:
    name = "fake"

    def __init__(self, caps=("send", "actions"), outcomes=()):
        self._caps = set(caps)
        self._outcomes = list(outcomes)
        self.sent = []
        self.waits = 0

    def capabilities(self):
        return set(self._caps)

    def server_capabilities(self):
        return ["actions", "body-markup"]

    def send(self, summary, body, actions=(), **kwargs):
        self.sent.append((summary, body, list(actions), kwargs))
        return {"id": len(self.sent), "backend": "fake"}

    def wait_for_action(self, receipt, timeout):
        self.waits += 1
        if self._outcomes:
            return self._outcomes.pop(0)
        return ("timeout", None)

    def close(self, nid):
        pass


class JobHandlerTest(unittest.TestCase):
    def _handler(self, backend=None, now=1_000_000.0, hour=12):
        clock = Clock()
        clock.now = now
        handler = notifier.JobHandler(
            {"notify": config()},
            backend or FakeBackend(),
            clock=clock,
            localtime=lambda now: (2026, 1, 1, hour, 0, 0, 0, 0, 0),
        )
        return handler, clock

    def _job(self, kind, seq=1, **fields):
        job = {"seq": seq, "created": 1_000_000.0, "ttl": 600, "kind": kind}
        job.update(fields)
        return job

    def test_close_batch_shows_after_window(self):
        handler, clock = self._handler()
        reports = []
        handler.handle(
            [self._job("close", app="firefox", mem_bytes=300 * 1024**2, sig_repeats=1)],
            "default",
            [],
            reports.append,
        )
        self.assertEqual(handler.backend.sent, [])
        clock.advance(61)
        handler.handle([], "default", [], reports.append)
        self.assertEqual(len(handler.backend.sent), 1)
        self.assertIn("firefox", handler.backend.sent[0][0])

    def test_undo_click_reports(self):
        backend = FakeBackend(outcomes=[("action", "undo")])
        handler, _clock = self._handler(backend)
        reports = []
        handler.handle(
            [
                self._job(
                    "undo",
                    action="stop",
                    decision_id=9,
                    scope="s",
                    apps=["vite"],
                    freed_bytes=10,
                )
            ],
            "default",
            [],
            reports.append,
        )
        self.assertEqual(reports, [{"kind": "undo", "decision_id": 9}])

    def test_undo_timeout_reports_nothing(self):
        handler, _clock = self._handler()
        reports = []
        handler.handle(
            [self._job("undo", action="stop", decision_id=9, scope="s", apps=[])],
            "default",
            [],
            reports.append,
        )
        self.assertEqual(reports, [])

    def test_undo_without_action_caps_is_plain(self):
        backend = FakeBackend(caps=("send",))
        handler, _clock = self._handler(backend)
        handler.handle(
            [self._job("undo", action="stop", decision_id=9, scope="s", apps=[])],
            "default",
            [],
            lambda payload: None,
        )
        self.assertEqual(len(backend.sent), 1)
        self.assertEqual(backend.sent[0][2], [])
        self.assertEqual(backend.waits, 0)

    def test_countdown_keep_and_stop(self):
        for choice, outcome in (
            ("keep", ("action", "keep")),
            ("stop", ("action", "stop")),
        ):
            backend = FakeBackend(outcomes=[outcome])
            handler, _clock = self._handler(backend)
            reports = []
            handler.handle(
                [self._job("countdown", nonce="n", app="firefox", seconds=30)],
                "default",
                [],
                reports.append,
            )
            self.assertEqual(
                reports, [{"kind": "countdown", "nonce": "n", "choice": choice}]
            )

    def test_expired_countdown_is_skipped(self):
        backend = FakeBackend(outcomes=[("action", "keep")])
        handler, clock = self._handler(backend)
        clock.advance(120)
        reports = []
        handler.handle(
            [self._job("countdown", nonce="n", app="firefox", seconds=30)],
            "default",
            [],
            reports.append,
        )
        self.assertEqual(reports, [])
        self.assertEqual(backend.sent, [])

    def test_guard_error_digest_send(self):
        handler, _clock = self._handler()
        handler.handle(
            [
                self._job("guard", trigger="psi", bytes_freed=2048),
                self._job(
                    "error", seq=2, error_kind="store-recovery", detail="rebuilt"
                ),
                self._job(
                    "digest", seq=3, stops_24h=1, frozen=0, guard_bytes=0, reviews=0
                ),
            ],
            "default",
            [],
            lambda payload: None,
        )
        self.assertEqual(len(handler.backend.sent), 3)

    def test_error_dedup(self):
        handler, _clock = self._handler()
        job = self._job("error", error_kind="k", detail="d")
        handler.handle([job], "default", [], lambda payload: None)
        handler.handle([dict(job, seq=2)], "default", [], lambda payload: None)
        self.assertEqual(len(handler.backend.sent), 1)

    def test_quiet_hours_suppress(self):
        handler, _clock = self._handler(hour=23)
        handler.handle(
            [self._job("guard", trigger="psi", bytes_freed=1)],
            "default",
            [],
            lambda payload: None,
        )
        self.assertEqual(handler.backend.sent, [])

    def test_muted_app_suppressed(self):
        handler, _clock = self._handler()
        handler.handle(
            [
                self._job(
                    "close", app="firefox", mem_bytes=300 * 1024**2, sig_repeats=1
                ),
                self._job("countdown", seq=2, nonce="n", app="firefox", seconds=30),
            ],
            "default",
            ["firefox"],
            lambda payload: None,
        )
        self.assertEqual(handler.backend.sent, [])

    def test_markup_flows_to_backend(self):
        handler, _clock = self._handler()
        handler.handle(
            [self._job("guard", trigger="psi", bytes_freed=1)],
            "default",
            [],
            lambda payload: None,
        )
        self.assertTrue(handler.backend.sent[0][3].get("markup"))

    def test_unknown_kind_and_backend_errors_ignored(self):
        class Failing(FakeBackend):
            def send(self, summary, body, actions=(), **kwargs):
                from taema import notify as notify_mod

                raise notify_mod.NotifyError("boom")

        handler, _clock = self._handler(Failing())
        handler.handle(
            [self._job("bogus"), self._job("guard", seq=2, trigger="t", bytes_freed=1)],
            "default",
            [],
            lambda payload: None,
        )


class AgentNotifyTest(unittest.TestCase):
    def test_null_backend_has_no_notify_caps(self):
        from taema import agent as agent_mod

        cfg = make_cfg(tmp(), notify={"backend": "null", "enabled": True})
        agent = agent_mod.Agent(cfg, "s1")
        self.assertNotIn("notify", agent.capabilities)
        self.assertNotIn("notify-actions", agent.capabilities)

    def test_action_backend_adds_caps(self):
        from taema import agent as agent_mod

        cfg = make_cfg(tmp(), notify={"backend": "auto", "enabled": True})
        agent = agent_mod.Agent(cfg, "s1", backend=FakeBackend())
        self.assertIn("notify", agent.capabilities)
        self.assertIn("notify-actions", agent.capabilities)

    def test_poll_once_sends_and_advances(self):
        from taema import agent as agent_mod

        cfg = make_cfg(tmp(), notify={"backend": "null", "enabled": True})
        backend = FakeBackend()
        agent = agent_mod.Agent(cfg, "s1", backend=backend)
        seen = []

        def ask(message):
            seen.append(message)
            if message["cmd"] == "notify_poll":
                return {
                    "jobs": [
                        {
                            "seq": 4,
                            "created": 1_000_000.0,
                            "ttl": 600,
                            "kind": "guard",
                            "trigger": "psi",
                            "bytes_freed": 8,
                        }
                    ],
                    "profile": "default",
                    "mutes": [],
                }
            return {"ok": True}

        with mock.patch.object(agent, "_ask", side_effect=ask):
            with mock.patch(
                "time.localtime", return_value=(2026, 9, 9, 12, 0, 0, 0, 0, 0)
            ):
                agent.poll_once()
        self.assertEqual(len(backend.sent), 1)
        polls = [msg for msg in seen if msg["cmd"] == "notify_poll"]
        self.assertEqual(polls[0]["since_seq"], 0)
        self.assertEqual(agent.cursor, 4)

    def test_poll_once_tolerates_a_down_daemon(self):
        from taema import agent as agent_mod

        cfg = make_cfg(tmp(), notify={"backend": "null", "enabled": True})
        agent = agent_mod.Agent(cfg, "s1", backend=FakeBackend())
        with mock.patch.object(agent, "_ask", return_value=None):
            agent.poll_once()


class FormatTest(unittest.TestCase):
    def test_format_mb(self):
        self.assertEqual(notifier.format_mb(812 * 1024 * 1024), "812 MB")
        self.assertEqual(notifier.format_mb(1536 * 1024 * 1024), "1.5 GB")
        self.assertEqual(notifier.format_mb(512 * 1024), "0 MB")


class MuteStoreTest(unittest.TestCase):
    def setUp(self):
        self.dir = tmp()
        self.store = Store(self.dir, {}, Clock())

    def test_mute_and_unmute_roundtrip(self):
        self.store.apply_feedback_command(
            {"v": 2, "id": "m1", "op": "mute", "app": "firefox", "muted": True}
        )
        self.assertEqual(self.store.data["muted_apps"], ["firefox"])
        self.store.apply_feedback_command(
            {"v": 2, "id": "m2", "op": "mute", "app": "firefox", "muted": False}
        )
        self.assertEqual(self.store.data["muted_apps"], [])

    def test_mutes_persist(self):
        self.store.apply_feedback_command(
            {"v": 2, "id": "m1", "op": "mute", "app": "firefox", "muted": True}
        )
        self.store.save()
        reopened = Store(self.dir, {}, Clock())
        self.assertEqual(reopened.data["muted_apps"], ["firefox"])

    def test_mute_rejects_empty_app(self):
        self.assertIsNone(
            self.store.apply_feedback_command(
                {"v": 2, "id": "m3", "op": "mute", "app": "", "muted": True}
            )
        )
        self.assertEqual(self.store.data["muted_apps"], [])


class MuteCliTest(unittest.TestCase):
    def setUp(self):
        self.dir = tmp()
        self.cfg = make_cfg(self.dir, mode="auto")
        self.store = Store(self.dir, {}, Clock())
        self.daemon = service.Daemon(self.cfg)

    def _run(self, argv):
        next_id = [0]

        def feedback(_cfg, _store, op, **fields):
            next_id[0] += 1
            return "daemon", self.daemon.handle(
                {
                    "cmd": "feedback",
                    "v": 2,
                    "id": "mute-cli-%d" % next_id[0],
                    "op": op,
                    **fields,
                }
            )

        output = io.StringIO()
        with (
            mock.patch.object(cli, "_load", return_value=(self.cfg, self.store, [])),
            mock.patch.object(cli, "feedback_action", side_effect=feedback),
            redirect_stdout(output),
        ):
            code = cli.main(argv)
        return code, output.getvalue()

    def test_mute_command(self):
        code, output = self._run(["mute", "firefox"])
        self.assertEqual(code, 0)
        self.assertIn("firefox", output)
        self.assertIn("firefox", self.daemon.store.data["muted_apps"])

    def test_unmute_command(self):
        self.daemon.store.data["muted_apps"] = ["firefox"]
        code, _output = self._run(["unmute", "firefox"])
        self.assertEqual(code, 0)
        self.assertEqual(self.daemon.store.data["muted_apps"], [])

    def test_bare_mute_lists(self):
        self.store.data["muted_apps"] = ["firefox"]
        code, output = self._run(["mute"])
        self.assertEqual(code, 0)
        self.assertIn("firefox", output)

    def test_registry_has_mute_commands(self):
        names = {entry["name"] for entry in registry.COMMANDS}
        self.assertIn("mute", names)
        self.assertIn("unmute", names)


def make_daemon(mode="auto"):
    cfg = make_cfg(tmp(), mode=mode)
    return service.Daemon(cfg)


def register(daemon, session="s1", capabilities=("heartbeat", "notify-actions")):
    import os

    return daemon.handle(
        {
            "cmd": "register_agent",
            "session": session,
            "pid": os.getpid(),
            "capabilities": list(capabilities),
            "compositor": "/run/user/1000/wayland-0",
        }
    )


class NotifyPollTest(unittest.TestCase):
    def test_poll_requires_a_registered_session(self):
        daemon = make_daemon()
        reply = daemon.handle(
            {"cmd": "notify_poll", "session": "nope", "pid": 424242, "since_seq": 0}
        )
        self.assertIn("error", reply)

    def test_poll_rejects_foreign_pid(self):
        daemon = make_daemon()
        register(daemon)
        reply = daemon.handle(
            {"cmd": "notify_poll", "session": "s1", "pid": 424242, "since_seq": 0}
        )
        self.assertIn("error", reply)

    def test_poll_returns_jobs_profile_and_mutes(self):
        import os

        daemon = make_daemon()
        register(daemon)
        daemon.store.data["muted_apps"] = ["firefox"]
        daemon.notify_agents({"kind": "guard", "detail": "reclaimed 1 MB"})
        reply = daemon.handle(
            {"cmd": "notify_poll", "session": "s1", "pid": os.getpid(), "since_seq": 0}
        )
        self.assertEqual(len(reply["jobs"]), 1)
        self.assertEqual(reply["jobs"][0]["kind"], "guard")
        self.assertIn("profile", reply)
        self.assertEqual(reply["mutes"], ["firefox"])
        again = daemon.handle(
            {
                "cmd": "notify_poll",
                "session": "s1",
                "pid": os.getpid(),
                "since_seq": reply["jobs"][0]["seq"],
            }
        )
        self.assertEqual(again["jobs"], [])

    def test_expired_jobs_are_dropped(self):
        import os
        import time

        daemon = make_daemon()
        register(daemon)
        with mock.patch.object(time, "time", return_value=1000.0):
            daemon.notify_agents({"kind": "guard", "detail": "old", "ttl": 10})
        reply = daemon.handle(
            {"cmd": "notify_poll", "session": "s1", "pid": os.getpid(), "since_seq": 0}
        )
        self.assertEqual(reply["jobs"], [])

    def test_queue_is_capped(self):
        daemon = make_daemon()
        register(daemon)
        for index in range(70):
            daemon.notify_agents({"kind": "close", "app": "a%d" % index})
        self.assertLessEqual(len(daemon.notify_queues["s1"]), 64)


class NotifyResultTest(unittest.TestCase):
    def _countdown(self, daemon, **overrides):
        import time as time_mod

        now = time_mod.time()
        record = {
            "nonce": "n1",
            "scope": "leftover/firefox",
            "path": "/sys/fs/cgroup/taema/leftover/firefox",
            "app": "firefox",
            "pairs": [["firefox", "helper"]],
            "signature": None,
            "why": "learned stop",
            "require_pair": True,
            "authority": "pair",
            "trigger": "countdown-test",
            "deadline": now + 30,
            "created": now,
        }
        record.update(overrides)
        daemon.countdowns[record["nonce"]] = record
        return record

    def test_result_requires_a_registered_session(self):
        daemon = make_daemon()
        reply = daemon.handle(
            {
                "cmd": "notify_result",
                "session": "nope",
                "pid": 424242,
                "kind": "countdown",
                "nonce": "n1",
                "choice": "keep",
            }
        )
        self.assertIn("error", reply)

    def test_unknown_kind_refused(self):
        import os

        daemon = make_daemon()
        register(daemon)
        reply = daemon.handle(
            {
                "cmd": "notify_result",
                "session": "s1",
                "pid": os.getpid(),
                "kind": "review",
                "nonce": "n1",
            }
        )
        self.assertIn("error", reply)

    def test_countdown_keep_records_keep_evidence_and_suspends(self):
        import os

        daemon = make_daemon()
        register(daemon)
        self._countdown(daemon)
        reply = daemon.handle(
            {
                "cmd": "notify_result",
                "session": "s1",
                "pid": os.getpid(),
                "kind": "countdown",
                "nonce": "n1",
                "choice": "keep",
            }
        )
        self.assertTrue(reply.get("ok"))
        self.assertNotIn("n1", daemon.countdowns)
        pair = daemon.store._pair("firefox", "helper")
        import time as time_mod

        self.assertAlmostEqual(
            pair.get("suspended_until", 0), time_mod.time() + 7 * 86400, delta=30
        )
        self.assertGreater(pair.get("ex_keep", 0), 0)

    def test_countdown_stop_executes_the_stop(self):
        import os

        daemon = make_daemon()
        register(daemon)
        record = self._countdown(daemon)
        with mock.patch.object(daemon, "auto_stop_path", return_value=True) as stopper:
            reply = daemon.handle(
                {
                    "cmd": "notify_result",
                    "session": "s1",
                    "pid": os.getpid(),
                    "kind": "countdown",
                    "nonce": "n1",
                    "choice": "stop",
                }
            )
        self.assertTrue(reply.get("ok"))
        self.assertNotIn("n1", daemon.countdowns)
        stopper.assert_called_once_with(
            record["path"],
            record["why"],
            record["require_pair"],
            authority=record["authority"],
            trigger=record["trigger"],
            _countdown_approved=True,
        )

    def test_countdown_bad_nonce_refused(self):
        import os

        daemon = make_daemon()
        register(daemon)
        reply = daemon.handle(
            {
                "cmd": "notify_result",
                "session": "s1",
                "pid": os.getpid(),
                "kind": "countdown",
                "nonce": "bogus",
                "choice": "keep",
            }
        )
        self.assertIn("error", reply)

    def test_countdown_expires_through_deadlines(self):
        daemon = make_daemon()
        register(daemon)
        self._countdown(daemon, deadline=100.0)
        daemon.add_deadline(100.0, "countdown", "n1")
        with (
            mock.patch.object(daemon, "auto_stop_path", return_value=True) as stopper,
            mock.patch("time.time", return_value=200.0),
        ):
            daemon.run_deadlines()
        self.assertNotIn("n1", daemon.countdowns)
        stopper.assert_called_once()
        self.assertTrue(stopper.call_args.kwargs.get("_countdown_approved"))

    def test_veto_cancels_a_matching_countdown(self):
        daemon = make_daemon()
        register(daemon)
        self._countdown(daemon)
        reply = daemon.handle(
            {
                "cmd": "feedback",
                "v": 2,
                "id": "veto-1",
                "op": "veto",
                "target": {"kind": "app", "value": "firefox"},
            }
        )
        self.assertNotIn("error", reply)
        self.assertNotIn("n1", daemon.countdowns)

    def test_unrelated_veto_keeps_the_countdown(self):
        daemon = make_daemon()
        register(daemon)
        self._countdown(daemon)
        daemon.handle(
            {
                "cmd": "feedback",
                "v": 2,
                "id": "veto-2",
                "op": "veto",
                "target": {"kind": "app", "value": "foot"},
            }
        )
        self.assertIn("n1", daemon.countdowns)

    def test_undo_result_reverses_and_regrets(self):
        import os

        daemon = make_daemon()
        register(daemon)
        action = daemon.store.record_auto_action(
            "leftover/vite", "pair stop", [("npm", "vite")], ["vite"]
        )
        pair = daemon.store._pair("npm", "vite")
        pair["last_auto_stop"] = daemon.store.now()
        decision_id = action["decision_id"]
        daemon.notify_agents(
            {
                "kind": "undo",
                "decision_id": decision_id,
                "owner": "npm",
                "leftover": "vite",
            }
        )
        reply = daemon.handle(
            {
                "cmd": "notify_result",
                "session": "s1",
                "pid": os.getpid(),
                "kind": "undo",
                "decision_id": decision_id,
            }
        )
        self.assertTrue(reply.get("ok"))
        self.assertIsNotNone(daemon.store.decision(decision_id).get("undone"))
        self.assertGreater(pair.get("regret_keep", 0), 0)

    def test_undo_unknown_decision_refused(self):
        import os

        daemon = make_daemon()
        register(daemon)
        reply = daemon.handle(
            {
                "cmd": "notify_result",
                "session": "s1",
                "pid": os.getpid(),
                "kind": "undo",
                "decision_id": 424242,
            }
        )
        self.assertIn("error", reply)


class StopEmissionTest(unittest.TestCase):
    def test_auto_stop_queues_an_undo_job(self):
        import os

        daemon = make_daemon()
        register(daemon)
        with daemon.store.decision_context("stop", scope="leftover/x") as decision:
            daemon.note_auto_stop(
                "leftover/x",
                "pair stop",
                [("firefox", "helper")],
                apps=["helper"],
                decision=decision,
                owner="firefox",
                freed_bytes=812 * 1024 * 1024,
            )
        reply = daemon.handle(
            {"cmd": "notify_poll", "session": "s1", "pid": os.getpid(), "since_seq": 0}
        )
        jobs = [job for job in reply["jobs"] if job["kind"] == "undo"]
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0]["decision_id"], decision["id"])
        self.assertEqual(jobs[0]["freed_bytes"], 812 * 1024 * 1024)
        self.assertEqual(jobs[0]["action"], "stop")

    def test_no_queue_without_an_agent(self):
        daemon = make_daemon()
        with daemon.store.decision_context("stop", scope="leftover/x") as decision:
            daemon.note_auto_stop("leftover/x", "why", [], decision=decision)
        self.assertEqual(daemon.notify_queues, {})


class FreezeEmissionTest(unittest.TestCase):
    def setUp(self):
        from tests.test_phase0 import FakeCg

        self.cg = FakeCg().__enter__()
        self.addCleanup(self.cg.__exit__)
        self.scope = "leftover/browser"
        self.path = self.cg.leaf(self.scope, [4242], cpu=0)
        with open(os.path.join(self.path, "cgroup.freeze"), "w") as handle:
            handle.write("0\n")
        self.cfg = make_cfg(
            os.path.join(self.cg.root, "state"),
            mode="enforce",
            freeze={
                "enabled": True,
                "adopt": False,
                "after": 120,
                "wake_on_connect": False,
                "max_frozen": 32,
                "cpu_idle_max": 100.0,
            },
            experimental={"freeze": True},
        )
        self.daemon = service.Daemon(self.cfg)
        self.daemon.lineage = mock.Mock()
        self.daemon.lineage.entry.return_value = {"start": 100, "key": "app:browser"}
        self.daemon.lineage.ptmx_host.return_value = False

    def test_auto_freeze_queues_an_undo_job(self):
        import os

        register(self.daemon)
        with (
            mock.patch.object(
                self.daemon, "_wait_for_cgroup_frozen", return_value=True
            ),
            mock.patch.object(
                self.daemon, "_freeze_safety_facts", return_value=(None, [])
            ),
        ):
            result = self.daemon.freeze_scope(self.scope)
        self.assertTrue(result.get("ok"))
        reply = self.daemon.handle(
            {"cmd": "notify_poll", "session": "s1", "pid": os.getpid(), "since_seq": 0}
        )
        jobs = [job for job in reply["jobs"] if job["kind"] == "undo"]
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0]["action"], "freeze")
        decision = self.daemon.store.decision(jobs[0]["decision_id"])
        self.assertEqual(decision["undo"]["operation"], "thaw")

    def test_manual_freeze_is_silent(self):
        import os

        register(self.daemon)
        with (
            mock.patch.object(
                self.daemon, "_wait_for_cgroup_frozen", return_value=True
            ),
            mock.patch.object(
                self.daemon, "_freeze_safety_facts", return_value=(None, [])
            ),
            mock.patch.object(
                self.daemon, "_manual_freeze_cpu_reason", return_value=None
            ),
        ):
            result = self.daemon.freeze_scope(self.scope, manual=True)
        self.assertTrue(result.get("ok"))
        reply = self.daemon.handle(
            {"cmd": "notify_poll", "session": "s1", "pid": os.getpid(), "since_seq": 0}
        )
        self.assertEqual([job for job in reply["jobs"] if job["kind"] == "undo"], [])


class GuardEmissionTest(unittest.TestCase):
    def test_guard_finish_queues_a_notice(self):
        import os
        import time as time_mod

        daemon = make_daemon()
        register(daemon)
        daemon.guard_state.update(
            trigger="pressure",
            steps=[{"stage": "page_cache"}],
            bytes_freed=1024,
            triggers=["psi"],
        )
        daemon.guard_started_monotonic = time_mod.monotonic()
        daemon._finish_guard("reclaimed")
        reply = daemon.handle(
            {"cmd": "notify_poll", "session": "s1", "pid": os.getpid(), "since_seq": 0}
        )
        jobs = [job for job in reply["jobs"] if job["kind"] == "guard"]
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0]["bytes_freed"], 1024)

    def test_guard_without_reclaim_is_silent(self):
        import os
        import time as time_mod

        daemon = make_daemon()
        register(daemon)
        daemon.guard_state.update(trigger="pressure", steps=[], bytes_freed=0)
        daemon.guard_started_monotonic = time_mod.monotonic()
        daemon._finish_guard("nothing to reclaim")
        reply = daemon.handle(
            {"cmd": "notify_poll", "session": "s1", "pid": os.getpid(), "since_seq": 0}
        )
        self.assertEqual([job for job in reply["jobs"] if job["kind"] == "guard"], [])


class CloseEmissionTest(unittest.TestCase):
    def _daemon(self):
        from tests.test_phase0 import FakeCg

        cg = FakeCg().__enter__()
        self.addCleanup(cg.__exit__)
        cfg = make_cfg(os.path.join(cg.root, "state"), mode="enforce")
        daemon = service.Daemon(cfg)
        return cg, daemon

    def test_clean_close_queues_a_close_job(self):
        import os

        cg, daemon = self._daemon()
        register(daemon)
        leaf = cg.leaf("leftover/clean", [], cpu=0)
        _leaf_rel = os.path.basename(os.path.dirname(leaf)) + "/clean"
        with (
            mock.patch.object(
                service.engine, "stop", return_value={"removed": True, "stopped": []}
            ),
            mock.patch.object(daemon, "_scope_bytes", return_value=300 * 1024 * 1024),
        ):
            daemon.stop_leaf("leftover/clean", "owner 5 exited", owner=5)
        reply = daemon.handle(
            {"cmd": "notify_poll", "session": "s1", "pid": os.getpid(), "since_seq": 0}
        )
        jobs = [job for job in reply["jobs"] if job["kind"] == "close"]
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0]["mem_bytes"], 300 * 1024 * 1024)

    def test_close_repeats_are_counted(self):
        daemon = make_daemon()
        self.assertEqual(daemon._note_close("firefox"), 1)
        self.assertEqual(daemon._note_close("firefox"), 2)
        self.assertEqual(daemon._note_close("foot"), 1)


class RecoveryEmissionTest(unittest.TestCase):
    def test_recovery_queues_one_error_job(self):
        import os

        daemon = make_daemon()
        daemon.store.recovery = {"source": "export", "at": 1.0}
        register(daemon)
        reply = daemon.handle(
            {"cmd": "notify_poll", "session": "s1", "pid": os.getpid(), "since_seq": 0}
        )
        jobs = [job for job in reply["jobs"] if job["kind"] == "error"]
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0]["error_kind"], "store-recovery")
        register(daemon)
        again = daemon.handle(
            {
                "cmd": "notify_poll",
                "session": "s1",
                "pid": os.getpid(),
                "since_seq": reply["jobs"][-1]["seq"],
            }
        )
        self.assertEqual([job for job in again["jobs"] if job["kind"] == "error"], [])


class DigestTest(unittest.TestCase):
    def test_daily_digest_when_enabled(self):
        import os

        cfg = make_cfg(tmp(), mode="auto", notify={"digest": "daily"})
        daemon = service.Daemon(cfg)
        register(daemon)
        reply = daemon.handle(
            {"cmd": "notify_poll", "session": "s1", "pid": os.getpid(), "since_seq": 0}
        )
        digests = [job for job in reply["jobs"] if job["kind"] == "digest"]
        self.assertEqual(len(digests), 1)
        self.assertIn("stops_24h", digests[0])
        again = daemon.handle(
            {
                "cmd": "notify_poll",
                "session": "s1",
                "pid": os.getpid(),
                "since_seq": reply["jobs"][-1]["seq"],
            }
        )
        self.assertEqual([job for job in again["jobs"] if job["kind"] == "digest"], [])

    def test_no_digest_when_off(self):
        import os

        daemon = make_daemon()
        register(daemon)
        reply = daemon.handle(
            {"cmd": "notify_poll", "session": "s1", "pid": os.getpid(), "since_seq": 0}
        )
        self.assertEqual([job for job in reply["jobs"] if job["kind"] == "digest"], [])


class StatusMutedTest(unittest.TestCase):
    def test_daemon_status_reports_mutes(self):
        cfg = make_cfg(tmp(), mode="auto")
        daemon = service.Daemon(cfg)
        daemon.store.data["muted_apps"] = ["firefox"]
        reply = daemon.handle({"cmd": "status"})
        self.assertEqual(reply["muted"], ["firefox"])

    def test_status_view_renders_mutes(self):
        from taema.cli import view

        model = {
            "status": {"details": {"muted": ["firefox"]}},
            "scopes": [],
        }
        args = mock.Mock()
        args._width = 80
        args._color = False
        self.assertIn("firefox", view.render_status(model, args))


if __name__ == "__main__":
    unittest.main()
