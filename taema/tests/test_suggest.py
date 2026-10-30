"""Ranked, user-confirmed improvement suggestions (issue #79)."""

import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from taema.cli import commands
from taema.core import signature as survivor_signature
from taema.store.knowledge import Store


class Clock:
    def __init__(self):
        import time as _time

        self.t = _time.time()

    def __call__(self):
        return self.t


DAY = 86400.0


def run_cli(root, *argv):
    override = os.path.join(root, "taema.toml")
    with open(override, "w", encoding="utf-8") as stream:
        stream.write('[paths]\nstate_dir = "%s"\n' % os.path.join(root, "state"))
    dead_socket = os.path.join(root, "dead.sock")
    output = io.StringIO()
    with redirect_stdout(output):
        code = commands.main(
            ["--config", override, "--socket", dead_socket, *argv]
        )
    return code, output.getvalue()


class SuggestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.clock = Clock()
        self.root = os.path.join(self.temp.name, "root")
        os.makedirs(self.root)
        self.state_dir = os.path.join(self.root, "state")
        self.store = Store(self.state_dir, {}, self.clock)

    def make_review(self, owner="owner", helper="helper"):
        self.store.observe_close(owner, helper)
        signature = survivor_signature.signature(
            owner, [helper], "runtime", "node", False
        )
        self.store.observe_signature_close(signature)
        return self.store.add_review(
            owner,
            [{"key": helper, "pid": 42, "start": 100}],
            "leftover/%s-42" % owner,
            signature=self.store.db.signature(signature["id"]),
            memory=2 * 1024 * 1024,
            provenance="last seen under editor",
        )

    def age_review(self, review, days):
        row = next(
            item
            for item in self.store.data["reviews"]
            if item.get("id") == review["id"]
        )
        row["created"] = self.clock() - days * DAY
        row["expires"] = self.clock() + 30 * DAY

    def test_stale_review_ranked_with_id(self):
        from taema import suggest

        review = self.make_review()
        self.age_review(review, 4)
        ranked = suggest.rank(self.store, {}, now=self.clock())
        kinds = [(item["kind"], item["id"]) for item in ranked]
        self.assertIn(("stale-review", "stale-review-%s" % review["id"]), kinds)
        fresh = [item for item in ranked if item["kind"] == "stale-review"]
        self.assertTrue(all("answer" in item["detail"].lower() for item in fresh))

    def test_fresh_review_not_suggested(self):
        from taema import suggest

        self.make_review()
        ranked = suggest.rank(self.store, {}, now=self.clock())
        self.assertFalse(
            [item for item in ranked if item["kind"] == "stale-review"]
        )

    def test_suggest_lists_ranked_suggestions(self):
        review = self.make_review()
        self.age_review(review, 4)
        self.store.save()
        code, output = run_cli(self.root, "suggest")
        self.assertEqual(code, 0)
        self.assertIn("stale-review-%s" % review["id"], output)

    def test_apply_review_asks_choice_then_answers(self):
        review = self.make_review()
        self.age_review(review, 4)
        self.store.save()
        identifier = "stale-review-%s" % review["id"]
        with mock.patch.object(commands, "_confirm_bulk", return_value=True):
            with mock.patch("builtins.input", return_value="keep"):
                code, _output = run_cli(
                    self.root, "suggest", "apply", identifier
                )
        self.assertEqual(code, 0)
        check = Store(self.state_dir, {}, self.clock, read_only=True)
        self.assertEqual(check.data["reviews"][0]["state"], "answered")

    def test_expired_and_unused_vetoes_ranked(self):
        from taema import suggest

        self.store.data["vetoes"] = [
            {"kind": "app", "value": "old", "expires": self.clock() - 10},
            {"kind": "app", "value": "ghost"},
        ]
        ranked = suggest.rank(self.store, {}, now=self.clock())
        ids = [item["id"] for item in ranked if item["kind"] == "veto"]
        self.assertIn("veto-app-old", ids)
        self.assertIn("veto-app-ghost", ids)

    def test_used_veto_not_suggested(self):
        from taema import suggest

        self.store.observe_close("owner", "helper")
        self.store.add_veto("app", "owner")
        self.store.save()
        ranked = suggest.rank(self.store, {}, now=self.clock())
        self.assertFalse([item for item in ranked if item["kind"] == "veto"])

    def test_apply_veto_removes_it(self):
        self.store.add_veto("app", "ghost")
        self.store.save()
        code, _output = run_cli(
            self.root, "suggest", "apply", "veto-app-ghost", "--yes"
        )
        self.assertEqual(code, 0)
        check = Store(self.state_dir, {}, self.clock, read_only=True)
        self.assertEqual(check.data["vetoes"], [])

    def stable_signature(self, owner="browser", member="worker", closes=5):
        signature = {
            "id": "sig-%s" % owner,
            "owner": owner,
            "members": [{"key": member, "count": 1}],
            "runtime_class": "node",
            "runtime_hash": "runtime-hash",
            "tty": False,
        }
        for _ in range(closes):
            self.store.db.record_signature(signature, now=self.clock(), close=True)
        return signature

    def test_stable_children_suggest_unit_draft(self):
        from taema import suggest

        self.stable_signature()
        units_dir = os.path.join(self.temp.name, "units")
        os.makedirs(units_dir)
        ranked = suggest.rank(
            self.store, {"paths": {"units_dir": units_dir}}, now=self.clock()
        )
        matches = [item for item in ranked if item["kind"] == "stable-unit"]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["id"], "stable-unit-browser")
        self.assertIn("worker", matches[0]["detail"])

    def test_stable_unit_skipped_when_unit_exists(self):
        from taema import suggest

        self.stable_signature()
        units_dir = os.path.join(self.temp.name, "units")
        os.makedirs(units_dir)
        with open(os.path.join(units_dir, "browser.toml"), "w") as stream:
            stream.write(
                '[unit]\nname = "browser"\nkind = "app"\n[match]\ncomm = "browser"\n'
            )
        ranked = suggest.rank(
            self.store, {"paths": {"units_dir": units_dir}}, now=self.clock()
        )
        self.assertFalse([item for item in ranked if item["kind"] == "stable-unit"])

    def test_apply_stable_unit_writes_linted_file(self):
        from unittest import mock

        from taema.config import policy

        self.stable_signature()
        userbase = os.path.join(self.temp.name, "user-home")
        units_dir = os.path.join(self.temp.name, "units")
        os.makedirs(units_dir)
        cfg = {"paths": {"units_dir": units_dir}}
        with mock.patch.object(policy, "user_config_dir", return_value=userbase):
            code, _output = run_cli(
                self.root, "suggest", "apply", "stable-unit-browser", "--yes"
            )
        # CLI rank uses the override config, which has no units_dir: unit
        # existence is checked against the real configured units instead.
        self.assertEqual(code, 0)
        target = os.path.join(userbase, "units", "browser.toml")
        self.assertTrue(os.path.isfile(target))
        unit, error = policy.read_unit_file(target)
        self.assertIsNone(error)
        self.assertEqual(policy.validate_unit(unit), [])
        with mock.patch.object(policy, "user_config_dir", return_value=userbase):
            code, _output = run_cli(
                self.root, "suggest", "apply", "stable-unit-browser", "--yes"
            )
        self.assertEqual(code, 2)
        from taema import suggest as suggest_mod

        repeat = {
            "id": "stable-unit-browser",
            "kind": "stable-unit",
            "payload": {"app": "browser", "children": ["worker"]},
        }
        with mock.patch.object(policy, "user_config_dir", return_value=userbase):
            ok, message = suggest_mod.apply_suggestion(
                self.store, cfg, repeat, force=False
            )
        self.assertFalse(ok)
        self.assertIn("--force", message)
        with mock.patch.object(policy, "user_config_dir", return_value=userbase):
            ok, _message = suggest_mod.apply_suggestion(
                self.store, cfg, repeat, force=True
            )
        self.assertTrue(ok)

    def seed_app(self, key, instances):
        with self.store.db.connection() as connection:
            connection.execute(
                "INSERT INTO apps(key, kind, instances) VALUES (?, 'app', ?)",
                (key, instances),
            )
            connection.commit()

    def test_wrap_suggests_frequently_launched_app(self):
        from unittest import mock

        from taema import desktop as desktop_mod
        from taema import suggest

        self.seed_app("code", 7)
        system = os.path.join(self.temp.name, "applications")
        os.makedirs(system)
        with open(os.path.join(system, "code.desktop"), "w") as stream:
            stream.write("[Desktop Entry]\nName=Code\nExec=/usr/share/code/code\n")
        with (
            mock.patch.object(desktop_mod, "system_dirs", return_value=[system]),
            mock.patch.object(desktop_mod, "list_wraps", return_value=[]),
        ):
            ranked = suggest.rank(self.store, {}, now=self.clock())
        matches = [item for item in ranked if item["kind"] == "wrap"]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["id"], "wrap-code")

    def test_wrap_skipped_when_wrapped_or_rare(self):
        from unittest import mock

        from taema import desktop as desktop_mod
        from taema import suggest

        self.seed_app("code", 7)
        self.seed_app("rare", 2)
        system = os.path.join(self.temp.name, "applications")
        os.makedirs(system)
        for name, exe in (("code", "/usr/share/code/code"), ("rare", "/usr/bin/rare")):
            with open(os.path.join(system, name + ".desktop"), "w") as stream:
                stream.write("[Desktop Entry]\nName=%s\nExec=%s\n" % (name, exe))
        with (
            mock.patch.object(desktop_mod, "system_dirs", return_value=[system]),
            mock.patch.object(
                desktop_mod,
                "list_wraps",
                return_value=[
                    {
                        "file": "/home/u/.local/share/applications/code.desktop",
                        "drifted": False,
                    }
                ],
            ),
        ):
            ranked = suggest.rank(self.store, {}, now=self.clock())
        self.assertFalse([item for item in ranked if item["kind"] == "wrap"])

    def test_apply_wrap_installs_wrapper(self):
        from unittest import mock

        from taema import desktop as desktop_mod

        self.seed_app("code", 7)
        system = os.path.join(self.temp.name, "applications")
        user = os.path.join(self.temp.name, "wraps")
        os.makedirs(system)
        os.makedirs(user)
        with open(os.path.join(system, "code.desktop"), "w") as stream:
            stream.write("[Desktop Entry]\nName=Code\nExec=/usr/share/code/code\n")
        with (
            mock.patch.object(desktop_mod, "system_dirs", return_value=[system]),
            mock.patch.object(desktop_mod, "user_dir", return_value=user),
            mock.patch.object(desktop_mod, "list_wraps", return_value=[]),
        ):
            code, _output = run_cli(self.root, "suggest", "apply", "wrap-code", "--yes")
        self.assertEqual(code, 0)
        self.assertTrue(os.path.isfile(os.path.join(user, "code.desktop")))

    def test_zswap_suggested_when_swap_active_but_zswap_off(self):
        from taema import suggest

        system = os.path.join(self.temp.name, "sysroot")
        os.makedirs(os.path.join(system, "sys/module/zswap/parameters"))
        with open(
            os.path.join(system, "sys/module/zswap/parameters/enabled"), "w"
        ) as stream:
            stream.write("N\n")
        os.makedirs(os.path.join(system, "proc"))
        with open(os.path.join(system, "proc/swaps"), "w") as stream:
            stream.write("Filename\tType\tSize\tUsed\tPriority\n")
            stream.write("/swapfile\tfile\t1048576\t0\t-2\n")
        ranked = suggest.rank(self.store, {}, system_root=system, now=self.clock())
        matches = [item for item in ranked if item["kind"] == "zswap"]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["id"], "zswap")

    def test_zswap_skipped_when_enabled_or_no_swap(self):
        from taema import suggest

        system = os.path.join(self.temp.name, "sysroot")
        os.makedirs(os.path.join(system, "sys/module/zswap/parameters"))
        os.makedirs(os.path.join(system, "proc"))
        with open(os.path.join(system, "proc/swaps"), "w") as stream:
            stream.write("Filename\tType\tSize\tUsed\tPriority\n")
        with open(
            os.path.join(system, "sys/module/zswap/parameters/enabled"), "w"
        ) as stream:
            stream.write("N\n")
        ranked = suggest.rank(self.store, {}, system_root=system, now=self.clock())
        self.assertFalse([item for item in ranked if item["kind"] == "zswap"])

    def test_earlyoom_suggested_when_prefer_missing(self):
        from taema import suggest

        proc = os.path.join(self.temp.name, "proc")
        pid = os.path.join(proc, "4242")
        os.makedirs(pid)
        with open(os.path.join(pid, "comm"), "w") as stream:
            stream.write("earlyoom\n")
        with open(os.path.join(pid, "cmdline"), "wb") as stream:
            stream.write(b"earlyoom\0-m\010\0")
        self.seed_app("code", 9)
        ranked = suggest.rank(self.store, {}, proc_root=proc, now=self.clock())
        matches = [item for item in ranked if item["kind"] == "earlyoom"]
        self.assertEqual(len(matches), 1)
        self.assertIn("code", matches[0]["detail"])

    def test_earlyoom_skipped_when_prefer_set_or_absent(self):
        from taema import suggest

        proc = os.path.join(self.temp.name, "proc")
        pid = os.path.join(proc, "4242")
        os.makedirs(pid)
        with open(os.path.join(pid, "comm"), "w") as stream:
            stream.write("earlyoom\n")
        with open(os.path.join(pid, "cmdline"), "wb") as stream:
            stream.write(b"earlyoom\0--prefer\0^code\0")
        self.seed_app("code", 9)
        ranked = suggest.rank(self.store, {}, proc_root=proc, now=self.clock())
        self.assertFalse([item for item in ranked if item["kind"] == "earlyoom"])
        ranked = suggest.rank(
            self.store, {}, proc_root="/nonexistent-proc", now=self.clock()
        )
        self.assertFalse([item for item in ranked if item["kind"] == "earlyoom"])

    def test_apply_zswap_and_earlyoom_print_root_commands(self):
        from taema import suggest

        ok, message = suggest.apply_suggestion(
            self.store, {}, {"kind": "zswap", "payload": {}}
        )
        self.assertFalse(ok)
        self.assertIn("sudo", message)
        ok, message = suggest.apply_suggestion(
            self.store,
            {},
            {"kind": "earlyoom", "payload": {"candidate": "code"}},
        )
        self.assertFalse(ok)
        self.assertIn("code", message)

    def test_grace_suggested_for_app_with_regrets(self):
        from taema import suggest

        self.store.observe_close("owner", "helper")
        self.store.data["pairs"][self.store.pkey("owner", "helper")]["respawn"] = 3
        ranked = suggest.rank(
            self.store, {"agent": {"windowless_grace": 30}}, now=self.clock()
        )
        matches = [item for item in ranked if item["kind"] == "grace"]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["id"], "grace-owner")
        self.assertIn("60", matches[0]["detail"])

    def test_grace_skipped_when_learned_or_capped(self):
        from taema import suggest

        self.store.observe_close("owner", "helper")
        self.store.data["pairs"][self.store.pkey("owner", "helper")]["respawn"] = 3
        self.store.data["windowless_grace"] = {"owner": 60}
        ranked = suggest.rank(
            self.store, {"agent": {"windowless_grace": 30}}, now=self.clock()
        )
        self.assertFalse([item for item in ranked if item["kind"] == "grace"])
        self.store.data["windowless_grace"] = {}
        ranked = suggest.rank(
            self.store, {"agent": {"windowless_grace": 600}}, now=self.clock()
        )
        self.assertFalse([item for item in ranked if item["kind"] == "grace"])

    def test_apply_grace_records_learned_value(self):
        self.store.observe_close("owner", "helper")
        self.store.data["pairs"][self.store.pkey("owner", "helper")]["respawn"] = 3
        self.store.save()
        code, _output = run_cli(self.root, "suggest", "apply", "grace-owner", "--yes")
        self.assertEqual(code, 0)
        check = Store(self.state_dir, {}, self.clock, read_only=True)
        self.assertEqual(check.data["windowless_grace"]["owner"], 60)
        ranked = __import__("taema.suggest", fromlist=["rank"]).rank(
            check, {"agent": {"windowless_grace": 30}}, now=self.clock()
        )
        self.assertFalse([item for item in ranked if item["kind"] == "grace"])

    def test_trailing_caps_lines(self):
        from taema import suggest

        self.store.add_veto("app", "ghost")
        self.store.add_veto("app", "spooky")
        lines = suggest.trailing(self.store, {}, 1, now=self.clock())
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].startswith("suggestion: "))
        lines = suggest.trailing(self.store, {}, 3, now=self.clock())
        self.assertLessEqual(len(lines), 3)

    def test_report_ends_with_suggestions(self):
        self.store.add_veto("app", "ghost")
        self.store.save()
        code, output = run_cli(self.root, "report", "--day")
        self.assertEqual(code, 0)
        trailer = [
            line
            for line in output.splitlines()
            if line.startswith("suggestion: ")
        ]
        self.assertLessEqual(len(trailer), 3)
        self.assertTrue(trailer)

    def test_bare_taema_shows_one_suggestion(self):
        from tests.test_phase0 import make_cfg

        state_dir = os.path.join(self.temp.name, "bare-state")
        os.makedirs(state_dir)
        store = Store(state_dir, {})
        store.add_veto("app", "ghost")
        store.save()
        cfg = make_cfg(state_dir)
        output = io.StringIO()
        with (
            mock.patch.object(commands, "_load_status", return_value=(cfg, store)),
            mock.patch.object(commands, "_fast_status_probe", return_value=None),
            mock.patch.object(commands, "ask", return_value=None),
            mock.patch.dict(os.environ, {"TAEMA_MEM": "0"}),
            mock.patch.object(
                commands.cgroup, "base", return_value="/missing/cgroup"
            ),
            redirect_stdout(output),
        ):
            result = commands.main([])
        self.assertEqual(result, 3)
        trailer = [
            line
            for line in output.getvalue().splitlines()
            if line.startswith("suggestion: ")
        ]
        self.assertEqual(len(trailer), 1)

    def test_apply_unknown_id_fails(self):
        error = io.StringIO()
        with redirect_stderr(error):
            code, _output = run_cli(self.root, "suggest", "apply", "nope-1")
        self.assertEqual(code, 2)
        self.assertIn("no such suggestion", error.getvalue())


if __name__ == "__main__":
    unittest.main()
