"""Application identity resolution, authority boundaries, and persistence."""

import tempfile
import unittest
import os
from pathlib import Path
from unittest import mock

from taema.config import policy
from taema.core import identity, lineage, process
from taema.governor import engine
from taema.store import db, knowledge
from taema.core.process import ProcTable
from taema.daemon.service import Daemon
from tests.test_phase0 import make_cfg, tmp


class IdentityResolution(unittest.TestCase):
    def test_matching_unit_precedes_executable_script_runtime_and_display_hints(self):
        result = identity.resolve_identity(
            identity.ProcessFacts(
                comm="node",
                exe="/usr/bin/node",
                device=8,
                inode=71,
                argv=("node", "/project/vite.js"),
                cgroup="/user/1000/libpod-abcdef012345.scope",
                unit="app-dev-server",
            ),
            identity.IdentityHints(desktop_id="org.example.Editor"),
        )

        self.assertEqual(result.key, "unit:app-dev-server")
        self.assertEqual(result.kind, "unit")
        self.assertEqual(result.display, "org.example.Editor")
        self.assertTrue(result.validated)
        self.assertNotEqual(result.key, "org.example.Editor")

    def test_explicit_unit_key_cannot_collide_with_a_comm_identity(self):
        unit = identity.resolve_identity(
            identity.ProcessFacts(comm="bash", unit="bash")
        )
        comm = identity.resolve_identity(identity.ProcessFacts(comm="bash"))

        self.assertEqual(unit.key, "unit:bash")
        self.assertNotEqual(unit.key, comm.key)
        self.assertIsNone(policy.bad_owner(unit.key))

    def test_executable_inode_identifies_upgrades_and_shares_only_exact_inode(self):
        original = identity.resolve_identity(
            identity.ProcessFacts(
                comm="firefox",
                exe="/usr/lib/firefox/firefox",
                device=8,
                inode=71,
            )
        )
        same_binary = identity.resolve_identity(
            identity.ProcessFacts(
                comm="firefox",
                exe="/usr/lib/firefox/firefox",
                device=8,
                inode=71,
            )
        )
        upgraded = identity.resolve_identity(
            identity.ProcessFacts(
                comm="firefox",
                exe="/usr/lib/firefox/firefox",
                device=8,
                inode=72,
            )
        )

        self.assertEqual(original.key, "exe:firefox:8:71")
        self.assertEqual(original.display, "firefox")
        self.assertEqual(original.key, same_binary.key)
        self.assertNotEqual(original.key, upgraded.key)
        self.assertIsNone(policy.bad_owner(original.key))
        store = knowledge.Store(tmp())
        store.answer(original.key, "worker", "stop")
        self.assertEqual(store.pair_decision(upgraded.key, "worker")[0], "ask")

    def test_equal_interpreter_script_names_are_separated_by_project_path(self):
        first = identity.resolve_identity(
            identity.ProcessFacts(
                comm="node",
                exe="/usr/bin/node",
                argv=("node", "/work/one/vite.js"),
                cwd="/work/one",
            )
        )
        second = identity.resolve_identity(
            identity.ProcessFacts(
                comm="node",
                exe="/usr/bin/node",
                argv=("node", "/work/two/vite.js"),
                cwd="/work/two",
            )
        )

        self.assertEqual(first.kind, "script")
        self.assertEqual(first.display, "vite.js")
        self.assertNotEqual(first.key, second.key)
        self.assertNotIn("/work/", first.key)

    def test_runtime_identity_uses_cgroup_or_socket_evidence_before_binary(self):
        container_id = "abcdef0123456789"
        container = identity.resolve_identity(
            identity.ProcessFacts(
                comm="conmon",
                exe="/usr/bin/conmon",
                device=8,
                inode=71,
                cgroup="/user/1000/libpod-%s.scope" % container_id,
            )
        )
        same_container = identity.resolve_identity(
            identity.ProcessFacts(
                comm="conmon",
                exe="/usr/bin/conmon",
                device=8,
                inode=99,
                cgroup="/user/1000/libpod-%s.scope" % container_id,
            )
        )
        vm = identity.resolve_identity(
            identity.ProcessFacts(
                comm="qemu-system-x86",
                exe="/usr/bin/qemu-system-x86_64",
                device=8,
                inode=71,
                sockets=("/run/user/1000/taema/qmp-vm-one.sock",),
            )
        )

        self.assertEqual(container.kind, "runtime")
        self.assertEqual(container.runtime, "container")
        self.assertEqual(container.key, same_container.key)
        self.assertEqual(vm.kind, "runtime")
        self.assertEqual(vm.runtime, "qemu")
        self.assertNotIn("/run/user/", vm.key)

    def test_validated_comm_fallback_and_generic_owner_rejection(self):
        valid = identity.resolve_identity(identity.ProcessFacts(comm="editor"))
        generic = identity.resolve_identity(identity.ProcessFacts(comm="MainThread"))
        numeric = identity.resolve_identity(identity.ProcessFacts(comm="2.1.300"))
        interpreter = identity.resolve_identity(
            identity.ProcessFacts(comm="python3.12", exe="/usr/bin/python3.12")
        )

        self.assertEqual(valid.key, "editor")
        self.assertTrue(valid.validated)
        self.assertFalse(generic.validated)
        self.assertFalse(numeric.validated)
        self.assertFalse(interpreter.validated)
        self.assertTrue(policy.bad_owner(generic.key))

    def test_desktop_and_launch_hints_decorate_evidence_not_authority(self):
        desktop = identity.IdentityHints(desktop_id="org.example.Browser")
        first = identity.resolve_identity(
            identity.ProcessFacts(
                comm="browser", exe="/opt/browser", device=8, inode=1
            ),
            desktop,
        )
        upgraded = identity.resolve_identity(
            identity.ProcessFacts(
                comm="browser", exe="/opt/browser", device=8, inode=2
            ),
            desktop,
        )
        launched = identity.resolve_identity(
            identity.ProcessFacts(comm="worker", exe="/opt/worker", device=8, inode=1),
            identity.IdentityHints(launch_name="Build worker"),
        )

        self.assertEqual(first.display, "org.example.Browser")
        self.assertTrue(first.key.startswith("desktop:org.example.Browser|"))
        self.assertNotEqual(first.key, upgraded.key)
        self.assertEqual(launched.display, "Build worker")
        self.assertIn("launch:Build worker|", launched.key)

    def test_owner_validation_uses_evidence_keys_after_hint_decoration(self):
        self.assertIn(
            "unvalidated",
            policy.bad_owner("desktop:Editor|invalid:comm:MainThread"),
        )
        self.assertIn("shell", policy.bad_owner("exe:bash:8:71"))
        self.assertIn("trivial", policy.bad_owner("exe:sleep:8:71"))
        self.assertIn("interpreter", policy.bad_owner("exe:python3.12:8:71"))
        self.assertIn("interpreter", policy.bad_owner("comm:python3.12"))
        self.assertIsNone(policy.bad_owner("script:python:main.py:123456789abc"))
        self.assertIsNone(policy.bad_owner("runtime:qemu:123456789abcdef0"))
        self.assertIsNone(policy.bad_owner("unit:bash"))
        self.assertIn(
            "denied",
            policy.bad_owner("desktop:Editor|exe:gpu-render:8:71", ["gpu-*"]),
        )


class UnixSocketEvidence(unittest.TestCase):
    def test_socket_paths_match_owned_socket_inodes_and_respect_descriptor_cap(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "net").mkdir()
            (root / "42" / "fd").mkdir(parents=True)
            (root / "net" / "unix").write_text(
                "Num RefCount Protocol Flags Type St Inode Path\n"
                "000: 00000002 00000000 00010000 0001 01 123 /run/a.sock\n"
                "001: 00000002 00000000 00010000 0001 01 124 /run/z.sock\n"
                "malformed row\n",
                encoding="utf-8",
            )
            descriptors = {
                "3": "socket:[123]",
                "4": "socket:[124]",
                "5": "pipe:[9]",
                "6": "socket:[999]",
                "7": "socket:[123]",
            }
            original_listdir = os.listdir

            def listdir(path):
                if path == str(root / "42" / "fd"):
                    return list(descriptors)
                return original_listdir(path)

            def readlink(path):
                descriptor = Path(path).name
                if descriptor == "7":
                    raise FileNotFoundError(path)
                return descriptors[descriptor]

            with (
                mock.patch.object(process, "PROC", str(root)),
                mock.patch.object(process.os, "listdir", side_effect=listdir),
                mock.patch.object(process.os, "readlink", side_effect=readlink),
            ):
                self.assertEqual(
                    process.unix_socket_paths(42), ["/run/a.sock", "/run/z.sock"]
                )
                self.assertEqual(
                    process.unix_socket_paths(42, limit=1), ["/run/a.sock"]
                )

    def test_socket_paths_fail_closed_when_proc_data_is_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with mock.patch.object(process, "PROC", str(root)):
                self.assertEqual(process.unix_socket_paths(42), [])

            (root / "net").mkdir()
            (root / "net" / "unix").write_text(
                "Num RefCount Protocol Flags Type St Inode Path\n", encoding="utf-8"
            )
            with (
                mock.patch.object(process, "PROC", str(root)),
                mock.patch.object(process.os, "listdir", side_effect=PermissionError),
            ):
                self.assertEqual(process.unix_socket_paths(42), [])


class IdentityPersistence(unittest.TestCase):
    def test_apps_and_instances_are_persisted_under_storage_caps(self):
        now = [1_800_000_000.0]
        with tempfile.TemporaryDirectory() as directory:
            store = knowledge.Store(directory, now=lambda: now[0])
            with (
                mock.patch.object(db, "MAX_APPS", 2),
                mock.patch.object(db, "MAX_INSTANCES", 2),
            ):
                for index in range(3):
                    key = "exe:app%d:1:%d" % (index, index + 1)
                    app = identity.AppIdentity(
                        key,
                        "app%d" % index,
                        "exe",
                        "app%d" % index,
                        1,
                        index + 1,
                    )
                    self.assertTrue(
                        store.record_identity(
                            app,
                            {
                                "pid": 100 + index,
                                "start": 200 + index,
                                "born": now[0],
                                "scope": "/user/1000/app-example",
                                "parent_app": "editor",
                                "terminal": 0,
                            },
                        )
                    )
                    now[0] += 1

            with store.db.connection() as connection:
                apps = connection.execute(
                    "SELECT key, display FROM apps ORDER BY key"
                ).fetchall()
                instances = connection.execute(
                    "SELECT app, pid, start FROM instances ORDER BY pid"
                ).fetchall()
            app = store.app_identity("exe:app2:1:3")
            instance = store.latest_app_instance("exe:app2:1:3")

        self.assertEqual(len(apps), 2)
        self.assertEqual(len(instances), 2)
        self.assertNotIn("exe:app0:1:1", {row["key"] for row in apps})
        self.assertEqual(instances[-1]["app"], "exe:app2:1:3")
        self.assertEqual(app["display"], "app2")
        self.assertEqual(instance["pid"], 102)
        self.assertEqual(instance["scope"], "/user/1000/app-example")

    def test_lineage_persists_resolved_identities_at_end_of_observe_pass(self):
        app = identity.AppIdentity("exe:editor:1:2", "editor", "exe", "editor", 1, 2)
        with tempfile.TemporaryDirectory() as directory:
            store = knowledge.Store(directory, now=lambda: 1_800_000_000.0)
            observed = lineage.Lineage({}, uid=0, identity_sink=store.record_identities)
            with (
                mock.patch.object(policy, "app_identity", return_value=app),
                mock.patch.object(lineage.inspect, "uid_of", return_value=0),
                mock.patch.object(
                    lineage.cgroup,
                    "proc_cgroup",
                    return_value="/user/1000/app-editor",
                ),
            ):
                observed.observe(
                    ProcTable.from_ppid({42: 1}), now=1_800_000_000.0, uptime=100
                )

            with store.db.connection() as connection:
                saved_app = connection.execute(
                    "SELECT key, display FROM apps WHERE key=?", (app.key,)
                ).fetchone()
                saved_instance = connection.execute(
                    "SELECT app, pid, start, scope, launched_by, exited "
                    "FROM instances WHERE id='42:0'"
                ).fetchone()

        self.assertEqual(saved_app["display"], "editor")
        self.assertEqual(saved_instance["app"], app.key)
        self.assertEqual(saved_instance["scope"], "/user/1000/app-editor")
        self.assertEqual(saved_instance["launched_by"], "adopt")
        self.assertIsNone(saved_instance["exited"])

    def test_parent_evidence_is_idempotent_and_chain_survives_store_restart(self):
        now = [1_800_000_000.0]
        niri = identity.AppIdentity(
            "unit:niri", "niri", "unit", "/usr/bin/niri", unit="niri.service"
        )
        firefox = identity.AppIdentity(
            "exe:firefox:8:71", "firefox", "exe", "/usr/bin/firefox", 8, 71
        )
        parent = {
            "pid": 40,
            "start": 100,
            "born": now[0],
            "scope": "/user/1000/scope-desktop",
            "launched_by": "unit",
        }
        child = {
            "pid": 41,
            "start": 101,
            "born": now[0],
            "parent_app": niri.key,
            "scope": parent["scope"],
            "runtime": "runtime:wayland",
            "launched_by": "run",
            "parent_evidence": ["co_birth", "cgroup", "job", "runtime"],
        }
        with tempfile.TemporaryDirectory() as directory:
            store = knowledge.Store(directory, now=lambda: now[0])
            self.assertEqual(
                store.record_identities([(niri, parent), (firefox, child)]), 2
            )
            now[0] += 1
            restarted = knowledge.Store(directory, now=lambda: now[0])
            self.assertEqual(
                restarted.record_identities([(niri, parent), (firefox, child)]), 2
            )

            with restarted.db.connection() as connection:
                counts = connection.execute(
                    "SELECT co_birth, cgroup, job, runtime, window, launch "
                    "FROM parents WHERE app = ? AND parent = ?",
                    (firefox.key, niri.key),
                ).fetchone()
                instance_count = connection.execute(
                    "SELECT count(*) FROM instances WHERE id='41:101'"
                ).fetchone()[0]

            self.assertEqual(tuple(counts), (1, 1, 1, 1, 0, 0))
            self.assertEqual(instance_count, 1)

            exited = dict(child, exited=now[0] + 10)
            restarted.record_identity(firefox, exited)
            self.assertEqual(
                restarted.latest_app_instance(firefox.key)["exited"], now[0] + 10
            )

            now[0] += 11
            live = knowledge.Store(directory, now=lambda: now[0])
            live.record_identity(firefox, child)
            self.assertIsNone(live.latest_app_instance(firefox.key)["exited"])
            chain = live.provenance_chain(firefox.key)

        self.assertEqual(chain["chain_text"], "firefox ← niri")
        self.assertEqual(
            chain["chain"][0]["relation"]["evidence_counts"],
            {
                "co_birth": 1,
                "cgroup": 1,
                "job": 1,
                "runtime": 1,
            },
        )
        self.assertEqual(chain["chain"][0]["relation"]["confidence"], 1.0)

    def test_lineage_restart_reconciles_pid_start_and_records_exit(self):
        now = [1_800_000_000.0]
        niri = identity.AppIdentity(
            "unit:niri", "niri", "unit", "/usr/bin/niri", runtime="runtime:wayland"
        )
        firefox = identity.AppIdentity(
            "exe:firefox:8:71",
            "firefox",
            "exe",
            "/usr/bin/firefox",
            8,
            71,
            runtime="runtime:wayland",
        )
        table = ProcTable.from_ppid({40: 1, 41: 40})
        empty = ProcTable.from_ppid({})
        with tempfile.TemporaryDirectory() as directory:
            store = knowledge.Store(directory, now=lambda: now[0])

            def app_for(pid, **_kwargs):
                return niri if pid == 40 else firefox

            with (
                mock.patch.object(lineage.policy, "app_identity", side_effect=app_for),
                mock.patch.object(lineage.inspect, "uid_of", return_value=0),
                mock.patch.object(
                    lineage.cgroup,
                    "proc_cgroup",
                    return_value="/user/1000/app-desktop",
                ),
            ):
                first_daemon = lineage.Lineage(
                    {}, uid=0, identity_sink=store.record_identities
                )
                first_daemon.observe(table, now=now[0], uptime=100)
                now[0] += 1
                restarted_daemon = lineage.Lineage(
                    {}, uid=0, identity_sink=store.record_identities
                )
                restarted_daemon.observe(table, now=now[0], uptime=101)

                with store.db.connection() as connection:
                    self.assertEqual(
                        connection.execute("SELECT count(*) FROM instances").fetchone()[
                            0
                        ],
                        2,
                    )
                    evidence = connection.execute(
                        "SELECT cgroup, runtime FROM parents WHERE app = ? AND parent = ?",
                        (firefox.key, niri.key),
                    ).fetchone()
                self.assertEqual(tuple(evidence), (1, 1))

                now[0] += 1
                restarted_daemon.observe(empty, now=now[0], uptime=102)

            exited = store.latest_app_instance(firefox.key)
        self.assertEqual(exited["exited"], now[0])
        self.assertEqual(exited["id"], "41:0")

    def test_launch_source_uses_managed_source_not_display_hint(self):
        app = identity.AppIdentity(
            "exe:browser:1:2",
            "Browser Display",
            "exe",
            "/usr/bin/browser",
            launch_name="Browser Display",
        )
        self.assertEqual(
            lineage.Lineage._launch_source(
                {"identity": app, "scope": "/user/1000/app-browser"}
            ),
            "adopt",
        )
        self.assertEqual(
            lineage.Lineage._launch_source(
                {"identity": app, "scope": "/user/1000/scope-browser"}
            ),
            "run",
        )
        self.assertIsNone(
            lineage.Lineage._launch_source(
                {"identity": app, "scope": "/user/1000/shared/browser"}
            )
        )
        unit_app = identity.AppIdentity(
            "unit:editor", "editor", "unit", "/usr/bin/editor", unit="editor.service"
        )
        self.assertEqual(
            lineage.Lineage._launch_source(
                {"identity": unit_app, "scope": "/user/1000/shared/editor"}
            ),
            "unit",
        )

    def test_parent_evidence_moves_when_parent_identity_settles(self):
        now = [1_800_000_000.0]
        phase = [0]
        unresolved = identity.AppIdentity(
            "comm:niri", "niri", "comm", "/usr/bin/niri", runtime="runtime:wayland"
        )
        resolved = identity.AppIdentity(
            "unit:niri",
            "niri",
            "unit",
            "/usr/bin/niri",
            runtime="runtime:wayland",
            unit="niri.service",
        )
        firefox = identity.AppIdentity(
            "exe:firefox:8:71",
            "firefox",
            "exe",
            "/usr/bin/firefox",
            8,
            71,
            runtime="runtime:wayland",
        )
        table = ProcTable(
            {
                40: process.Proc(1, 40, 40, 0, 100, "S"),
                41: process.Proc(40, 41, 40, 0, 101, "S"),
            }
        )

        def app_for(pid, **_kwargs):
            if pid == 40:
                return unresolved if phase[0] == 0 else resolved
            return firefox

        with tempfile.TemporaryDirectory() as directory:
            store = knowledge.Store(directory, now=lambda: now[0])
            observed = lineage.Lineage({}, uid=0, identity_sink=store.record_identities)
            with (
                mock.patch.object(lineage.policy, "app_identity", side_effect=app_for),
                mock.patch.object(lineage.inspect, "uid_of", return_value=0),
                mock.patch.object(
                    lineage.cgroup,
                    "proc_cgroup",
                    return_value="/user/1000/app-desktop",
                ),
            ):
                observed.observe(table, now=now[0], uptime=1)
                phase[0] = 1
                now[0] += 1
                observed.observe(table, now=now[0], uptime=2)

            with store.db.connection() as connection:
                child = connection.execute(
                    "SELECT parent_app FROM instances WHERE id='41:101'"
                ).fetchone()
                old_edge = connection.execute(
                    "SELECT 1 FROM parents WHERE app = ? AND parent = ?",
                    (firefox.key, unresolved.key),
                ).fetchone()
                new_edge = connection.execute(
                    "SELECT cgroup, runtime FROM parents WHERE app = ? AND parent = ?",
                    (firefox.key, resolved.key),
                ).fetchone()

        self.assertEqual(child["parent_app"], resolved.key)
        self.assertIsNone(old_edge)
        self.assertEqual(tuple(new_edge), (1, 1))

    def test_governor_fallback_keeps_lineage_units_when_entry_is_missing(self):
        observed = mock.Mock()
        observed.entry.return_value = None
        observed.units = ({"unit": {"name": "editor"}},)
        with (
            mock.patch.object(
                engine.policy, "app_key", return_value="unit:editor"
            ) as key,
            mock.patch.object(engine.policy, "protected_reason", return_value=None),
        ):
            info = engine.member_info({}, observed, 42, {})

        key.assert_called_once_with(42, units=observed.units)
        self.assertEqual(info["key"], "unit:editor")

    def test_ambiguous_owner_review_is_informational_and_never_answers_on_expiry(self):
        now = [1_800_000_000.0]
        store = knowledge.Store(tmp(), now=lambda: now[0])
        review = store.add_provenance_review(
            [{"pid": 9, "start": 12, "key": "worker"}],
            "leftover/provenance-9-12",
            [
                {"kind": "ancestor", "key": "exe:editor:1:2", "label": "editor"},
                {"kind": "ancestor", "key": "invalid:comm:MainThread"},
            ],
        )

        self.assertEqual(review["kind"], "provenance-candidate")
        self.assertNotIn("owner", review)
        self.assertEqual(
            [item["key"] for item in review["candidates"]], ["exe:editor:1:2"]
        )
        self.assertFalse(store.answer("invalid:comm:MainThread", "worker", "stop"))
        now[0] += knowledge.REVIEW_TTL + 1
        store.expire_reviews()
        self.assertEqual(store.data["pairs"], {})

    def test_daemon_queues_candidates_without_creating_a_pair(self):
        with tempfile.TemporaryDirectory() as directory:
            daemon = Daemon(make_cfg(directory))
            review = daemon.queue_provenance_review(
                "leftover/provenance-42-99",
                [
                    {
                        "pid": 42,
                        "start": 99,
                        "key": "worker",
                        "chain": ["exe:editor:1:2"],
                        "chain_ids": [None],
                    }
                ],
                reason="owner is ambiguous",
            )

        self.assertEqual(review["kind"], "provenance-candidate")
        self.assertEqual(review["candidates"][0]["key"], "exe:editor:1:2")
        self.assertEqual(daemon.store.data["pairs"], {})

    def test_stop_plan_carries_the_same_application_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            store = knowledge.Store(directory)
            with (
                mock.patch.object(engine.cgroup, "tree_procs", return_value=[42]),
                mock.patch.object(
                    engine.policy, "app_key", return_value="exe:editor:1:2"
                ),
                mock.patch.object(engine.policy, "protected_reason", return_value=None),
                mock.patch.object(engine.inspect, "edges", return_value={}),
                mock.patch.object(
                    engine.inspect,
                    "LazySnapshot",
                    return_value=mock.Mock(
                        get=mock.Mock(return_value=mock.Mock(ok=True))
                    ),
                ),
            ):
                plan = engine.plan_stop(
                    "/scope",
                    {},
                    store,
                    pt=engine.inspect.ProcTable.from_ppid({42: 1}),
                )

        self.assertEqual(plan[0]["key"], "exe:editor:1:2")


if __name__ == "__main__":
    unittest.main()
