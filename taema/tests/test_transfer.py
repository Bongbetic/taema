"""Versioned learning export, import, reset, and restore."""

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from taema.cli import commands
from taema.store import knowledge
from taema.store import transfer


def make_store(root):
    state_dir = Path(root) / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    store = knowledge.Store(str(state_dir))
    store.answer("code", "esbuild", "stop")
    store.answer("code", "rg", "keep")
    store.mark_standalone("syncthing")
    store.save()
    return store


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


class LearnExportTests(unittest.TestCase):
    def test_export_v1_answers_validate(self):
        with tempfile.TemporaryDirectory() as root:
            store = make_store(root)
            document = transfer.export_learn(store)
            self.assertIsNone(transfer.validate_learn_document(document))
            self.assertEqual(document["format"], "taema-learn")
            self.assertEqual(document["version"], 1)
            self.assertFalse(document["redacted"])
            pairs = {
                (entry["owner"], entry["leftover"]): entry
                for entry in document["pairs"]
            }
            self.assertEqual(pairs[("code", "esbuild")]["ex_last"], "stop")
            self.assertEqual(pairs[("code", "rg")]["ex_last"], "keep")
            self.assertIn({"key": "syncthing", "n": 1}, document["standalone"])

    def test_export_v1_matches_schema_file(self):
        schema_path = (
            Path(transfer.__file__).resolve().parents[3]
            / "schema"
            / "learn"
            / "v1.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as root:
            document = transfer.export_learn(make_store(root))
        self.assertEqual(
            set(schema["required"]),
            {"format", "version", "pairs", "standalone", "signatures"},
        )
        for key in schema["required"]:
            self.assertIn(key, document)

    def test_redacted_export_has_no_sensitive_values(self):
        with tempfile.TemporaryDirectory() as root:
            document = transfer.export_learn(make_store(root), redacted=True)
            self.assertTrue(document["redacted"])
        text = json.dumps(document)
        for marker in ('"argv"', '"cwd"', '"title"', '"env"', '"environment"'):
            self.assertNotIn(marker, text)

    def test_validator_rejects_bad_documents(self):
        with tempfile.TemporaryDirectory() as root:
            good = transfer.export_learn(make_store(root))
        cases = []
        missing = dict(good)
        del missing["pairs"]
        cases.append(missing)
        bad_version = dict(good)
        bad_version["version"] = 2
        cases.append(bad_version)
        bad_pair = json.loads(json.dumps(good))
        bad_pair["pairs"].append({"owner": "x"})
        cases.append(bad_pair)
        bad_choice = json.loads(json.dumps(good))
        bad_choice["pairs"][0]["ex_last"] = "explode"
        cases.append(bad_choice)
        for index, document in enumerate(cases):
            with self.subTest(case=index):
                self.assertIsNotNone(transfer.validate_learn_document(document))

    def test_cli_export_defaults_to_v1(self):
        with tempfile.TemporaryDirectory() as root:
            make_store(root)
            code, output = run_cli(root, "learn", "export")
            self.assertEqual(code, 0)
            document = json.loads(output)
            self.assertEqual(document["format"], "taema-learn")
            self.assertEqual(document["version"], 1)

    def test_cli_export_redact_flag(self):
        with tempfile.TemporaryDirectory() as root:
            make_store(root)
            code, output = run_cli(root, "learn", "export", "--redact")
            self.assertEqual(code, 0)
            self.assertTrue(json.loads(output)["redacted"])


def make_document():
    return {
        "format": "taema-learn",
        "version": 1,
        "exported": "2026-01-01T00:00:00+00:00",
        "taema": "0.5.0",
        "redacted": False,
        "pairs": [
            {
                "owner": "code",
                "leftover": "esbuild",
                "sig": None,
                "ex_stop": 6.0,
                "ex_keep": 0.0,
                "ex_last": "stop",
                "from_source": "explicit",
            },
            {
                "owner": "firefox",
                "leftover": "ffmpeg",
                "sig": None,
                "ex_stop": 0.0,
                "ex_keep": 3.0,
                "ex_last": "keep",
                "from_source": "explicit",
            },
        ],
        "standalone": [{"key": "syncthing", "n": 2}],
        "signatures": [],
    }


class LearnImportTests(unittest.TestCase):
    def test_merge_adds_missing_with_probation(self):
        with tempfile.TemporaryDirectory() as root:
            store = make_store(root)
            summary = store.import_learning_document(make_document(), mode="merge")
            store.save()
            self.assertEqual(summary["pairs_added"], 1)
            self.assertEqual(summary["pairs_skipped"], 1)
            pair = store.data["pairs"]["firefox\x00ffmpeg"]
            self.assertEqual(pair["ex_last"], "keep")
            self.assertEqual(pair["source"], "import")
            self.assertTrue(store.stop_in_probation("firefox", "ffmpeg"))

    def test_merge_keeps_local_explicit_answers(self):
        with tempfile.TemporaryDirectory() as root:
            store = make_store(root)
            store.import_learning_document(make_document(), mode="merge")
            pair = store.data["pairs"]["code\x00esbuild"]
            self.assertEqual(pair["ex_stop"], 3.0)
            self.assertEqual(pair.get("source", "explicit"), "explicit")

    def test_replace_clears_first(self):
        with tempfile.TemporaryDirectory() as root:
            store = make_store(root)
            summary = store.import_learning_document(make_document(), mode="replace")
            self.assertEqual(summary["pairs_removed"], 2)
            self.assertNotIn("code\x00rg", store.data["pairs"])
            self.assertIn("firefox\x00ffmpeg", store.data["pairs"])

    def test_apply_feedback_command_imports(self):
        with tempfile.TemporaryDirectory() as root:
            store = make_store(root)
            reply = store.apply_feedback_command(
                {
                    "v": 2,
                    "id": "import-1",
                    "op": "import_learning",
                    "mode": "merge",
                    "document": make_document(),
                }
            )
            self.assertTrue(reply["ok"])
            self.assertIn("firefox\x00ffmpeg", store.data["pairs"])
            again = store.apply_feedback_command(
                {
                    "v": 2,
                    "id": "import-1",
                    "op": "import_learning",
                    "mode": "merge",
                    "document": make_document(),
                }
            )
            self.assertTrue(again["duplicate"])

    def test_cli_import_offline_applies_directly(self):
        with tempfile.TemporaryDirectory() as root:
            store = make_store(root)
            store.save()
            path = Path(root) / "learn.json"
            path.write_text(json.dumps(make_document()), encoding="utf-8")
            code, output = run_cli(root, "learn", "import", str(path), "--yes")
            self.assertEqual(code, 0, output)
            self.assertIn("firefox/ffmpeg", output)
            reopened = knowledge.Store(str(Path(root) / "state"), read_only=True)
            self.assertIn("firefox\x00ffmpeg", reopened.data["pairs"])

    def test_cli_import_requires_confirmation(self):
        with tempfile.TemporaryDirectory() as root:
            make_store(root)
            path = Path(root) / "learn.json"
            path.write_text(json.dumps(make_document()), encoding="utf-8")
            code, _output = run_cli(root, "learn", "import", str(path))
            self.assertEqual(code, 1)
            reopened = knowledge.Store(str(Path(root) / "state"), read_only=True)
            self.assertNotIn("firefox\x00ffmpeg", reopened.data["pairs"])

    def test_cli_import_rejects_invalid_document(self):
        with tempfile.TemporaryDirectory() as root:
            make_store(root)
            path = Path(root) / "learn.json"
            path.write_text('{"format": "taema-learn"}', encoding="utf-8")
            code, _output = run_cli(root, "learn", "import", str(path), "--yes")
            self.assertEqual(code, 2)


def make_full_store(root):
    store = make_store(root)
    store.add_veto("app", "firefox", reason="test veto")
    with store.decision_context("stop", owner="code", authority="pair"):
        store.log(event="stop", scope="scope-code")
    store.save()
    return store


class ResetTests(unittest.TestCase):
    def test_reset_learning_clears_answers_keeps_vetoes(self):
        with tempfile.TemporaryDirectory() as root:
            store = make_full_store(root)
            summary = store.reset_scope("learning")
            store.save()
            self.assertEqual(summary["pairs_removed"], 2)
            self.assertEqual(store.data["pairs"], {})
            self.assertEqual(store.data["standalone"], {})
            self.assertEqual(len(store.data["vetoes"]), 1)

    def test_reset_vetoes_only(self):
        with tempfile.TemporaryDirectory() as root:
            store = make_full_store(root)
            summary = store.reset_scope("vetoes")
            self.assertEqual(summary["vetoes_removed"], 1)
            self.assertEqual(len(store.data["pairs"]), 2)

    def test_reset_history_only(self):
        with tempfile.TemporaryDirectory() as root:
            store = make_full_store(root)
            summary = store.reset_scope("history")
            self.assertGreaterEqual(summary["decisions_removed"], 1)
            self.assertEqual(len(store.data["pairs"]), 2)

    def test_reset_rejects_bad_scope(self):
        with tempfile.TemporaryDirectory() as root:
            store = make_full_store(root)
            self.assertIsNone(store.reset_scope("everything"))

    def test_cli_reset_takes_backup_first(self):
        with tempfile.TemporaryDirectory() as root:
            make_full_store(root)
            code, output = run_cli(root, "reset", "--learning", "--yes")
            self.assertEqual(code, 0, output)
            backups = sorted((Path(root) / "state" / "backups").glob("*.tar.gz"))
            self.assertEqual(len(backups), 1)
            reopened = knowledge.Store(str(Path(root) / "state"), read_only=True)
            self.assertEqual(reopened.data["pairs"], {})
            self.assertEqual(len(reopened.data["vetoes"]), 1)

    def test_cli_reset_requires_one_scope(self):
        with tempfile.TemporaryDirectory() as root:
            make_full_store(root)
            code, _output = run_cli(root, "reset", "--yes")
            self.assertEqual(code, 2)
            code, _output = run_cli(root, "reset", "--learning", "--all", "--yes")
            self.assertEqual(code, 2)

    def test_cli_reset_requires_confirmation(self):
        with tempfile.TemporaryDirectory() as root:
            make_full_store(root)
            code, _output = run_cli(root, "reset", "--learning")
            self.assertEqual(code, 1)
            reopened = knowledge.Store(str(Path(root) / "state"), read_only=True)
            self.assertEqual(len(reopened.data["pairs"]), 2)

    def test_feedback_reset_scope(self):
        with tempfile.TemporaryDirectory() as root:
            store = make_full_store(root)
            reply = store.apply_feedback_command(
                {"v": 2, "id": "reset-1", "op": "reset_scope", "scope": "vetoes"}
            )
            self.assertTrue(reply["ok"])
            self.assertEqual(reply["vetoes_removed"], 1)


class RestoreTests(unittest.TestCase):
    def isolated(self, root):
        config_home = Path(root) / "config"
        config_home.mkdir(parents=True, exist_ok=True)
        return mock.patch.dict(
            os.environ, {"XDG_CONFIG_HOME": str(config_home)}, clear=False
        )

    def test_offline_round_trip(self):
        with tempfile.TemporaryDirectory() as root, self.isolated(root):
            make_full_store(root)
            code, _output = run_cli(
                root, "backup", "--to", str(Path(root) / "b.tar.gz")
            )
            self.assertEqual(code, 0)
            code, _output = run_cli(root, "reset", "--all", "--yes")
            self.assertEqual(code, 0)
            code, output = run_cli(
                root, "restore-backup", str(Path(root) / "b.tar.gz"), "--yes"
            )
            self.assertEqual(code, 0, output)
            reopened = knowledge.Store(str(Path(root) / "state"), read_only=True)
            self.assertEqual(len(reopened.data["pairs"]), 2)
            self.assertEqual(len(reopened.data["vetoes"]), 1)

    def test_rejects_bad_tarball(self):
        with tempfile.TemporaryDirectory() as root, self.isolated(root):
            make_full_store(root)
            bad = Path(root) / "bad.tar.gz"
            bad.write_text("not a tarball", encoding="utf-8")
            code, _output = run_cli(root, "restore-backup", str(bad), "--yes")
            self.assertEqual(code, 2)
            reopened = knowledge.Store(str(Path(root) / "state"), read_only=True)
            self.assertEqual(len(reopened.data["pairs"]), 2)

    def test_requires_confirmation(self):
        with tempfile.TemporaryDirectory() as root, self.isolated(root):
            make_full_store(root)
            target = str(Path(root) / "b.tar.gz")
            code, _output = run_cli(root, "backup", "--to", target)
            self.assertEqual(code, 0)
            code, _output = run_cli(root, "reset", "--all", "--yes")
            self.assertEqual(code, 0)
            code, _output = run_cli(root, "restore-backup", target)
            self.assertEqual(code, 1)
            reopened = knowledge.Store(str(Path(root) / "state"), read_only=True)
            self.assertEqual(reopened.data["pairs"], {})

    def test_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as root, self.isolated(root):
            make_full_store(root)
            evil = str(Path(root) / "evil.tar.gz")
            import tarfile

            with tarfile.open(evil, "w:gz") as archive:
                info = tarfile.TarInfo("../../evil")
                info.size = 0
                archive.addfile(info)
            code, _output = run_cli(root, "restore-backup", evil, "--yes")
            self.assertEqual(code, 2)

    def test_feedback_restore_refreshes_memory(self):
        with tempfile.TemporaryDirectory() as root, self.isolated(root):
            store = make_full_store(root)
            store.save()
            target = str(Path(root) / "b.tar.gz")
            code, _output = run_cli(root, "backup", "--to", target)
            self.assertEqual(code, 0)
            store.reset_scope("all")
            store.save()
            self.assertEqual(store.data["pairs"], {})
            staging = str(Path(root) / "staging")
            os.makedirs(staging)
            problem = transfer.stage_backup(target, staging)
            self.assertIsNone(problem)
            reply = store.apply_feedback_command(
                {"v": 2, "id": "restore-1", "op": "restore_backup", "staging": staging}
            )
            self.assertTrue(reply["ok"])
            self.assertEqual(len(store.data["pairs"]), 2)


if __name__ == "__main__":
    unittest.main()
