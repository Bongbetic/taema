"""Backup and restore of state, configuration, and units."""

import json
import os
import sqlite3
import stat
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from taema.cli import commands
from taema.store import knowledge


class BackupCliTests(unittest.TestCase):
    def make_tree(self, root):
        root = Path(root)
        config_home = root / "config"
        state_dir = root / "state"
        (config_home / "taema" / "taema.d").mkdir(parents=True)
        (config_home / "taema" / "units").mkdir(parents=True)
        (config_home / "taema" / "taema.toml").write_text(
            'mode = "adopt"\n', encoding="utf-8"
        )
        (config_home / "taema" / "taema.d" / "10-local.toml").write_text(
            "[timers]\nidle_grace = 40\n", encoding="utf-8"
        )
        (config_home / "taema" / "units" / "mine.toml").write_text(
            '[unit]\nname = "mine"\n', encoding="utf-8"
        )
        override = root / "taema.toml"
        override.write_text('[paths]\nstate_dir = "%s"\n' % state_dir, encoding="utf-8")
        state_dir.mkdir(parents=True, exist_ok=True)
        store = knowledge.Store(str(state_dir))
        store.save()
        return config_home, state_dir, override

    def test_backup_writes_db_config_and_units(self):
        with tempfile.TemporaryDirectory() as root:
            config_home, state_dir, override = self.make_tree(root)
            target = os.path.join(root, "out.tar.gz")
            with mock.patch.dict(
                os.environ, {"XDG_CONFIG_HOME": str(config_home)}, clear=False
            ):
                self.assertEqual(
                    commands.main(
                        ["--config", str(override), "backup", "--to", target]
                    ),
                    0,
                )
            self.assertTrue(os.path.isfile(target))
            self.assertEqual(oct(stat.S_IMODE(os.stat(target).st_mode)), "0o600")
            with tarfile.open(target, "r:gz") as archive:
                names = archive.getnames()
            for expected in (
                "state/state.db",
                "config/taema.toml",
                "config/taema.d/10-local.toml",
                "units/mine.toml",
                "manifest.json",
            ):
                self.assertIn(expected, names)
            with tempfile.TemporaryDirectory() as unpack:
                with tarfile.open(target, "r:gz") as archive:
                    archive.extractall(unpack)
                db_path = os.path.join(unpack, "state", "state.db")
                connection = sqlite3.connect("file:%s?mode=ro" % db_path, uri=True)
                try:
                    rows = connection.execute("PRAGMA quick_check").fetchall()
                finally:
                    connection.close()
                self.assertEqual(rows, [("ok",)])
                with open(os.path.join(unpack, "manifest.json")) as manifest:
                    document = json.load(manifest)
                self.assertEqual(document["version"], 1)
                self.assertEqual(
                    Path(unpack, "config", "taema.toml").read_text(),
                    'mode = "adopt"\n',
                )

    def test_backup_defaults_under_state_dir(self):
        with tempfile.TemporaryDirectory() as root:
            config_home, state_dir, override = self.make_tree(root)
            with mock.patch.dict(
                os.environ, {"XDG_CONFIG_HOME": str(config_home)}, clear=False
            ):
                self.assertEqual(
                    commands.main(["--config", str(override), "backup"]), 0
                )
            backups = sorted((state_dir / "backups").glob("*.tar.gz"))
            self.assertEqual(len(backups), 1)


if __name__ == "__main__":
    unittest.main()
