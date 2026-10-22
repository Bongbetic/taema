import os
import tempfile
import unittest
from unittest import mock

from taema.core import oom


class OOMScoreTests(unittest.TestCase):
    def test_path_requires_a_real_process_id(self):
        self.assertEqual(oom._path(42), "/proc/42/oom_score_adj")
        for pid in (0, 1, -1, True, "42"):
            with self.subTest(pid=pid), self.assertRaises(ValueError):
                oom._path(pid)

    def test_reads_and_writes_bounded_scores(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "oom_score_adj")
            with open(path, "w", encoding="ascii") as target:
                target.write("-50\n")
            with mock.patch.object(oom, "_path", return_value=path):
                self.assertEqual(oom.read_score(42), -50)
                oom.write_score(42, 100)
                self.assertEqual(oom.read_score(42), 100)

    def test_rejects_malformed_and_out_of_range_kernel_values(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "oom_score_adj")
            with mock.patch.object(oom, "_path", return_value=path):
                for raw in ("", "x", "--1", "1001", "-1001"):
                    with self.subTest(raw=raw):
                        with open(path, "w", encoding="ascii") as target:
                            target.write(raw)
                        with self.assertRaises(ValueError):
                            oom.read_score(42)

    def test_rejects_invalid_values_before_writing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "oom_score_adj")
            with open(path, "w", encoding="ascii") as target:
                target.write("25\n")
            with mock.patch.object(oom, "_path", return_value=path):
                for value in (-1001, 1001, True, "25"):
                    with self.subTest(value=value):
                        with self.assertRaises(ValueError):
                            oom.write_score(42, value)
                with self.assertRaisesRegex(ValueError, "refusing to lower"):
                    oom.write_score(42, 24)
                with open(path, encoding="ascii") as source:
                    self.assertEqual(source.read(), "25\n")

    def test_write_checks_the_original_value_and_process_start(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "oom_score_adj")
            with open(path, "w", encoding="ascii") as target:
                target.write("25\n")
            with (
                mock.patch.object(oom, "_path", return_value=path),
                mock.patch.object(oom.process, "starttime", return_value=99),
            ):
                with self.assertRaisesRegex(ValueError, "identity changed"):
                    oom.write_score(42, 50, expected_start=100, original=25)
            with (
                mock.patch.object(oom, "_path", return_value=path),
                mock.patch.object(oom.process, "starttime", return_value=100),
            ):
                with self.assertRaisesRegex(ValueError, "changed before"):
                    oom.write_score(42, 50, expected_start=100, original=20)
            with open(path, encoding="ascii") as source:
                self.assertEqual(source.read(), "25\n")


if __name__ == "__main__":
    unittest.main()
