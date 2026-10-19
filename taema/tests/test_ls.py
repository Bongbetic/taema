"""Ticket 7: MEM and PSI columns in `taema ls`, against the fake cgroup tree with memory
files present and absent. Missing facts degrade to '-', never to a crash."""

import io
import unittest
from contextlib import redirect_stdout

from taema import cgroup, cli
from tests.test_phase0 import FakeCg
from tests.test_phase1 import write

PSI = (
    "some avg10=12.34 avg60=1.00 avg300=0.50 total=12345\n"
    "full avg10=0.01 avg60=0.00 avg300=0.00 total=678\n"
)


def ls():
    """Run cmd_ls against the current fake cgroup tree; return (rc, stdout)."""
    out = io.StringIO()
    with redirect_stdout(out):
        rc = cli.cmd_ls(None)
    return rc, out.getvalue()


def row(out, name):
    """The single output line whose first column is scope `name`."""
    hits = [ln for ln in out.splitlines() if ln.split() and ln.split()[0] == name]
    if not hits:
        raise AssertionError("no row for %r in:\n%s" % (name, out))
    assert len(hits) == 1, hits
    return hits[0]


class LsColumns(unittest.TestCase):
    def test_header_names_mem_and_psi(self):
        with FakeCg() as cg:
            cg.leaf("scope-a")
            rc, out = ls()
        self.assertEqual(rc, 0)
        self.assertIn("MEM", out)
        self.assertIn("PSI", out)

    def test_readable_memory_and_pressure_are_shown(self):
        with FakeCg() as cg:
            d = cg.leaf("scope-a")
            write(d + "/memory.current", "1610612736\n")  # 1.5 GiB
            write(d + "/memory.pressure", PSI)
            rc, out = ls()
        self.assertEqual(rc, 0)
        r = row(out, "scope-a")
        self.assertIn("1.5G", r)  # human-readable MEM
        self.assertIn("12.34", r)  # some avg10

    def test_missing_memory_files_show_dash_not_failure(self):
        with FakeCg() as cg:
            cg.leaf("scopeplain")  # no memory.* files at all
            rc, out = ls()
        self.assertEqual(rc, 0)
        r = row(out, "scopeplain")  # no dash in the name itself
        self.assertIn("-", r)
        self.assertNotIn("12.34", r)

    def test_mem_and_psi_degrade_independently_per_scope(self):
        with FakeCg() as cg:
            a = cg.leaf("scope-half")
            b = cg.leaf("scope-full")
            write(a + "/memory.current", "512\n")  # memory only -> PSI is '-'
            write(b + "/memory.pressure", PSI)  # pressure only -> MEM is '-'
            rc, out = ls()
        self.assertEqual(rc, 0)
        ra, rb = row(out, "scope-half"), row(out, "scope-full")
        self.assertIn("512", ra)
        self.assertNotIn("12.34", ra)
        self.assertIn("12.34", rb)
        self.assertIn("-", rb)  # MEM unknown -> dash

    def test_every_scope_row_has_both_cells(self):
        with FakeCg() as cg:
            cg.leaf("shared/adb-1")
            d = cg.leaf("scope-nested")
            write(d + "/memory.current", "1048576\n")
            write(d + "/memory.pressure", PSI)
            rc, out = ls()
        self.assertEqual(rc, 0)
        self.assertEqual(len(out.splitlines()), 4)  # header + 3 scope rows
        for name in ("shared", "adb-1", "scope-nested"):
            row(out, name)


class Readers(unittest.TestCase):
    def test_memory_current_present_absent_and_garbage(self):
        with FakeCg() as cg:
            ok = cg.leaf("scope-ok")
            bare = cg.leaf("scope-bare")
            bad = cg.leaf("scope-bad")
            write(ok + "/memory.current", "4096\n")
            write(bad + "/memory.current", "garbage\n")
            self.assertEqual(cgroup.memory_current(ok), 4096)
            self.assertIsNone(cgroup.memory_current(bare))
            self.assertIsNone(cgroup.memory_current(bad))
        self.assertIsNone(cgroup.memory_current("/nonexistent/scope"))

    def test_memory_psi_reads_some_avg10_only(self):
        with FakeCg() as cg:
            ok = cg.leaf("scope-ok")
            bare = cg.leaf("scope-bare")
            full = cg.leaf("scope-full")
            write(ok + "/memory.pressure", PSI)
            write(
                full + "/memory.pressure",
                "full avg10=99.99 avg60=0.00 avg300=0.00 total=1\n",
            )
            self.assertEqual(cgroup.memory_psi(ok), 12.34)
            self.assertIsNone(cgroup.memory_psi(bare))
            self.assertIsNone(cgroup.memory_psi(full))  # no 'some' line -> unknown
        self.assertIsNone(cgroup.memory_psi("/nonexistent/scope"))


class Formatting(unittest.TestCase):
    def test_fmt_mem(self):
        self.assertEqual(cli._fmt_mem(None), "-")
        self.assertEqual(cli._fmt_mem(0), "0")
        self.assertEqual(cli._fmt_mem(512), "512")
        self.assertEqual(cli._fmt_mem(1536), "1.5K")
        self.assertEqual(cli._fmt_mem(1610612736), "1.5G")

    def test_fmt_psi(self):
        self.assertEqual(cli._fmt_psi(None), "-")
        self.assertEqual(cli._fmt_psi(0), "0.00")
        self.assertEqual(cli._fmt_psi(12.34), "12.34")
        self.assertEqual(cli._fmt_psi(100), "100.00")


if __name__ == "__main__":
    unittest.main()
