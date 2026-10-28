"""SECURITY.md: how to report vulnerabilities and how fixes are disclosed."""

import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(ROOT)
SECURITY = os.path.join(REPO, "SECURITY.md")


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


class DisclosureTest(unittest.TestCase):
    def test_security_policy_exists(self):
        self.assertTrue(os.path.isfile(SECURITY), "missing SECURITY.md at repo root")

    def test_names_a_disclosure_contact(self):
        text = read(SECURITY)
        contact = re.search(r"[\w.+-]+@[\w-]+\.[\w.]+", text) or re.search(
            r"https?://\S+", text
        )
        self.assertIsNotNone(contact, "SECURITY.md names no disclosure contact")

    def test_release_notes_must_call_out_privilege_boundary_fixes(self):
        text = read(SECURITY).lower()
        self.assertIn("release notes", text)
        self.assertIn("privilege boundary", text)


if __name__ == "__main__":
    unittest.main()
