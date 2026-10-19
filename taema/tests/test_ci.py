"""CI: the push/PR workflow runs the suites in Void glibc/musl containers and on Python 3.11."""
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(ROOT)
CI = os.path.join(REPO, ".github", "workflows", "ci.yml")
RELEASE = os.path.join(REPO, ".github", "workflows", "release.yml")
README = os.path.join(REPO, "README.md")


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


class TriggersTest(unittest.TestCase):
    def test_ci_workflow_exists(self):
        self.assertTrue(os.path.isfile(CI), "missing .github/workflows/ci.yml")

    def test_every_push_and_pull_request(self):
        text = read(CI)
        on = re.search(r"^on:\n((?:[ \t][^\n]*\n)*)", text, re.M)
        self.assertIsNotNone(on, "workflow has no top-level on: block")
        block = on.group(1)
        self.assertIn("  push:\n", block)
        self.assertIn("  pull_request:\n", block)
        # Every push and every pull request: no branch, path or event filters.
        self.assertNotRegex(block, r"^  (push|pull_request):\n[ \t]")


class VoidJobsTest(unittest.TestCase):
    def test_void_glibc_and_musl_containers(self):
        text = read(CI)
        # Either two literal jobs or a libc matrix over the official Void images.
        literal = "void-glibc" in text and "void-musl" in text
        matrix = ("void-${{ matrix.libc }}" in text
                  and re.search(r"libc:\s*\[glibc,\s*musl\]", text))
        self.assertTrue(literal or matrix, "no Void glibc and musl container jobs")

    def test_distribution_python(self):
        text = read(CI)
        self.assertIn("xbps-install -Sy python3", text)

    def test_suites_run_as_unprivileged_user(self):
        text = read(CI)
        self.assertIn("useradd -m builder", text)
        self.assertRegex(text, r"su builder[^\n]*make test")

    def test_package_build_script_runs(self):
        text = read(CI)
        self.assertIn("tools/build-xbps.sh", text)
        self.assertRegex(text, r"su builder[^\n]*build-xbps\.sh")


class PythonFloorTest(unittest.TestCase):
    def test_suites_run_on_python_311(self):
        text = read(CI)
        self.assertRegex(text, r"python-version:\s*['\"]3\.11['\"]")
        self.assertRegex(text, r"make (-C taema )?test")


class FailureTest(unittest.TestCase):
    def test_a_failing_step_fails_the_run(self):
        text = read(CI)
        # Nothing may shrug off a failure: a red step must fail the job, and with it
        # the commit and the pull request.
        self.assertNotIn("continue-on-error", text)


class ReadmeTest(unittest.TestCase):
    def test_readme_explains_local_checks(self):
        text = read(README)
        self.assertIn("## Checks", text, "README has no Checks section")
        checks = text.split("## Checks", 1)[1]
        self.assertIn("make -C taema test", checks)
        self.assertIn("tools/build-xbps.sh", checks)


class ReleaseWorkflowTest(unittest.TestCase):
    def test_release_still_tests_and_builds_on_tags(self):
        text = read(RELEASE)
        self.assertIn('tags: ["taema-v*"]', text)
        self.assertIn("tools/build-xbps.sh", text)


if __name__ == "__main__":
    unittest.main()
