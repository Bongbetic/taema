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
        self.assertNotRegex(block, r"^  (push|pull_request):\n {3,}")


class VoidJobsTest(unittest.TestCase):
    def test_void_glibc_and_musl_containers(self):
        text = read(CI)
        # Either two literal jobs or a libc matrix over the official Void images.
        literal = "void-glibc" in text and "void-musl" in text
        matrix = "void-${{ matrix.libc }}" in text and (
            re.search(r"libc:\s*\[glibc,\s*musl\]", text)
            or ("- libc: glibc" in text and "- libc: musl" in text)
        )
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

    def test_quality_gates_run_on_python_311(self):
        text = read(CI)
        self.assertIn("ruff check src tests tools", text)
        self.assertIn("ruff format --check src tests tools", text)
        self.assertIn("mypy src/taema", text)
        self.assertIn("coverage run -m unittest discover", text)
        self.assertIn("tools/check_coverage.py", text)


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


class FuzzJobTest(unittest.TestCase):
    def test_ci_runs_fuzz_targets_with_a_short_budget(self):
        text = read(CI)
        self.assertIn("cargo-fuzz", text, "no cargo-fuzz install in CI")
        self.assertRegex(text, r"cargo fuzz run \S+.*max_total_time=\d+")
        for target in ("argv", "rules", "oom_record"):
            self.assertIn(target, text, f"CI fuzz misses target {target}")


class LongFuzzTest(unittest.TestCase):
    FUZZ = os.path.join(REPO, ".github", "workflows", "fuzz.yml")

    def test_scheduled_chunked_campaign(self):
        self.assertTrue(os.path.isfile(self.FUZZ), "missing .github/workflows/fuzz.yml")
        text = read(self.FUZZ)
        # Manually triggered or scheduled.
        self.assertIn("workflow_dispatch", text)
        self.assertRegex(text, r"schedule:\n\s+- cron:")
        # Chunked: more than one chunk per target.
        self.assertRegex(text, r"[Cc]hunks?")
        self.assertIn("max_total_time", text)
        # Corpus kept between runs.
        self.assertIn("actions/cache", text)
        self.assertIn("corpus", text)
        # Total fuzzing time reported.
        self.assertIn("GITHUB_STEP_SUMMARY", text)

    def test_long_campaign_covers_all_targets(self):
        text = read(self.FUZZ)
        for target in ("argv", "rules", "oom_record"):
            self.assertIn(target, text, f"long fuzz misses target {target}")


class ReleaseWorkflowTest(unittest.TestCase):
    def test_release_still_tests_and_builds_on_tags(self):
        text = read(RELEASE)
        self.assertIn('tags: ["taema-v*"]', text)
        self.assertIn("tools/build-xbps.sh", text)

    def test_release_container_installs_build_runtime_dependencies(self):
        text = read(RELEASE)
        install = next(
            line for line in text.splitlines() if "xbps-install -Sy python3" in line
        )
        self.assertIn("findutils", install)
        self.assertIn("tzdata", install)


if __name__ == "__main__":
    unittest.main()
