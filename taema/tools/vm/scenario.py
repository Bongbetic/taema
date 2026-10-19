#!/usr/bin/env python3
"""In-guest scenario API for the taema disposable Void VM harness.

This module runs as the VM test user inside a guest, and is also imported by
the host-side unit tests against temporary directories.  Stdlib only; no host
cgroup, service, or user state is ever touched (the cgroup/proc roots are
seams: TAEMA_CGROOT / TAEMA_PROCROOT, defaulting to the real paths inside a
guest).

Scenario API:
  spawn_gui_tree   start a fake GUI app root plus sleeping children
  close_root       terminate only the root; children must survive
  wait_for_event   wait for a daemon audit event (decisions.log)
  assert_scope_member / wait_for_scope / scope_members / scope_of
  capture_daemon_logs   collect daemon logs into the artifact directory
  run_privileged   run one privileged setup step (sudo -n, argv only)
"""
import argparse
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time

CGROOT = os.environ.get("TAEMA_CGROOT", "/sys/fs/cgroup")
PROCROOT = os.environ.get("TAEMA_PROCROOT", "/proc")

#: The fake application root: forks out of the SSH session, spawns children,
#: records the tree, and idles. The final process is deliberately not a
#: session leader; its session-leader parent stays alive long enough for the
#: lineage scanner to see the parent relationship and classify it separately.
APP_ROOT = '''\
import json, os, signal, subprocess, sys, time

def main():
    n = int(sys.argv[1])
    workdir = sys.argv[2]

    # Popen starts this launcher as a session leader. Its child can therefore
    # create a distinct session with setsid(), then fork a non-session-leader
    # app root. Keep that session leader as the root's parent until it exits so
    # the daemon can observe the relationship instead of seeing a ppid-1
    # newcomer.
    if os.fork():
        os._exit(0)
    os.setsid()
    root = os.fork()
    if root:
        with open(os.path.join(workdir, "supervisor.pid"), "w") as f:
            f.write(str(os.getpid()))
        os.waitpid(root, 0)
        return

    children = []
    for _ in range(n):
        p = subprocess.Popen(["/bin/sleep", "3600"], stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
        children.append(p.pid)
    tmp = os.path.join(workdir, "tree.json.tmp")
    with open(tmp, "w") as f:
        json.dump({"root": os.getpid(), "session": os.getsid(0),
                   "supervisor": os.getppid(), "started": time.monotonic(),
                   "children": children}, f)
    os.replace(tmp, os.path.join(workdir, "tree.json"))
    signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))
    while True:
        signal.pause()

main()
'''


class ScenarioError(Exception):
    """A scenario step failed or an expected state did not appear in time."""


def default_state_dir():
    base = os.environ.get("XDG_STATE_HOME") or os.path.join(
        os.path.expanduser("~"), ".local", "state")
    return os.path.join(base, "taema")


def configured_adopt_interval():
    """Read the daemon's adopt cadence from system and user TOML config."""
    interval = 15.0
    paths = ("/etc/taema/taema.toml",
             os.path.join(os.path.expanduser("~"), ".config", "taema", "taema.toml"))
    for path in paths:
        section = ""
        try:
            with open(path) as f:
                for raw in f:
                    line = raw.split("#", 1)[0].strip()
                    if line.startswith("[") and line.endswith("]"):
                        section = line[1:-1].strip()
                    elif section == "timers":
                        match = re.match(r"adopt_interval\s*=\s*([0-9]+(?:\.[0-9]+)?)$", line)
                        if match:
                            interval = max(0.1, float(match.group(1)))
        except OSError:
            continue
    return interval


# ---- process tree ----------------------------------------------------------

def spawn_gui_tree(workdir, children=2, timeout=10):
    """Start a detached fake GUI app with `children` sleeping descendants.

    Returns root/child/supervisor pids, session id, workdir, and launcher Popen.
    The root has its own session but is not a session leader; the smoke scenario
    keeps the SSH login session open until after the root is closed.
    """
    os.makedirs(workdir, exist_ok=True)
    app = os.path.join(workdir, "app_root.py")
    with open(app, "w") as f:
        f.write(APP_ROOT)
    log = open(os.path.join(workdir, "root.log"), "w")
    proc = subprocess.Popen([sys.executable, app, str(children), workdir],
                            cwd=workdir, stdout=log, stderr=subprocess.STDOUT,
                            start_new_session=True)
    log.close()
    treefile = os.path.join(workdir, "tree.json")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if os.path.exists(treefile):
            with open(treefile) as f:
                data = json.load(f)
            return {"root": int(data["root"]), "children": [int(p) for p in data["children"]],
                    "session": int(data["session"]),
                    "supervisor": int(data["supervisor"]),
                    "started": float(data["started"]),
                    "workdir": workdir, "proc": proc}
        time.sleep(0.05)
    rc = proc.poll()
    raise ScenarioError("app root did not report its tree within %ss (launcher rc=%s)"
                        % (timeout, rc))


def _reaped(pid):
    """True when pid is our child and has been waited for (or is not ours)."""
    try:
        done, _ = os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        return False
    return done == pid


def _alive(pid):
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def close_root(root_pid, timeout=10):
    """Terminate the app root only; its children are left running."""
    if not _alive(root_pid) and not _reaped(root_pid):
        return
    try:
        os.kill(root_pid, signal.SIGTERM)
    except OSError:
        pass
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _reaped(root_pid) or not _alive(root_pid):
            return
        time.sleep(0.05)
    try:
        os.kill(root_pid, signal.SIGKILL)
    except OSError:
        pass
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if _reaped(root_pid) or not _alive(root_pid):
            return
        time.sleep(0.05)
    raise ScenarioError("root pid %d survived SIGKILL" % root_pid)


def kill_tree(tree, timeout=5):
    """Best-effort teardown of a spawned tree (root first, then children)."""
    try:
        close_root(tree["root"], timeout=timeout)
    except (KeyError, ScenarioError):
        pass
    for pid in tree.get("children", []):
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
    deadline = time.monotonic() + timeout
    for pid in tree.get("children", []):
        while _alive(pid) and time.monotonic() < deadline:
            time.sleep(0.05)
    proc = tree.get("proc")
    if proc is not None:
        try:
            proc.wait(timeout=timeout)
        except Exception:
            pass
    supervisor = tree.get("supervisor")
    if supervisor:
        try:
            os.kill(supervisor, signal.SIGKILL)
        except OSError:
            pass


# ---- daemon events ---------------------------------------------------------

def wait_for_event(log_path, pattern, timeout=60, poll=0.25):
    """Wait until a line containing `pattern` appears in the daemon audit log."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            with open(log_path) as f:
                for line in f:
                    if pattern in line:
                        return line.rstrip("\n")
        except OSError:
            pass
        if time.monotonic() >= deadline:
            raise ScenarioError(
                "no line matching %r in %s within %ss" % (pattern, log_path, timeout))
        time.sleep(poll)


# ---- scope membership ------------------------------------------------------

def scope_of(pid, cgroot=None, procroot=None):
    """Relative cgroup path of pid under cgroot (e.g. user/1000/app-x-1)."""
    cgroot = cgroot or CGROOT
    procroot = procroot or PROCROOT
    path = os.path.join(procroot, str(pid), "cgroup")
    try:
        with open(path) as f:
            raw = f.read()
    except OSError:
        raise ScenarioError("pid %d has no readable cgroup" % pid)
    rel = ""
    for line in raw.splitlines():
        if line.startswith("0::"):
            cgpath = line[3:]
            if cgpath.startswith("/sys/fs/cgroup"):
                cgpath = cgpath[len("/sys/fs/cgroup"):]
            rel = cgpath.lstrip("/")
            break
    return rel


def scope_matches(rel, prefix):
    p = str(prefix).rstrip("/")
    return any(seg.startswith(p) for seg in rel.split("/"))


def scope_members(rel, cgroot=None):
    """Pids listed in the cgroup.procs of a scope relative to cgroot."""
    cgroot = cgroot or CGROOT
    path = os.path.join(cgroot, rel, "cgroup.procs")
    try:
        with open(path) as f:
            return [int(x) for x in f.read().split()]
    except OSError:
        raise ScenarioError("no cgroup.procs at %s" % path)


def assert_scope_member(pid, prefix, cgroot=None, procroot=None):
    """Assert pid lives in a scope whose path matches `prefix`; return the scope."""
    rel = scope_of(pid, cgroot=cgroot, procroot=procroot)
    if not scope_matches(rel, prefix):
        raise ScenarioError("pid %d is in scope %r which does not match %r"
                            % (pid, rel, prefix))
    members = scope_members(rel, cgroot=cgroot)
    if pid not in members:
        raise ScenarioError("pid %d is not a member of %r (members: %s)"
                            % (pid, rel, members))
    return rel


def wait_for_scope(pid, prefixes, timeout=90, poll=0.5, cgroot=None, procroot=None):
    """Wait until pid's scope matches one of `prefixes`; return the scope."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            rel = scope_of(pid, cgroot=cgroot, procroot=procroot)
            if any(scope_matches(rel, p) for p in prefixes):
                return rel
        except ScenarioError:
            pass
        if time.monotonic() >= deadline:
            raise ScenarioError("pid %d not in any scope matching %s within %ss"
                                % (pid, prefixes, timeout))
        time.sleep(poll)


# ---- logs and privileged steps --------------------------------------------

def capture_daemon_logs(dest_dir, state_dir=None, extra_dirs=()):
    """Copy user state and privileged daemon logs into dest_dir."""
    state = state_dir or default_state_dir()
    os.makedirs(dest_dir, exist_ok=True)
    copied = []
    for name in ("decisions.log", "decisions.log.1", "knowledge.json",
                 "feedback.jsonl", "feedback.jsonl.replay"):
        src = os.path.join(state, name)
        if os.path.isfile(src):
            dst = os.path.join(dest_dir, name)
            shutil.copy2(src, dst)
            os.chmod(dst, 0o644)
            copied.append(dst)
    for d in extra_dirs:
        if not os.path.exists(d):
            continue
        root_dst = os.path.join(dest_dir, os.path.basename(d.rstrip("/")) or "log")
        listing = run_privileged(["find", d, "-type", "f", "!", "-name", "lock", "-print0"])
        if listing.returncode != 0:
            raise OSError("cannot list privileged logs under %s: %s"
                          % (d, listing.stderr.strip()))
        for src in listing.stdout.split("\0"):
            if not src:
                continue
            rel = os.path.relpath(src, d)
            dst = os.path.join(root_dst, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            copied_file = run_privileged(["install", "-m", "0644", src, dst])
            if copied_file.returncode != 0:
                raise OSError("cannot copy privileged log %s: %s"
                              % (src, copied_file.stderr.strip()))
            copied.append(dst)
    return copied


def run_privileged(argv, timeout=60):
    """Run one privileged setup step as root (argv only, never a shell line)."""
    return subprocess.run(["sudo", "-n"] + [str(a) for a in argv],
                          capture_output=True, text=True, timeout=timeout)


def _run(argv, timeout=60):
    return subprocess.run([str(a) for a in argv],
                          capture_output=True, text=True, timeout=timeout)


def wait_for_auto_status(timeout=30, poll=0.5):
    """Wait for the per-user daemon socket to appear and answer status."""
    deadline = time.monotonic() + timeout
    attempts = 0
    while True:
        attempts += 1
        result = _run(["/usr/bin/taema", "status"], timeout=10)
        if result.returncode == 0 and '"mode": "auto"' in result.stdout:
            return result, attempts
        if time.monotonic() >= deadline:
            return result, attempts
        time.sleep(poll)


def runtime_socket_detail():
    runtime_dir = os.environ.get("XDG_RUNTIME_DIR") or "/run/user/%d" % os.getuid()
    path = os.path.join(runtime_dir, "taema.sock")
    try:
        st = os.stat(path)
        return "%s mode=%04o uid=%d gid=%d" % (
            path, st.st_mode & 0o7777, st.st_uid, st.st_gid)
    except OSError as e:
        return "%s unavailable: %s" % (path, e)


# ---- results ---------------------------------------------------------------

class ResultRecorder:
    """Collects step outcomes and writes <artifacts>/<name>.json."""

    def __init__(self, name, artifacts):
        self.name = name
        self.artifacts = artifacts
        self.steps = []
        self.started = time.time()
        os.makedirs(artifacts, exist_ok=True)

    def step(self, name, ok, detail=""):
        self.steps.append({"name": name, "ok": bool(ok),
                           "detail": str(detail).strip()[:4000]})
        return ok

    def finish(self, ok):
        data = {"scenario": self.name, "ok": bool(ok), "started": self.started,
                "duration_s": round(time.time() - self.started, 3),
                "steps": self.steps}
        path = os.path.join(self.artifacts, self.name + ".json")
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2, sort_keys=True)
        os.replace(tmp, path)
        return path


# ---- scenarios -------------------------------------------------------------

def scenario_smoke(rec, args, tree_holder):
    """Contain a GUI-like tree, close the root, verify survivor containment."""
    timeout = args.timeout
    runtime_dir = os.environ.get("XDG_RUNTIME_DIR", "")
    runner_pid = os.getpid()
    runner_sid = os.getsid(0)
    runner_scope = scope_of(runner_pid)
    rec.step("runner-session-leader", runner_sid == runner_pid,
             "pid=%d sid=%d pgrp=%d scope=%s"
             % (runner_pid, runner_sid, os.getpgrp(), runner_scope))
    rec.step("login-session-env", bool(runtime_dir),
             "XDG_RUNTIME_DIR=%s" % (runtime_dir or "<unset>"))

    service = run_privileged(["sv", "status", "/var/service/taema"])
    rec.step("service-status", service.returncode == 0,
             (service.stdout + service.stderr).strip()[:300])

    status, attempts = wait_for_auto_status(timeout=30)
    rec.step("daemon-status", status.returncode == 0 and '"mode": "auto"' in status.stdout,
             "attempts=%d HOME=%s XDG_RUNTIME_DIR=%s socket={%s} %s"
             % (attempts, os.environ.get("HOME", "<unset>"), runtime_dir or "<unset>",
                runtime_socket_detail(), (status.stdout or status.stderr)[:600]))

    tree = spawn_gui_tree(os.path.join(args.artifacts, "work"), children=2)
    tree_holder.append(tree)
    rec.step("spawn", True, "root=%d children=%s"
             % (tree["root"], tree["children"]))
    rec.step("fixture-session", tree["root"] != tree["session"]
             and tree["session"] != runner_sid,
             "root=%d session=%d runner_session=%d supervisor=%d"
             % (tree["root"], tree["session"], runner_sid, tree["supervisor"]))

    rel = wait_for_scope(tree["root"], ["app-"], timeout=timeout)
    rec.step("root-contained", rel != "", "scope=%s" % rel)
    rec.step("root-distinct-scope", rel != runner_scope,
             "root=%s runner=%s" % (rel, runner_scope))

    # decisions.log records the scope leaf (app-...), while cgroup paths
    # include the user/session prefix (user/<uid>/...).
    event = wait_for_event(os.path.join(args.state_dir, "decisions.log"),
                           os.path.basename(rel),
                           timeout=timeout)
    rec.step("daemon-event", True, event[:300])

    # The lineage model treats a root seen only once as a short-lived wrapper.
    # Keep the app alive through one full configured interval after the first
    # adoption event so the next pass records a second sighting before close.
    adopt_interval = configured_adopt_interval()
    observation_window = adopt_interval + 1.0
    time.sleep(observation_window)
    stable_scope = scope_of(tree["root"])
    root_age = time.monotonic() - tree["started"]
    second_sighting = (_alive(tree["root"]) and stable_scope == rel
                       and root_age >= observation_window)
    rec.step("root-observed-twice", second_sighting,
             "first_adopt=%s held=%.3fs adopt_interval=%.3fs root_age=%.3fs scope=%s"
             % (event[:200], observation_window, adopt_interval, root_age, stable_scope))

    close_started = time.monotonic()
    close_root(tree["root"], timeout=15)
    closed_at = time.monotonic()
    rec.step("close-root", True, "root=%d terminated in %.3fs"
             % (tree["root"], closed_at - close_started))

    alive = [p for p in tree["children"] if _alive(p)]
    rec.step("children-alive", len(alive) == len(tree["children"]),
             "alive=%s of %s" % (alive, tree["children"]))

    first = tree["children"][0]
    leftover = wait_for_scope(first, ["leftover/"], timeout=timeout)
    promotion_latency = time.monotonic() - closed_at
    rec.step("survivors-contained", leftover != "", "scope=%s" % leftover)
    rec.step("survivor-promotion-latency", promotion_latency <= timeout,
             "scope=%s seconds_after_root_close=%.3f timeout=%ds"
             % (leftover, promotion_latency, timeout))

    both = [assert_scope_member(p, "leftover/") for p in tree["children"]]
    rec.step("assert-scope-membership", both[0] == both[1],
             "members=%s" % both)

    review_event = wait_for_event(os.path.join(args.state_dir, "decisions.log"),
                                  "review_created", timeout=timeout)
    review = _run(["/usr/bin/taema", "review"], timeout=30)
    rec.step("review-created", review.returncode == 0 and "review #" in review.stdout
             and "survivors=" in review.stdout,
             (review_event + "\n" + review.stdout + review.stderr)[:800])

    return all(s["ok"] for s in rec.steps)


def scenario_upgrade(rec, args, tree_holder):
    """Install the previous release, then upgrade back to the working tree."""
    prevdir = os.path.dirname(args.previous)
    index = run_privileged(["xbps-rindex", "-f", "-a", args.previous])
    rec.step("index-previous", index.returncode == 0,
             (index.stdout + index.stderr)[-600:])
    down = run_privileged(["xbps-install", "-y", "-i", "--repository", prevdir, "taema"])
    rec.step("install-previous", down.returncode == 0, (down.stdout + down.stderr)[-600:])

    ver = _run(["/usr/bin/taema", "--version"])
    rec.step("previous-version", args.previous_version in (ver.stdout + ver.stderr),
             (ver.stdout + ver.stderr).strip()[:200])

    up = run_privileged(["xbps-install", "-y", "-i", "--repository", args.package_dir, "taema"])
    rec.step("install-current", up.returncode == 0, (up.stdout + up.stderr)[-600:])

    ver = _run(["/usr/bin/taema", "--version"])
    rec.step("current-version", args.current_version in (ver.stdout + ver.stderr),
             (ver.stdout + ver.stderr).strip()[:200])

    svc = run_privileged(["sv", "status", "/var/service/taema"])
    rec.step("service-up", svc.returncode == 0, (svc.stdout + svc.stderr).strip()[:300])

    status = _run(["/usr/bin/taema", "status"], timeout=30)
    rec.step("daemon-status", status.returncode == 0, (status.stdout or status.stderr)[:300])
    return all(s["ok"] for s in rec.steps)


def scenario_remove(rec, args, tree_holder):
    """Remove the package and verify the guest is cleaned up."""
    rm = run_privileged(["xbps-remove", "-y", "taema"])
    rec.step("remove-package", rm.returncode == 0, (rm.stdout + rm.stderr)[-600:])

    q = run_privileged(["xbps-query", "taema"])
    rec.step("package-gone", q.returncode != 0,
             "rc=%d %s" % (q.returncode, (q.stdout + q.stderr).strip()[:200]))

    missing = [p for p in ("/usr/bin/taema", "/usr/lib/taema") if not os.path.exists(p)]
    rec.step("binaries-gone", len(missing) == 2, "absent=%s" % missing)

    rec.step("service-gone", not os.path.lexists("/var/service/taema"),
             "/var/service/taema")

    leftovers = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit() or int(entry) == os.getpid():
            continue
        try:
            with open(os.path.join("/proc", entry, "cmdline"), "rb") as f:
                cmd = f.read().replace(b"\0", b" ").decode("utf-8", "replace")
        except OSError:
            continue
        if "taema daemon" in cmd:
            leftovers.append((entry, cmd[:120]))
    rec.step("daemon-stopped", not leftovers, "running=%s" % leftovers)
    return all(s["ok"] for s in rec.steps)


SCENARIOS = {"smoke": scenario_smoke, "upgrade": scenario_upgrade,
             "remove": scenario_remove}


def ensure_session_leader():
    """Exclude the CLI runner from app-root adoption without moving cgroups."""
    pid = os.getpid()
    if os.getsid(0) == pid:
        return True
    # setsid(2) rejects process-group leaders. In that unusual launch shape,
    # leave the process in place and let the smoke assertion report the issue.
    if os.getpgrp() == pid:
        return False
    try:
        os.setsid()
    except OSError:
        return False
    return os.getsid(0) == pid


def main(argv):
    parser = argparse.ArgumentParser(prog="scenario.py",
                                     description="taema VM scenario runner")
    sub = parser.add_subparsers(dest="name", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--artifacts", required=True,
                        help="directory where results and logs are written")
    common.add_argument("--state-dir", default=default_state_dir(),
                        help="taema user state directory (decisions.log lives here)")
    common.add_argument("--timeout", type=int, default=180,
                        help="per-step wait timeout in seconds")
    common.add_argument("--package-dir",
                        help="local repository with the current package (upgrade)")
    common.add_argument("--previous", help="path to the previous release .xbps")
    common.add_argument("--previous-version", help="expected previous version")
    common.add_argument("--current-version", help="expected current version")
    for name in sorted(SCENARIOS):
        sub.add_parser(name, parents=[common])
    args = parser.parse_args(argv)

    rec = ResultRecorder(args.name, args.artifacts)
    tree_holder = []
    ok = False
    try:
        ok = SCENARIOS[args.name](rec, args, tree_holder)
    except ScenarioError as e:
        rec.step("fatal", False, str(e))
        ok = False
    except Exception as e:  # noqa: BLE001 - any crash is a scenario failure
        rec.step("fatal", False, "%s: %s" % (type(e).__name__, e))
        ok = False
    finally:
        for tree in tree_holder:
            kill_tree(tree, timeout=10)
        try:
            copied = capture_daemon_logs(
                os.path.join(args.artifacts, "daemon-logs"),
                state_dir=args.state_dir, extra_dirs=("/var/log/taema",))
            captured = bool(copied)
            detail = "files=%d" % len(copied)
        except OSError as e:
            captured = False
            detail = "%s: %s" % (type(e).__name__, e)
        rec.step("capture-daemon-logs", captured, detail)
        ok = ok and captured
        rec.finish(ok)
    print("%s: %s" % (args.name, "PASS" if ok else "FAIL"))
    for step in rec.steps:
        print("  [%s] %s" % ("ok" if step["ok"] else "FAIL", step["name"]))
    return 0 if ok else 1


if __name__ == "__main__":
    ensure_session_leader()
    sys.exit(main(sys.argv[1:]))
