"""Phase 3 tests: taema-hook against a fake daemon, the shell hooks, and the kill_done flow."""

import importlib.machinery
import importlib.util
import json
import os
import pty
import select
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from unittest import mock

from taema import daemon
from tests.test_phase0 import FakeCg, make_cfg, tmp
from tests.test_phase2 import ProcCase

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOK = os.path.join(ROOT, "libexec", "taema-hook")


def load_hook():
    loader = importlib.machinery.SourceFileLoader("taema_hook", HOOK)
    spec = importlib.util.spec_from_loader("taema_hook", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


hook = load_hook()


class FakeDaemon:
    """A unix socket server thread: records each request, answers with replies(msg)."""

    def __init__(self, replies=None):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "t.sock")
        self.replies = replies or (lambda m: {"ok": True})
        self.got = []
        self.srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.srv.bind(self.path)
        self.srv.listen(8)
        self.t = threading.Thread(target=self.loop, daemon=True)
        self.t.start()

    def loop(self):
        while True:
            try:
                c, _ = self.srv.accept()
            except OSError:
                return
            with c:
                buf = b""
                while not buf.endswith(b"\n"):
                    d = c.recv(65536)
                    if not d:
                        break
                    buf += d
                try:
                    m = json.loads(buf)
                except ValueError:
                    continue
                self.got.append(m)
                c.sendall((json.dumps(self.replies(m)) + "\n").encode())

    def close(self):
        self.srv.close()
        shutil.rmtree(self.dir, ignore_errors=True)


def run_hook(*args, sock, timeout=5):
    env = dict(os.environ, TAEMA_SOCKET=sock)
    return subprocess.run([HOOK, *args], env=env, capture_output=True, timeout=timeout)


QUESTION = {
    "id": 1,
    "kind": "job",
    "nonce": "abc123",
    "shell_pid": 20,
    "job": "npm run dev",
    "candidates": [
        {"id": 1, "kind": "job", "key": "npm", "label": "npm run dev"},
        {"id": 2, "kind": "ancestor", "key": "code", "label": "code"},
    ],
    "leftovers": [
        {"key": "node:esbuild", "comm": "node", "count": 1},
        {"key": "node:vite", "comm": "node", "count": 1},
    ],
    "choices": ["stop", "keep", "standalone"],
    "expires_in": 60,
}


class TtyCase(unittest.TestCase):
    """A pty pair: the hook reads keys from the slave, the test plays the user on the master."""

    def setUp(self):
        self.master, self.slave = pty.openpty()
        self.addCleanup(os.close, self.master)
        self.addCleanup(os.close, self.slave)

    def read_until(self, needle, timeout=3.0):
        out, end = b"", time.time() + timeout
        while needle not in out and time.time() < end:
            if select.select([self.master], [], [], 0.1)[0]:
                out += os.read(self.master, 4096)
        return out

    def drain(self, wait=0.2):
        out = b""
        while select.select([self.master], [], [], wait)[0]:
            out += os.read(self.master, 4096)
        return out

    def ask_in_thread(self, paths, shell=20):
        res = []
        t = threading.Thread(
            target=lambda: res.append(hook.ask(shell, fd=self.slave, paths=paths))
        )
        t.start()
        return t, res


# ---- 1. taema-hook: done / kill ----------------------------------------------------------------------


class HookSend(unittest.TestCase):
    def setUp(self):
        self.d = FakeDaemon()
        self.addCleanup(self.d.close)

    def test_executable_and_isolated(self):
        self.assertTrue(os.access(HOOK, os.X_OK))
        with open(HOOK) as f:
            self.assertEqual(f.readline().strip(), "#!/usr/bin/python3 -IS")

    def test_done(self):
        r = run_hook("done", "20", "20.3", "1", "npm", sock=self.d.path)
        self.assertEqual((r.returncode, r.stdout, r.stderr), (0, b"", b""))
        self.assertEqual(
            self.d.got,
            [
                {
                    "cmd": "job_done",
                    "shell_pid": 20,
                    "tag": "20.3",
                    "status": 1,
                    "word": "npm",
                }
            ],
        )

    def test_done_strips_and_caps_word(self):
        run_hook("done", "20", "20.3", "0", "a\x1b[2Jb" + "x" * 50, sock=self.d.path)
        self.assertEqual(self.d.got[0]["word"], "a[2Jb" + "x" * 27)

    def test_done_without_word(self):
        run_hook("done", "20", "20.3", "0", "", sock=self.d.path)
        self.assertEqual(self.d.got[0]["word"], "")

    def test_kill(self):
        r = run_hook("kill", "20", "pkill", sock=self.d.path)
        self.assertEqual((r.returncode, r.stdout), (0, b""))
        self.assertEqual(
            self.d.got, [{"cmd": "kill_done", "shell_pid": 20, "word": "pkill"}]
        )
        run_hook("kill", "20", "rm", sock=self.d.path)
        self.assertEqual(len(self.d.got), 1)

    def test_daemon_down_is_silent_and_fast(self):
        t = time.monotonic()
        for args in (
            ("done", "20", "20.1", "0", "x"),
            ("kill", "20", "kill"),
            ("ask", "20"),
        ):
            r = run_hook(*args, sock="/nonexistent/none.sock")
            self.assertEqual((r.returncode, r.stdout, r.stderr), (0, b"", b""), args)
        self.assertLess(time.monotonic() - t, 3.0)

    def test_garbage_arguments_exit_zero(self):
        for args in (
            (),
            ("done",),
            ("done", "x", "y", "z"),
            ("ask", "notanumber"),
            ("bogus", "20"),
            ("done", "1", "1.1", "0", "x"),
        ):
            r = run_hook(*args, sock=self.d.path)
            self.assertEqual((r.returncode, r.stdout), (0, b""), args)
        self.assertEqual(self.d.got, [])

    def test_hung_daemon_stays_within_budget(self):
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        path = tempfile.mkdtemp() + "/h.sock"
        srv.bind(path)
        srv.listen(1)
        self.addCleanup(srv.close)
        t = time.monotonic()
        r = run_hook("done", "20", "20.1", "0", "x", sock=path)
        self.assertEqual(r.returncode, 0)
        self.assertLess(time.monotonic() - t, 2.0)


# ---- 2. taema-hook: the question -----------------------------------------------------------------------


class QuestionText(unittest.TestCase):
    def test_job_question_matches_the_plan(self):
        lines = hook.format_question(QUESTION)
        self.assertEqual(
            lines[0],
            "tæma: `npm run dev` left 2 processes running (node:esbuild, node:vite).",
        )
        self.assertEqual(
            lines[1], "  [1] part of npm run dev: stop them when it closes"
        )
        self.assertEqual(lines[2], "  [2] part of another app: code")
        self.assertIn("[3] standalone app", lines[3])
        self.assertEqual(lines[4], "  [Enter] ask me later")

    def test_seen_count_shown_when_given(self):
        q = json.loads(json.dumps(QUESTION))
        q["candidates"][1]["seen"] = 3
        self.assertEqual(
            hook.format_question(q)[2], "  [2] part of another app: code (seen 3x)"
        )

    def test_no_other_candidates_no_option_two(self):
        q = dict(QUESTION, candidates=QUESTION["candidates"][:1])
        text = "\n".join(hook.format_question(q))
        self.assertNotIn("[2]", text)
        self.assertEqual(hook.map_key("2", q), ("later",))

    def test_closed_question(self):
        q = dict(
            QUESTION,
            kind="closed",
            leftovers=[{"key": "node:vite", "comm": "vite", "count": 1}],
        )
        lines = hook.format_question(q)
        self.assertEqual(
            lines[0], "tæma: `vite` was closed. Was it part of npm run dev?"
        )
        self.assertIn("[1] yes", lines[1])

    def test_control_characters_stripped_and_width_kept(self):
        q = json.loads(json.dumps(QUESTION))
        q["job"] = "evil\x1b[2J\x07‮" + "x" * 300
        q["candidates"][0]["label"] = "a\x1b]0;pwn\x07b\x9b"
        q["leftovers"][0]["key"] = "k\r\x08\x1b[31mred"
        text = "\n".join(hook.format_question(q))
        for ch in "\x1b\x07\r\x08\x9b‮":
            self.assertNotIn(ch, text)
        for line in text.split("\n"):
            self.assertLessEqual(len(line), 80)

    def test_many_leftovers_are_summarised(self):
        q = dict(
            QUESTION,
            leftovers=[{"key": "k%d" % i, "comm": "c", "count": 2} for i in range(9)],
        )
        head = hook.format_question(q)[0]
        self.assertIn("left 18 processes", head)
        self.assertIn("...", head)

    def test_key_mapping(self):
        m = hook.map_key
        self.assertEqual(m("1", QUESTION), ("answer", "stop", "npm"))
        self.assertEqual(m("2", QUESTION), ("answer", "stop", "code"))
        self.assertEqual(m("3", QUESTION), ("answer", "standalone", None))
        for k in ("", "\r", "\n", "x", "4", "0"):
            self.assertEqual(m(k, QUESTION), ("later",), k)
        three = json.loads(json.dumps(QUESTION))
        three["candidates"].append(
            {"id": 3, "kind": "historic", "key": "idea", "label": "idea"}
        )
        self.assertEqual(m("2", three), ("menu",))
        self.assertEqual(hook.menu_choice("1", three), "code")
        self.assertEqual(hook.menu_choice("2", three), "idea")
        self.assertIsNone(hook.menu_choice("3", three))
        self.assertIsNone(hook.menu_choice("", three))

    def test_typeahead_detection(self):
        m, s = pty.openpty()
        self.addCleanup(os.close, m)
        self.addCleanup(os.close, s)
        self.assertFalse(hook.pending_input(s))
        os.write(m, b"ls")
        time.sleep(0.1)
        self.assertTrue(hook.pending_input(s))
        self.assertTrue(hook.pending_input(-1))  # unknown counts as waiting


class AskFlow(TtyCase):
    def setUp(self):
        super().setUp()
        self.answer = {
            "ok": True,
            "choice": "stop",
            "owner": "npm",
            "leftovers": ["node:vite"],
        }
        self.d = FakeDaemon(
            lambda m: {"question": QUESTION} if m["cmd"] == "ask" else self.answer
        )
        self.addCleanup(self.d.close)

    def play(self, keys, expect=b"ask me later"):
        t, res = self.ask_in_thread([self.d.path])
        out = self.read_until(expect)
        for k in keys:
            os.write(self.master, k.encode())
            time.sleep(0.1)
        t.join(5)
        return res[0], out + self.drain()

    def test_stop_with_first_candidate(self):
        res, out = self.play(["1"])
        self.assertEqual(res, "answered")
        self.assertIn("tæma: `npm run dev` left 2 processes".encode(), out)
        self.assertEqual(
            self.d.got[1],
            {"cmd": "answer", "nonce": "abc123", "choice": "stop", "owner": "npm"},
        )
        self.assertIn(b"noted", out)
        self.assertEqual(out.count(b"noted"), 1)
        self.assertNotIn(b"\x1b", out)

    def test_standalone_has_no_owner(self):
        res, _out = self.play(["3"])
        self.assertEqual(res, "answered")
        self.assertEqual(
            self.d.got[1], {"cmd": "answer", "nonce": "abc123", "choice": "standalone"}
        )

    def test_second_menu(self):
        q = json.loads(json.dumps(QUESTION))
        q["candidates"].append(
            {"id": 3, "kind": "historic", "key": "idea", "label": "idea"}
        )
        self.d.replies = lambda m: {"question": q} if m["cmd"] == "ask" else self.answer
        res, out = self.play(["2", "2"])
        self.assertEqual(res, "answered")
        self.assertIn(b"which app", out)
        self.assertEqual(self.d.got[1]["owner"], "idea")

    def test_enter_and_escape_ask_later(self):
        for key in ("\r", "\x1b[A"):
            self.d.got.clear()
            res, out = self.play([key])
            self.assertEqual(res, "later")
            self.assertEqual([m["cmd"] for m in self.d.got], ["ask"])
            self.assertIn(b"ask later", out)

    def test_timeout_asks_later(self):
        with mock.patch.object(
            hook, "read_key", return_value=""
        ):  # what read_key gives on timeout
            self.assertEqual(hook.ask(20, fd=self.slave, paths=[self.d.path]), "later")
        self.assertEqual([m["cmd"] for m in self.d.got], ["ask"])

    def test_read_key_timeout(self):
        t = time.monotonic()
        self.assertEqual(hook.read_key(self.slave, 0.2), "")
        self.assertLess(time.monotonic() - t, 2.0)

    def test_read_key_restores_terminal(self):
        import termios

        before = termios.tcgetattr(self.slave)
        os.write(self.master, b"3")
        self.assertEqual(hook.read_key(self.slave, 2.0), "3")
        self.assertEqual(termios.tcgetattr(self.slave), before)

    def test_typeahead_skips_the_question(self):
        os.write(self.master, b"ls")
        time.sleep(0.1)
        self.assertEqual(hook.ask(20, fd=self.slave, paths=[self.d.path]), "typeahead")
        self.assertEqual(self.d.got, [])

    def test_no_question_is_silent(self):
        self.d.replies = lambda m: {"question": None, "reason": "none"}
        self.assertEqual(hook.ask(20, fd=self.slave, paths=[self.d.path]), "none")
        self.assertEqual(self.drain(), b"")

    def test_refused_answer_is_reported(self):
        self.answer = {"error": "unknown or expired nonce"}
        res, out = self.play(["1"])
        self.assertEqual(res, "failed")
        self.assertIn(b"could not save", out)

    def test_daemon_down(self):
        self.assertEqual(
            hook.ask(20, fd=self.slave, paths=["/nonexistent/x.sock"]), "down"
        )
        self.assertEqual(self.drain(), b"")

    def test_later_removes_the_pending_file(self):
        rt = tmp()
        os.makedirs(rt + "/taema")
        with open(rt + "/taema/q.20", "w") as f:
            f.write("{}")
        with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": rt}):
            self.play(["\r"])
        self.assertFalse(os.path.exists(rt + "/taema/q.20"))


# ---- 3. shell hooks -------------------------------------------------------------------------------------------

BASH = os.path.join(ROOT, "shell", "taema.bash")
ZSH = os.path.join(ROOT, "shell", "taema.zsh")
FISH = os.path.join(ROOT, "shell", "taema.fish")


class ShellFiles(unittest.TestCase):
    def test_syntax(self):
        self.assertEqual(subprocess.run(["bash", "-n", BASH]).returncode, 0)
        for exe, args, path in (("zsh", ["-n"], ZSH), ("fish", ["-n"], FISH)):
            if shutil.which(exe):
                self.assertEqual(subprocess.run([exe, *args, path]).returncode, 0, exe)

    def test_no_debug_trap_and_no_subprocess_on_the_idle_path(self):
        for path in (BASH, ZSH, FISH):
            with open(path) as f:
                text = f.read()
            code = "\n".join(
                l for l in text.split("\n") if not l.lstrip().startswith("#")
            )
            self.assertNotIn("trap ", code, path)
            self.assertNotIn("$(date", code, path)

    def test_files_are_installed(self):
        with open(os.path.join(ROOT, "Makefile")) as f:
            mk = f.read()
        for needle in (
            "shell/taema.bash",
            "shell/taema.zsh",
            "shell/taema.fish",
            "libexec/taema-hook",
            "bashrc.d",
            "vendor_conf.d",
        ):
            self.assertIn(needle, mk)


def bash_script(body, env=None, interactive=True):
    """Run bash on a pty (stdin and stdout are terminals); returns (status, output)."""
    master, slave = pty.openpty()
    e = dict(os.environ, PATH="/usr/bin:/bin")
    e.update(env or {})
    p = subprocess.Popen(
        ["bash", "--norc", "--noprofile"] + (["-i"] if interactive else ["-c", body]),
        stdin=slave,
        stdout=slave,
        stderr=slave,
        env=e,
        close_fds=True,
    )
    os.close(slave)
    if interactive:
        os.write(master, (body + "\nexit\n").encode())
    out = b""
    end = time.time() + 15
    while time.time() < end:
        if select.select([master], [], [], 0.2)[0]:
            try:
                d = os.read(master, 4096)
            except OSError:
                break
            if not d:
                break
            out += d
        elif p.poll() is not None:
            break
    p.wait(10)
    os.close(master)
    return p.returncode, out.decode("utf-8", "replace")


class BashHook(unittest.TestCase):
    def setUp(self):
        self.dir = tmp()
        self.calls = self.dir + "/calls"
        self.hook = self.dir + "/hook"
        with open(self.hook, "w") as f:
            f.write('#!/bin/bash\necho "$@" >> %s\n' % self.calls)
        os.chmod(self.hook, 0o755)
        self.env = {"TAEMA_HOOK": self.hook, "XDG_RUNTIME_DIR": self.dir + "/rt"}
        self.addCleanup(shutil.rmtree, self.dir, True)

    def src(self):
        return "source %s\n" % BASH

    def called(self):
        try:
            with open(self.calls) as f:
                return f.read().splitlines()
        except OSError:
            return []

    def test_installs_exactly_one_hook(self):
        _rc, out = bash_script(
            self.src()
            + self.src()
            + 'echo "PC=${#PROMPT_COMMAND[@]}:${PROMPT_COMMAND[0]}"; '
            'echo "JOB=$TAEMA_JOB"; echo "PID=$$"',
            self.env,
        )
        self.assertIn("PC=1:_taema_precmd", out)
        job = [l for l in out.splitlines() if l.startswith("JOB=")][-1][4:]
        pid = [l for l in out.splitlines() if l.startswith("PID=")][-1][4:]
        self.assertRegex(job, r"^%s\.\d+\s*$" % pid.strip())

    def test_ps0_added_once(self):
        _rc, out = bash_script(
            self.src()
            + self.src()
            + 'echo "PS0N=$(printf %s "$PS0" | grep -o _taema_t0 | wc -l)"',
            self.env,
        )
        self.assertIn("PS0N=1", out)

    def test_off_when_not_interactive_or_disabled_or_hook_missing(self):
        for env, interactive in (
            ({}, False),
            ({"TAEMA_NO_PROMPT": "1"}, True),
            ({"TAEMA_HOOK": "/nonexistent"}, True),
        ):
            e = dict(self.env, **env)
            body = (
                self.src()
                + 'echo "PC=${#PROMPT_COMMAND[@]}"; echo "J=${TAEMA_JOB-unset}"'
            )
            _rc, out = bash_script(
                body
                if interactive
                else 'source %s; echo "PC=${#PROMPT_COMMAND[@]}"' % BASH,
                e,
                interactive,
            )
            self.assertIn("PC=0", out, env)

    def test_off_without_a_tty(self):
        r = subprocess.run(
            [
                "bash",
                "--norc",
                "-i",
                "-c",
                "source %s; echo PC=${#PROMPT_COMMAND[@]}" % BASH,
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            env=dict(os.environ, **self.env),
        )
        self.assertIn("PC=0", r.stdout)

    def test_precmd_idle_path_spawns_nothing(self):
        body = (
            self.src()
            + 'PATH=; _taema_precmd; echo "RC=$?"; false; _taema_precmd; echo "RC2=$?"; '
            "true || _taema_precmd; echo END"
        )
        _rc, out = bash_script(body, self.env)
        self.assertIn("RC=0", out)
        self.assertIn(
            "RC2=1", out
        )  # the function returns the status it was entered with
        self.assertNotIn("command not found", out)
        self.assertEqual(self.called(), [])

    def test_precmd_preserves_status(self):
        body = (
            self.src()
            + 'false; _taema_precmd; echo "S=$?"; (exit 7); _taema_precmd; echo "S2=$?"'
        )
        _rc, out = bash_script(body, self.env)
        self.assertIn("S=1", out)
        self.assertIn("S2=7", out)

    def test_pending_file_runs_ask_and_slow_job_runs_done(self):
        os.makedirs(self.dir + "/rt/taema")
        body = (
            self.src()
            + "sleep 2.2; echo X\n"
            + "touch %s/rt/taema/q.$$\n" % self.dir
            + "true\n"
            + "sleep 0.3\n"
            + "echo DONE"
        )
        _rc, out = bash_script(body, self.env)
        time.sleep(0.5)
        calls = self.called()
        self.assertTrue(
            any(
                c.split()[0] == "done"
                and c.split()[2].startswith(c.split()[1] + ".")
                and c.split()[3] == "0"
                for c in calls
            ),
            calls,
        )
        self.assertTrue(any(c.split()[0] == "ask" for c in calls), calls)
        self.assertEqual(
            sum(c.split()[0] == "done" for c in calls), 1, calls
        )  # fast lines send nothing
        self.assertNotRegex(out, r"\[\d+\]")  # no job-control noise

    def test_nested_shell_remembers_the_parent_job(self):
        body = (
            "export TAEMA_JOB=999.7\n"
            + self.src()
            + 'echo "P=$TAEMA_PARENT_JOB J=$TAEMA_JOB"'
        )
        _rc, out = bash_script(body, self.env)
        self.assertIn("P=999.7 J=", out)

    def test_ble_registers_through_blehook(self):
        body = 'blehook() { echo "BLE $*"; }\n' + self.src()
        _rc, out = bash_script(body, self.env)
        self.assertIn("BLE PREEXEC+=_taema_preexec", out)
        self.assertIn("BLE PRECMD+=_taema_precmd", out)

    def test_preexec_word_and_kill_flag(self):
        body = (
            self.src()
            + '_taema_preexec "  pkill -f vite"; echo "W=$_taema_word K=$_taema_kill"; '
            '_taema_preexec "taema kill emu"; echo "K2=$_taema_kill"; _taema_preexec "taema ls"; echo "K3=$_taema_kill"; '
            '_taema_preexec "ls -l"; echo "W4=$_taema_word K4=$_taema_kill"'
        )
        _rc, out = bash_script(body, self.env)
        self.assertIn("W=pkill K=1", out)
        self.assertIn("K2=1", out)
        self.assertIn("K3=\r", out.replace("\r\n", "\r\n"))
        self.assertIn("W4=ls K4=", out)


# ---- 4. daemon: kill_done ----------------------------------------------------------------------------------------


class KillFlow(ProcCase):
    def setUp(self):
        super().setUp()
        self.cg = FakeCg()
        self.cg.__enter__()
        self.addCleanup(self.cg.__exit__)
        self.rt = tmp()
        p = mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": self.rt})
        p.start()
        self.addCleanup(p.stop)
        self.d = daemon.Daemon(
            make_cfg(
                tmp(), seeds={"persist": ["gpg-agent"]}, protected={"comm": ["niri*"]}
            )
        )
        self.fp.add(20, 1, comm="bash", sid=20, tty=34816, born=1000.0)
        self.fp.add(21, 20, comm="npm", pgrp=21)
        self.fp.add(22, 21, comm="vite", pgrp=21)
        self.fp.add(23, 21, comm="esbuild", pgrp=21)
        self.d.lineage.observe(self.fp.table())

    def kill(self, pid=22, word="kill"):
        self.fp.remove(pid)
        r = self.d.handle({"cmd": "kill_done", "shell_pid": 20, "word": word})
        self.d.decide_kill(max(self.d.kills))
        return r

    def test_validation(self):
        h = self.d.handle
        good = {"cmd": "kill_done", "shell_pid": 20, "word": "kill"}
        for patch in (
            {"shell_pid": "20"},
            {"shell_pid": True},
            {"shell_pid": 1},
            {"shell_pid": 999999},
            {"word": "rm"},
            {"word": 3},
            {"word": None},
        ):
            self.assertIn("error", h(dict(good, **patch)), patch)
        self.assertEqual(h(good), {"ok": True})
        self.assertEqual(self.d.deadlines[-1][1], "kill")
        for w in ("pkill", "killall", "taema"):
            self.assertEqual(h(dict(good, word=w)), {"ok": True})

    def test_closed_app_becomes_a_question_and_an_answer(self):
        self.assertEqual(self.kill(), {"ok": True})
        q = self.d.handle({"cmd": "ask", "shell_pid": 20})["question"]
        self.assertEqual(q["kind"], "closed")
        self.assertEqual(q["candidates"][0]["key"], "npm")
        self.assertEqual([l["key"] for l in q["leftovers"]], ["vite"])
        self.assertTrue(os.path.exists(self.rt + "/taema/q.20"))
        a = self.d.handle(
            {"cmd": "answer", "nonce": q["nonce"], "choice": "stop", "owner": "npm"}
        )
        self.assertEqual((a["ok"], a["owner"], a["leftovers"]), (True, "npm", ["vite"]))
        self.assertEqual(self.d.store.pair_decision("npm", "vite")[0], "stop")
        self.assertFalse(os.path.exists(self.rt + "/taema/q.20"))

    def test_the_kill_is_evidence_even_without_a_question(self):
        self.kill()
        p = self.d.store.data["pairs"]["npm\0vite"]
        self.assertEqual(p["kills"], 1)

    def test_rate_limit_and_pair_gap(self):
        self.kill()
        q = self.d.handle({"cmd": "ask", "shell_pid": 20})["question"]
        self.assertIsNotNone(q)  # shown: the pair is stamped
        self.d.handle({"cmd": "answer", "nonce": q["nonce"], "choice": "keep"})
        self.fp.add(22, 21, comm="vite", pgrp=21)
        self.d.lineage.observe(self.fp.table())
        self.kill()
        self.assertEqual(
            self.d.handle({"cmd": "ask", "shell_pid": 20}),
            {"question": None, "reason": "none"},
        )

    def test_daily_limit(self):
        for _ in range(3):
            self.d.store.mark_asked([("x", "y")])
        self.kill()
        self.assertEqual(self.d.pending, {})

    def test_shells_protected_and_persistent_never_asked(self):
        self.fp.add(30, 21, comm="gpg-agent", pgrp=21)
        self.fp.add(31, 21, comm="niri-x", pgrp=21)
        self.fp.add(32, 20, comm="bash", pgrp=32)
        self.d.lineage.observe(self.fp.table())
        for pid in (30, 31, 32):
            self.kill(pid)
        self.assertEqual(self.d.pending, {})

    def test_root_without_a_real_owner_is_not_asked(self):
        self.fp.add(
            40, 20, comm="solo", pgrp=40
        )  # its only recorded parent is the shell
        self.d.lineage.observe(self.fp.table())
        self.kill(40)
        self.assertEqual(self.d.pending, {})

    def test_old_vanishings_are_not_blamed_on_a_later_kill(self):
        self.fp.remove(22)
        self.d.lineage.observe(self.fp.table())
        self.d.after_observe()
        self.d.gone = [(t - 500, r) for t, r in self.d.gone]
        self.d.handle({"cmd": "kill_done", "shell_pid": 20, "word": "kill"})
        self.d.decide_kill(max(self.d.kills))
        self.assertEqual(self.d.pending, {})

    def test_one_vanishing_counts_once(self):
        self.kill()
        self.kill(23)
        self.assertEqual(self.d.store.data["pairs"]["npm\0vite"]["kills"], 1)

    def test_deadline_runs_decide_kill(self):
        self.fp.remove(22)
        self.d.handle({"cmd": "kill_done", "shell_pid": 20, "word": "kill"})
        self.d.deadlines = [(0.0, k, a) for _t, k, a in self.d.deadlines]
        self.d.run_deadlines()
        self.assertEqual(self.d.kills, {})
        self.assertEqual(len(self.d.pending), 1)


if __name__ == "__main__":
    unittest.main()
