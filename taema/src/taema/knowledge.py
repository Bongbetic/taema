"""Self-learning store: counters and timings per executable, with decay and an audit log.

Learned: whether an exe tends to be shared (default action), how long it takes to stop
gracefully, and how long an idle shared leaf should live. Not learned: protected list,
uid rules, configured cgroup and environment exclusions (see policy.py). No model, no network.
"""
import glob
import json
import math
import os
import time

DECAY_DAYS = 7
DECAY_FACTOR = 0.9
COUNTERS = ("seen", "shared_hits", "killed", "sigkill_needed", "respawned", "user_keep", "user_kill")
SEED_SHARE_PRIOR = 3.0


class Store:
    def __init__(self, state_dir, seeds=None, now=time.time, read_only=False):
        self.dir = state_dir
        self.path = os.path.join(state_dir, "knowledge.json")
        self.log_path = os.path.join(state_dir, "decisions.log")
        self.feedback_path = os.path.join(state_dir, "feedback.jsonl")
        self.now = now
        self.seeds = seeds or {}
        self.read_only = read_only      # CLI: the daemon is the single writer
        self.dirty = False
        self.last_save = 0.0
        self.data = {"last_decay": self.now(), "exes": {}}
        self._load()
        self._decay()

    def _load(self):
        try:
            with open(self.path) as f:
                data = json.load(f)
            if not isinstance(data, dict) or not isinstance(data.get("exes"), dict):
                raise ValueError("bad shape")
        except FileNotFoundError:
            return
        except OSError:
            return
        except ValueError:
            self._keep_corrupt()
            return
        data.setdefault("last_decay", self.now())
        self.data = data

    def _keep_corrupt(self):
        """Rename an unreadable knowledge.json once; never overwrite an earlier .corrupt copy."""
        if self.read_only or glob.glob(self.path + ".corrupt*"):
            return
        dest = "%s.corrupt-%d" % (self.path, int(self.now()))
        try:
            os.replace(self.path, dest)
        except OSError:
            return
        self.log(event="knowledge_corrupt", moved_to=dest)

    # ---- persistence ----
    def _mkdir(self):
        os.makedirs(self.dir, mode=0o700, exist_ok=True)
        try:
            os.chmod(self.dir, 0o700)
        except OSError:
            pass

    def save(self):
        if self.read_only:
            return
        self._mkdir()
        tmp = self.path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            os.fchmod(f.fileno(), 0o600)
            json.dump(self.data, f, indent=1, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)
        self.dirty = False
        self.last_save = self.now()

    def save_if_dirty(self, min_interval=0):
        """Save only when something changed and min_interval seconds passed. True when saved."""
        if not self.dirty or self.now() - self.last_save < min_interval:
            return False
        self.save()
        return True

    def log(self, **fields):
        fields["ts"] = round(self.now(), 3)
        self._mkdir()
        fd = os.open(self.log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a") as f:
            os.fchmod(f.fileno(), 0o600)
            f.write(json.dumps(fields, sort_keys=True) + "\n")

    # ---- feedback ----
    def apply_op(self, op, key):
        """One explicit user answer: keep | forget | kill. Returns False for a bad op or key."""
        if op not in ("keep", "forget", "kill") or not isinstance(key, str) or not key or len(key) > 256:
            return False
        if op == "keep":
            self.bump(key, "user_keep", 3.0)
        elif op == "kill":
            self.bump(key, "user_kill", 1.0)
        else:
            self.forget(key)
        self.log(event=op, exe=key)
        return True

    def apply_feedback(self, path=None):
        """Replay and remove feedback.jsonl (written by the CLI while the daemon was down)."""
        path = path or self.feedback_path
        work = path + ".replay"
        if os.path.exists(path):
            try:
                if os.path.exists(work):    # leftover of a crash: keep it, append the new lines
                    with open(path, "rb") as src, open(work, "ab") as dst:
                        dst.write(src.read())
                    os.unlink(path)
                else:
                    os.replace(path, work)
            except OSError:
                return 0
        n = 0
        try:
            with open(work) as f:
                for line in f:
                    try:
                        m = json.loads(line)
                        if isinstance(m, dict) and self.apply_op(m.get("op"), m.get("key")):
                            n += 1
                    except ValueError:
                        continue
            os.unlink(work)
        except FileNotFoundError:
            return 0
        except OSError:
            pass
        return n

    # ---- records ----
    def _fill(self, r):
        for c in COUNTERS:
            r.setdefault(c, 0.0)
        r.setdefault("term_exit_ms", [])
        r.setdefault("idle_grace_scale", 1.0)
        r.setdefault("stops", 0)
        return r

    def rec(self, key):
        """The stored record for key (created on first write). Reads use peek()."""
        r = self._fill(self.data["exes"].setdefault(key, {}))
        r["last_seen"] = self.now()
        self.dirty = True
        return r

    def peek(self, key):
        """Read-only view: never creates a record."""
        return self._fill(dict(self.data["exes"].get(key, {})))

    def bump(self, key, field, n=1.0):
        self.rec(key)[field] += n

    def add_term_ms(self, key, ms):
        r = self.rec(key)
        r["term_exit_ms"] = (r["term_exit_ms"] + [int(ms)])[-20:]

    def forget(self, key):
        self.dirty = True
        return self.data["exes"].pop(key, None) is not None

    def is_persistent(self, key):
        """True for [seeds] persist keys (tmux, gpg-agent ...): never a GC candidate."""
        return key in self.seeds.get("persist", [])

    def _decay(self):
        days = (self.now() - self.data.get("last_decay", self.now())) / 86400.0
        steps = int(days // DECAY_DAYS)
        if steps <= 0:
            return
        self.dirty = True
        f = DECAY_FACTOR ** steps
        for r in self.data["exes"].values():
            for c in COUNTERS:
                v = r.get(c, 0.0) * f
                r[c] = 0.0 if v < 0.01 else v
        self.data["last_decay"] += steps * DECAY_DAYS * 86400

    # ---- derived defaults ----
    def default_action(self, key):
        """('share'|'kill', explanation). Learned 'share' defers a kill; it never overrides
        hard rules or detected edges."""
        r = self.peek(key)
        prior = SEED_SHARE_PRIOR if (key in self.seeds.get("share", []) or self.is_persistent(key)) else 0.0
        score = prior + r["user_keep"] + r["shared_hits"] + 0.5 * r["respawned"]
        against = r["user_kill"] + 2
        action = "share" if score > against else "kill"
        why = ("score %.2f (seed %.1f + keep %.1f + shared_hits %.1f + 0.5*respawned %.1f; "
               "respawn is weighted half: supervisors restart things that were not needed) "
               "vs user_kill+2 = %.1f" % (score, prior, r["user_keep"], r["shared_hits"],
                                          r["respawned"], against))
        return action, why

    def graceful_timeout(self, key, default):
        """(seconds, True) from the p95 of observed stop times. Never 0 and never skips SIGTERM:
        a key that is always SIGKILLed gets the 2 s floor, except every 10th stop gets the full
        default grace to re-probe (a self-sealed skip could never un-learn)."""
        r = self.peek(key)
        default = max(2.0, float(default))
        if r["killed"] >= 5 and r["sigkill_needed"] / max(r["killed"], 1.0) > 0.8:
            return (default if (r["stops"] + 1) % 10 == 0 else 2.0), True
        xs = sorted(r["term_exit_ms"])
        if len(xs) < 3:
            return default, True
        p95 = xs[min(len(xs) - 1, int(math.ceil(0.95 * len(xs))) - 1)]
        return min(60.0, max(2.0, p95 * 1.5 / 1000.0)), True

    def idle_grace(self, key, base):
        r = self.peek(key)
        return min(7200.0, max(min(120.0, float(base)), base * r["idle_grace_scale"]))

    def gc_outcome(self, key, respawned):
        """Adjust the idle grace after a GC stop: double when it came back, shrink 10% otherwise."""
        r = self.rec(key)
        r["idle_grace_scale"] = r["idle_grace_scale"] * 2 if respawned else max(0.2, r["idle_grace_scale"] * 0.9)

    def explain(self, key):
        r = self.peek(key)
        action, why = self.default_action(key)
        t, graceful = self.graceful_timeout(key, 10)
        return {"key": key, "default_action": action, "why": why,
                "graceful_timeout_s": round(t, 1), "graceful": graceful,
                "counters": {c: round(r[c], 2) for c in COUNTERS},
                "term_exit_ms": r["term_exit_ms"], "idle_grace_scale": round(r["idle_grace_scale"], 2)}
