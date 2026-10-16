"""Self-learning store: counters and timings per executable, with decay and an audit log.

Learned: whether an exe tends to be shared (default action), how long it takes to stop
gracefully, and how long an idle shared leaf should live. Not learned: protected list,
uid rules, configured cgroup and environment exclusions (see policy.py). No model, no network.
"""
import json
import math
import os
import time

DECAY_DAYS = 7
DECAY_FACTOR = 0.9
COUNTERS = ("seen", "shared_hits", "killed", "sigkill_needed", "respawned", "user_keep", "user_kill")
SEED_SHARE_PRIOR = 3.0


class Store:
    def __init__(self, state_dir, seeds=None, now=time.time):
        self.dir = state_dir
        self.path = os.path.join(state_dir, "knowledge.json")
        self.log_path = os.path.join(state_dir, "decisions.log")
        self.now = now
        self.seeds = seeds or {}
        self.data = {"last_decay": self.now(), "exes": {}}
        try:
            with open(self.path) as f:
                self.data = json.load(f)
        except (OSError, ValueError):
            pass
        self._decay()

    # ---- persistence ----
    def save(self):
        os.makedirs(self.dir, exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.data, f, indent=1, sort_keys=True)
        os.replace(tmp, self.path)

    def log(self, **fields):
        fields["ts"] = round(self.now(), 3)
        os.makedirs(self.dir, exist_ok=True)
        with open(self.log_path, "a") as f:
            f.write(json.dumps(fields, sort_keys=True) + "\n")

    # ---- records ----
    def _fill(self, r):
        for c in COUNTERS:
            r.setdefault(c, 0.0)
        r.setdefault("term_exit_ms", [])
        r.setdefault("idle_grace_scale", 1.0)
        return r

    def rec(self, key):
        """The stored record for key (created on first write). Reads use peek()."""
        r = self._fill(self.data["exes"].setdefault(key, {}))
        r["last_seen"] = self.now()
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
        return self.data["exes"].pop(key, None) is not None

    def _decay(self):
        days = (self.now() - self.data.get("last_decay", self.now())) / 86400.0
        steps = int(days // DECAY_DAYS)
        if steps <= 0:
            return
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
        prior = SEED_SHARE_PRIOR if key in self.seeds.get("share", []) else 0.0
        score = prior + r["user_keep"] + r["shared_hits"] + 0.5 * r["respawned"]
        against = r["user_kill"] + 2
        action = "share" if score > against else "kill"
        why = ("score %.2f (seed %.1f + keep %.1f + shared_hits %.1f + 0.5*respawned %.1f; "
               "respawn is weighted half: supervisors restart things that were not needed) "
               "vs user_kill+2 = %.1f" % (score, prior, r["user_keep"], r["shared_hits"],
                                          r["respawned"], against))
        return action, why

    def graceful_timeout(self, key, default):
        """(seconds, graceful?) from the p95 of observed stop times; skip SIGTERM when it never works."""
        r = self.peek(key)
        if r["killed"] >= 5 and r["sigkill_needed"] / max(r["killed"], 1.0) > 0.8:
            return 0.0, False
        xs = sorted(r["term_exit_ms"])
        if len(xs) < 3:
            return float(default), True
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
