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
SAVE_INTERVAL = 300         # seconds between routine saves; answers and exit save at once
LOG_MAX = 1 << 20           # decisions.log rotates to decisions.log.1 at 1 MiB
MAX_EXES = 512
STALE_DAYS = 90
SCHEMA = 2

# ---- pair model (Phase 2/4 thresholds; pure, see decide()) ----
DAY = 86400.0
MAX_PAIRS = 256
MAX_PER_OWNER = 32
W_ANSWER = 3.0              # explicit answer weight; never decayed
W_INFERRED = 0.25           # user kill inferred from a vanished pid
W_REGRET = 3.0              # keep evidence added when an auto-stopped app comes back
SILENT_KILLS = 5            # shell-observed kills ...
SILENT_DAYS = 3             # ... on this many distinct days
SILENT_RATIO = 0.9
SILENT_KEEP_FREE_DAYS = 30  # no keep evidence this long
SILENT_MIN_AGE = DAY        # pair first seen more than 24 h ago
BURN_IN_DAYS = 7            # store age ... 
BURN_IN_CLOSES = 20         # ... or closes seen since creation
REGRET_WINDOW = 30 * 60.0
REGRET_SUSPEND = 7 * DAY
ASK_PER_DAY = 3
ASK_PAIR_GAP = 7 * DAY
CHOICES = ("stop", "keep", "standalone")
SEP = "\0"


def decide(p, now, created, closes_total):
    """Pure pair decision from a pair record (or None). Returns (action, confidence, why).
    Explicit answers act at once; silent stop needs the Phase 4 evidence; anything else asks."""
    if not p:
        return "ask", 0.0, "no evidence"
    if p.get("suspended_until", 0) > now:
        return "ask", 0.0, "suspended after regret until day +%d" % int((p["suspended_until"] - now) // DAY + 1)
    ex_s, ex_k = p.get("ex_stop", 0), p.get("ex_keep", 0)
    stop, keep = p.get("stop", 0), p.get("keep", 0)
    if ex_s or ex_k:    # explicit: the last answer holds until contrary evidence outweighs it
        last = p.get("ex_last") or ("stop" if ex_s >= ex_k else "keep")
        if last == "stop" and keep < ex_s:
            return "stop", 1.0, "answered stop (weight %.0f), contrary %.2f" % (ex_s, keep)
        if last == "keep" and stop < ex_k:
            return "keep", 1.0, "answered keep (weight %.0f), contrary %.2f" % (ex_k, stop)
        return "ask", 0.0, "answer overturned by contrary evidence"
    if p.get("launches") and not p.get("kills"):
        return "keep", 0.5, "launcher pattern: survivors are what the job started"
    tot = stop + keep
    ratio = stop / tot if tot else 0.0
    kills, days = p.get("kills", 0), len(p.get("days", ()))
    burn = now - created >= BURN_IN_DAYS * DAY or closes_total >= BURN_IN_CLOSES
    quiet = not keep and now - p.get("last_keep", 0) > SILENT_KEEP_FREE_DAYS * DAY
    old = now - p.get("first_seen", now) > SILENT_MIN_AGE
    if kills >= SILENT_KILLS and days >= SILENT_DAYS and ratio >= SILENT_RATIO and quiet and old and burn:
        return "stop", ratio, "silent: %d kills on %d days, ratio %.2f" % (kills, days, ratio)
    if keep > stop and keep >= 1:
        return "keep", keep / tot, "keep evidence %.2f vs stop %.2f" % (keep, stop)
    return "ask", ratio, "kills %d/%d, days %d/%d, ratio %.2f, quiet %s, old %s, burn-in %s" % (
        kills, SILENT_KILLS, days, SILENT_DAYS, ratio, quiet, old, burn)


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
        self.sigs = {}          # change-detection signatures for log lines (see changed())
        self.data = self._fresh()
        self._load()
        self._decay()

    def _fresh(self):
        return {"version": SCHEMA, "last_decay": self.now(), "created": self.now(), "closes": 0,
                "exes": {}, "pairs": {}, "standalone": {}, "asked": {"day": 0, "n": 0}}

    def _migrate(self, data):
        """v1 (exes only) -> v2: add pairs, standalone, asked; keep every exe record."""
        fresh = self._fresh()
        if data.get("version") != SCHEMA:
            self.dirty = True
        for k in ("pairs", "standalone", "asked"):
            if not isinstance(data.get(k), dict):
                data[k] = fresh[k]
        if not isinstance(data.get("closes"), int) or isinstance(data["closes"], bool):
            data["closes"] = 0
        if not isinstance(data.get("created"), (int, float)) or isinstance(data["created"], bool):
            data["created"] = self.now()
        data["version"] = SCHEMA
        return data

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
        self.data = self._migrate(data)

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
            json.dump(self.data, f, separators=(",", ":"), sort_keys=True)
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
        try:
            if os.stat(self.log_path).st_size >= LOG_MAX:
                os.replace(self.log_path, self.log_path + ".1")
        except OSError:
            pass
        fd = os.open(self.log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a") as f:
            os.fchmod(f.fileno(), 0o600)
            f.write(json.dumps(fields, sort_keys=True) + "\n")

    def changed(self, key, sig):
        """True when sig differs from the last one seen for key (and remembers it)."""
        if self.sigs.get(key) == sig:
            return False
        self.sigs[key] = sig
        return True

    def forget_sigs(self, prefix, keep):
        """Drop remembered signatures under prefix that are not in keep (bounds the table)."""
        for k in [k for k in self.sigs if k.startswith(prefix) and k not in keep]:
            del self.sigs[k]

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

    def decay(self):
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
        for p in self.data["pairs"].values():
            for c in ("stop", "keep"):      # inferred evidence only; ex_* counters never decay
                v = p.get(c, 0.0) * f
                p[c] = 0.0 if v < 0.01 else v
        self.data["last_decay"] += steps * DECAY_DAYS * 86400

    _decay = decay

    @staticmethod
    def _empty(r):
        return (all(r.get(c, 0.0) == 0 for c in COUNTERS) and not r.get("term_exit_ms")
                and not r.get("stops") and r.get("idle_grace_scale", 1.0) == 1.0)

    def enforce_caps(self):
        """Drop all-zero records; above MAX_EXES evict stale (last_seen > 90 days) records first,
        then the lowest decayed weight."""
        exes = self.data["exes"]
        for k in [k for k, r in exes.items() if self._empty(r)]:
            del exes[k]
            self.dirty = True
        pairs = self.data["pairs"]
        for k in [k for k, p in pairs.items() if self._pweight(p) == 0 and not p.get("closes")
                  and not p.get("launches") and not p.get("kills")]:
            del pairs[k]
            self.dirty = True
        if len(pairs) > MAX_PAIRS:
            self._cap_pairs("\0none")
        over = len(exes) - MAX_EXES
        if over > 0:
            cutoff = self.now() - STALE_DAYS * 86400
            order = sorted(exes, key=lambda k: (exes[k].get("last_seen", 0) >= cutoff,
                                                sum(exes[k].get(c, 0.0) for c in COUNTERS),
                                                exes[k].get("last_seen", 0)))
            for k in order[:over]:
                del exes[k]
            self.dirty = True

    # ---- pairs ----
    @staticmethod
    def pkey(owner, leftover):
        return owner + SEP + leftover

    @staticmethod
    def _ok(*keys):
        return all(isinstance(k, str) and 0 < len(k) <= 256 and SEP not in k for k in keys)

    def _pair(self, owner, leftover, create=True):
        k = self.pkey(owner, leftover)
        p = self.data["pairs"].get(k)
        if p is None:
            if not create:
                return None
            p = self.data["pairs"][k] = {"first_seen": self.now()}
            self._cap_pairs(owner, keep=k)
        for f in ("stop", "keep", "ex_stop", "ex_keep", "closes", "kills", "launches", "last_asked",
                  "last_auto_stop", "last_keep", "suspended_until"):
            p.setdefault(f, 0 if f in ("closes", "kills", "launches") else 0.0)
        p.setdefault("days", [])
        p["last_seen"] = self.now()
        self.dirty = True
        return p

    @staticmethod
    def _pweight(p):
        return p.get("stop", 0) + p.get("keep", 0) + p.get("ex_stop", 0) + p.get("ex_keep", 0)

    def _cap_pairs(self, owner, keep=None):
        pairs = self.data["pairs"]
        def drop(cands, over):
            order = sorted((k for k in cands if k != keep),
                           key=lambda k: (self._pweight(pairs[k]), pairs[k].get("last_seen", 0)))
            for k in order[:over]:
                del pairs[k]
        mine = [k for k in pairs if k.startswith(owner + SEP)]
        if len(mine) > MAX_PER_OWNER:
            drop(mine, len(mine) - MAX_PER_OWNER)
        if len(pairs) > MAX_PAIRS:
            drop(list(pairs), len(pairs) - MAX_PAIRS)

    def answer(self, owner, leftover, choice):
        """One explicit answer: weight 3, kept in ex_* counters that decay never touches. A fresh
        answer clears contrary inferred evidence and any regret suspension for the pair."""
        if choice not in CHOICES or not self._ok(owner, leftover):
            return False
        if choice == "standalone":
            e = self.data["standalone"].setdefault(leftover, {"n": 0})
            e["n"] += 1
            e["ts"] = self.now()
            self.dirty = True
            return True
        p = self._pair(owner, leftover)
        p["ex_" + choice] += W_ANSWER
        p["ex_last"] = choice
        p["ex_ts"] = self.now()
        p["keep" if choice == "stop" else "stop"] = 0.0
        p["suspended_until"] = 0.0
        if choice == "keep":
            p["last_keep"] = self.now()
        return True

    def observe_close(self, owner, leftover, day=None, launcher=False):
        """A close was seen with `leftover` still running. Weight 0 evidence: counts only toward
        the burn-in. launcher=True marks a short job whose survivors are what the user launched."""
        if not self._ok(owner, leftover):
            return False
        p = self._pair(owner, leftover)
        p["closes"] += 1
        p["last_close_day"] = int(self.now() // DAY) if day is None else int(day)
        if launcher:
            p["launches"] += 1
        self.data["closes"] += 1
        return True

    def observe_kill_inferred(self, owner, leftover, day=None):
        """The user killed `leftover` in the shell (pid vanished, kill args matched): weight 0.25."""
        if not self._ok(owner, leftover):
            return False
        p = self._pair(owner, leftover)
        p["stop"] += W_INFERRED
        p["kills"] += 1
        d = int(self.now() // DAY) if day is None else int(day)
        if d not in p["days"]:
            p["days"] = (p["days"] + [d])[-32:]
        return True

    def respawn(self, key, same_owner):
        """A stopped key came back. Counts (respawned +1) only under a different owner or when
        self-started; re-running the same command (same_owner) is not a respawn."""
        if same_owner or not isinstance(key, str) or not key:
            return False
        self.bump(key, "respawned", 1.0)
        return True

    def auto_stopped(self, owner, leftover):
        if self._ok(owner, leftover):
            self._pair(owner, leftover)["last_auto_stop"] = self.now()

    def regret(self, owner, leftover):
        """The leftover came back within 30 min of an auto-stop: keep +3, suspended for 7 days
        (the pair asks again). True when it was a regret."""
        p = self._pair(owner, leftover, create=False) if self._ok(owner, leftover) else None
        if not p or not p["last_auto_stop"] or self.now() - p["last_auto_stop"] > REGRET_WINDOW:
            return False
        p["keep"] += W_REGRET
        p["last_keep"] = self.now()
        p["suspended_until"] = self.now() + REGRET_SUSPEND
        p["last_auto_stop"] = 0.0
        self.dirty = True
        return True

    def standalone(self, key):
        return key in self.data["standalone"]

    def owners_of(self, leftover, limit=3):
        """Owners that historically had this leftover key, strongest first."""
        suffix = SEP + leftover
        rows = [(self._pweight(p) + p.get("closes", 0) * 0.01, k[:-len(suffix)])
                for k, p in self.data["pairs"].items() if k.endswith(suffix)]
        return [o for _w, o in sorted(rows, reverse=True)[:limit]]

    def pair_decision(self, owner, leftover):
        """(action, confidence, why); action in ask|stop|keep|standalone."""
        if self.standalone(leftover):
            return "standalone", 1.0, "answered: standalone app"
        p = self.data["pairs"].get(self.pkey(owner, leftover))
        d = self.data
        return decide(p, self.now(), d["created"], d["closes"])

    def pair_explicit(self, owner, leftover):
        """True when the pair decision is "stop" because the user answered it (SIGKILL is allowed
        only then)."""
        action, _conf, why = self.pair_decision(owner, leftover)
        return action == "stop" and why.startswith("answered stop")

    def can_ask(self, pair, now=None):
        """pair = (owner, leftover). At most 3 questions per day, each pair once per 7 days."""
        now = self.now() if now is None else now
        a = self.data["asked"]
        if a.get("day") == int(now // DAY) and a.get("n", 0) >= ASK_PER_DAY:
            return False
        p = self.data["pairs"].get(self.pkey(*pair))
        return not (p and p.get("last_asked") and now - p["last_asked"] < ASK_PAIR_GAP)

    def mark_asked(self, pairs, now=None):
        """Record one question covering `pairs` [(owner, leftover)]: one daily count, per-pair stamp."""
        now = self.now() if now is None else now
        a = self.data["asked"]
        day = int(now // DAY)
        if a.get("day") != day:
            a["day"], a["n"] = day, 0
        a["n"] += 1
        for o, l in pairs:
            if self._ok(o, l):
                self._pair(o, l)["last_asked"] = now
        self.dirty = True

    def pairs_summary(self, limit=50):
        out = []
        for k, p in self.data["pairs"].items():
            owner, _, leftover = k.partition(SEP)
            action, conf, why = decide(p, self.now(), self.data["created"], self.data["closes"])
            out.append({"owner": owner, "leftover": leftover, "action": action, "confidence": round(conf, 2),
                        "stop": round(p.get("stop", 0) + p.get("ex_stop", 0), 2),
                        "keep": round(p.get("keep", 0) + p.get("ex_keep", 0), 2),
                        "closes": p.get("closes", 0), "kills": p.get("kills", 0), "why": why})
        out.sort(key=lambda r: (-(r["stop"] + r["keep"]), -r["closes"], r["owner"], r["leftover"]))
        return out[:limit]

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
        pairs = [x for x in self.pairs_summary(256) if x["leftover"] == key or x["owner"] == key][:20]
        return {"key": key, "standalone": self.standalone(key), "pairs": pairs, "default_action": action, "why": why,
                "graceful_timeout_s": round(t, 1), "graceful": graceful,
                "counters": {c: round(r[c], 2) for c in COUNTERS},
                "term_exit_ms": r["term_exit_ms"], "idle_grace_scale": round(r["idle_grace_scale"], 2)}
