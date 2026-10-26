"""Notification policy: what may interrupt the user, and how it reads.

Pure decisions over injected clocks: quiet hours, quiet profiles, mutes,
close batching, hourly caps, the 200 MB floor with its signature-repeat
exception, and once-a-day error notices. Rendering is plain text unless
the server advertised markup support.
"""

import time

from .core.memory import size_bytes

SIG_REPEAT_OVERRIDE = 3
DAY = 86400


def format_mb(value):
    """Format a byte count the way toasts read: 812 MB, 1.5 GB."""
    mb = max(0, value) / (1024 * 1024)
    if mb >= 1024:
        return "%.1f GB" % (mb / 1024)
    return "%d MB" % int(mb)


def _parse_quiet_hours(text):
    """Parse 22:00-08:00 into minute pairs; None when malformed."""
    try:
        start, end = text.split("-", 1)

        def minutes(part):
            hour, minute = part.split(":", 1)
            total = int(hour) * 60 + int(minute)
            if not 0 <= total < 24 * 60:
                raise ValueError
            return total

        return minutes(start.strip()), minutes(end.strip())
    except (ValueError, AttributeError):
        return None


def _bold(text, markup_ok):
    return "<b>%s</b>" % text if markup_ok else text


def render_close_batch(app, closes, freed_bytes, markup_ok):
    """One flushed batch of closes for an app."""
    summary = "%d close%s for %s" % (
        closes,
        "" if closes == 1 else "s",
        _bold(app, markup_ok),
    )
    return summary, "Freed %s" % format_mb(freed_bytes), []


def render_undo(kind, target, freed_bytes, markup_ok):
    """Undo toast after an automatic action; always offers Undo."""
    if kind == "freeze":
        summary = "Frozen %s" % _bold(target, markup_ok)
    elif freed_bytes:
        summary = "Freed %s" % format_mb(freed_bytes)
    else:
        summary = "Automatic %s on %s" % (kind, _bold(target, markup_ok))
    return summary, "", [("undo", "Undo")]


def render_countdown(app, seconds, markup_ok):
    """Learned stop awaiting objection: Keep or Stop now."""
    return (
        "Stop %s?" % _bold(app, markup_ok),
        "Learned stop in %d seconds" % seconds,
        [("keep", "Keep"), ("stop", "Stop now")],
    )


def render_guard(detail, markup_ok):
    """One guard notice; informational, no actions."""
    return "Memory pressure", detail, []


def render_error(kind, detail, markup_ok):
    """One error notice; informational, no actions."""
    return "taema: %s" % kind, detail, []


def render_digest(counts, markup_ok):
    """The optional daily digest: one line of counts."""
    body = "%s stops, %s frozen, %s reclaimed, %s open reviews" % (
        _bold(str(counts.get("stops_24h", 0)), markup_ok),
        _bold(str(counts.get("frozen", 0)), markup_ok),
        _bold(format_mb(counts.get("guard_bytes", 0)), markup_ok),
        _bold(str(counts.get("reviews", 0)), markup_ok),
    )
    return "taema digest", body, []


class NotifyPolicy:
    """Batching, caps, quiet, and dedup state for one agent."""

    def __init__(self, cfg, clock=None, mutes=()):
        self.cfg = cfg
        self.clock = clock or time.time
        self.mutes = set(mutes)
        self._batches = {}
        self._sent = []
        self._dropped = 0
        self._errors = {}

    def set_mutes(self, mutes):
        self.mutes = set(mutes)

    def muted(self, app):
        return app in self.mutes

    def quiet_now(self, now, profile, local=None):
        """Whether notifications stay silent: off, quiet hours, or profile."""
        if not self.cfg.get("enabled", True):
            return True
        if (profile or "default") in ("game", "quiet"):
            return True
        span = _parse_quiet_hours(self.cfg.get("quiet_hours", ""))
        if span is None:
            return False
        start, end = span
        local = local if local is not None else time.localtime(now)
        current = local[3] * 60 + local[4]
        if start <= end:
            return start <= current < end
        return current >= start or current < end

    def within_cap(self, now):
        """Whether another notification fits under the hourly cap."""
        hour_ago = now - 3600
        self._sent = [ts for ts in self._sent if ts > hour_ago]
        return len(self._sent) < int(self.cfg.get("max_per_hour", 6))

    def note_sent(self, now):
        self._sent.append(now)

    def dropped(self):
        return self._dropped

    def close_event(self, app, mem_bytes, sig_repeats, now):
        """Fold one close into its app batch, or skip it under the floor."""
        try:
            floor = size_bytes(self.cfg.get("min_mem", "200M"))
        except ValueError:
            floor = 0
        if mem_bytes < floor and sig_repeats < SIG_REPEAT_OVERRIDE:
            return ("skip", "under-200M")
        window = int(self.cfg.get("batch_seconds", 60))
        batch = self._batches.get(app)
        if batch is None or now - batch["opened"] >= window:
            batch = {"opened": now, "closes": 0, "freed": 0}
            self._batches[app] = batch
        batch["closes"] += 1
        batch["freed"] += mem_bytes
        return ("batch", app)

    def flush(self, now):
        """Batches whose window has closed; capped ones are dropped."""
        window = int(self.cfg.get("batch_seconds", 60))
        due = []
        for app, batch in list(self._batches.items()):
            if now - batch["opened"] < window:
                continue
            del self._batches[app]
            if not self.within_cap(now):
                self._dropped += 1
                continue
            due.append({"app": app, "closes": batch["closes"], "freed": batch["freed"]})
        return due

    def error_allowed(self, kind, now):
        """Error notices go out at most once per day per kind."""
        return self._errors.get(kind, -DAY - 1) <= now - DAY

    def note_error(self, kind, now):
        self._errors[kind] = now


class JobHandler:
    """Turn daemon notification jobs into backend sends.

    The agent polls jobs, the handler applies policy (quiet, mutes,
    batching, caps, dedup), renders plain or markup text, waits on
    actionable toasts, and reports outcomes through `report`. Backend
    failures are swallowed: the desktop is best-effort, the CLI keeps
    working.
    """

    def __init__(self, cfg, backend, policy=None, clock=None, localtime=None):
        self.cfg = cfg.get("notify", {}) if isinstance(cfg, dict) else {}
        self.backend = backend
        self.policy = policy or NotifyPolicy(self.cfg, clock=clock)
        self.clock = clock or time.time
        self.localtime = localtime or time.localtime

    def _send(self, summary, body, actions, expire_ms=-1):
        from .notify import supports_markup

        try:
            markup_ok = supports_markup(self.backend.server_capabilities())
        except Exception:
            markup_ok = False
        try:
            return self.backend.send(
                summary,
                body,
                actions=actions,
                markup=markup_ok,
                expire_ms=expire_ms,
            )
        except Exception:
            return None

    def _muted_apps(self, job):
        apps = []
        if job.get("app"):
            apps.append(job["app"])
        apps.extend(job.get("apps", []) or [])
        return apps

    def _muted(self, job):
        apps = self._muted_apps(job)
        return bool(apps) and all(self.policy.muted(app) for app in apps)

    def handle(self, jobs, profile, mutes, report):
        """Apply policy to fresh jobs, flush due batches; quiet drops all."""
        now = self.clock()
        self.policy.set_mutes(mutes)
        if self.policy.quiet_now(now, profile, self.localtime(now)):
            return
        for job in jobs:
            handler = getattr(self, "_job_" + str(job.get("kind", "")), None)
            if handler is not None:
                try:
                    handler(job, now, report)
                except Exception:
                    continue
        for batch in self.policy.flush(now):
            summary, body, actions = render_close_batch(
                batch["app"], batch["closes"], batch["freed"], self._markup()
            )
            if self._send(summary, body, actions):
                self.policy.note_sent(now)

    def _markup(self):
        from .notify import supports_markup

        try:
            return supports_markup(self.backend.server_capabilities())
        except Exception:
            return False

    def _job_close(self, job, now, report):
        if self._muted(job):
            return
        self.policy.close_event(
            job.get("app", "?"),
            job.get("mem_bytes", 0),
            job.get("sig_repeats", 1),
            now,
        )

    def _job_undo(self, job, now, report):
        from .notify import NotifyError

        if self._muted(job):
            return
        apps = job.get("apps", []) or []
        target = apps[0] if apps else job.get("scope", "?")
        summary, body, actions = render_undo(
            job.get("action", "stop"), target, job.get("freed_bytes", 0), self._markup()
        )
        if "actions" not in self.backend.capabilities():
            self._send(summary, body, [])
            return
        try:
            receipt = self.backend.send(
                summary, body, actions=actions, markup=self._markup(), wait=True
            )
        except NotifyError:
            return
        if receipt is None:
            return
        seconds = int(self.cfg.get("undo_toast_seconds", 30))
        try:
            outcome = self.backend.wait_for_action(receipt, seconds)
        except NotifyError:
            return
        if outcome == ("action", "undo"):
            report({"kind": "undo", "decision_id": job.get("decision_id")})

    def _job_countdown(self, job, now, report):
        from .notify import NotifyError

        if self._muted(job):
            return
        if "actions" not in self.backend.capabilities():
            return
        remaining = int(job.get("seconds", 30) - (now - job.get("created", now)))
        if remaining <= 0:
            return
        summary, body, actions = render_countdown(
            job.get("app", "?"), remaining, self._markup()
        )
        try:
            receipt = self.backend.send(
                summary, body, actions=actions, markup=self._markup(), wait=True
            )
        except NotifyError:
            return
        if receipt is None:
            return
        try:
            outcome = self.backend.wait_for_action(receipt, remaining)
        except NotifyError:
            return
        if outcome in (("action", "keep"), ("action", "stop")):
            report(
                {
                    "kind": "countdown",
                    "nonce": job.get("nonce"),
                    "choice": outcome[1],
                }
            )

    def _job_guard(self, job, now, report):
        summary, body, actions = render_guard(
            "reclaimed %s via %s"
            % (format_mb(job.get("bytes_freed", 0)), job.get("trigger", "?")),
            self._markup(),
        )
        self._send(summary, body, actions)

    def _job_error(self, job, now, report):
        kind = job.get("error_kind", "?")
        if not self.policy.error_allowed(kind, now):
            return
        summary, body, actions = render_error(
            kind, job.get("detail", ""), self._markup()
        )
        if self._send(summary, body, actions):
            self.policy.note_error(kind, now)

    def _job_digest(self, job, now, report):
        summary, body, actions = render_digest(job, self._markup())
        self._send(summary, body, actions)
