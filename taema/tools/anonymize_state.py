#!/usr/bin/env python3
"""Build a decision-preserving fixture from a read-only copy of a user's 0.2 state."""

from collections import deque
import json
import math
import os
from pathlib import Path
import re
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from taema.config import policy  # noqa: E402

DAY = 86400
EVENT_LIMIT = 10_000
SAFE_EVENTS = re.compile(r"^[A-Za-z0-9_.:-]{1,80}$")


class Anonymizer:
    """Replace app/scope/process identifiers and retain only decision-relevant values."""

    def __init__(self, deny=()):
        self.apps = {}
        self.scopes = {}
        self.pids = {}
        self.ids = {}
        self.deny = tuple(deny)

    @staticmethod
    def _token(mapping, value, prefix):
        if not isinstance(value, str) or not value:
            return value
        if value not in mapping:
            mapping[value] = "%s-%04d" % (prefix, len(mapping) + 1)
        return mapping[value]

    def app(self, value):
        return self._token(self.apps, value, "app")

    def scope(self, value):
        if not isinstance(value, str) or not value:
            return value
        if value.startswith("leftover/"):
            return "leftover/" + self.app(value[len("leftover/") :])
        return self._token(self.scopes, value, "scope")

    def pid(self, value):
        if isinstance(value, bool) or not isinstance(value, int):
            return None
        if value not in self.pids:
            self.pids[value] = len(self.pids) + 10_000
        return self.pids[value]

    def identifier(self, value, prefix):
        if value is not None and not isinstance(value, str):
            value = str(value)
        return self._token(self.ids.setdefault(prefix, {}), value, prefix)

    def _collect_state(self, state):
        values = set()
        for section in ("exes", "standalone", "noise"):
            records = state.get(section, {})
            if isinstance(records, dict):
                values.update(key for key in records if isinstance(key, str))
        pairs = state.get("pairs", {})
        if isinstance(pairs, dict):
            for key in pairs:
                if isinstance(key, str) and "\0" in key:
                    owner, leftover = key.split("\0", 1)
                    values.update((owner, leftover))
        for review in (
            state.get("reviews", []) if isinstance(state.get("reviews"), list) else []
        ):
            if not isinstance(review, dict):
                continue
            if isinstance(review.get("owner"), str):
                values.add(review["owner"])
            survivors = review.get("survivors", [])
            if isinstance(survivors, list):
                values.update(item for item in survivors if isinstance(item, str))
        for action in (
            state.get("auto_actions", [])
            if isinstance(state.get("auto_actions"), list)
            else []
        ):
            if not isinstance(action, dict):
                continue
            values.update(
                item for item in action.get("apps", []) if isinstance(item, str)
            )
            for pair in action.get("pairs", []):
                if isinstance(pair, (list, tuple)):
                    values.update(item for item in pair[:2] if isinstance(item, str))
        for veto in (
            state.get("vetoes", []) if isinstance(state.get("vetoes"), list) else []
        ):
            if isinstance(veto, dict) and veto.get("kind") == "app":
                if isinstance(veto.get("value"), str):
                    values.add(veto["value"])
        for key in sorted(values):
            self.app(key)

    @staticmethod
    def _number(value, default=None):
        if (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and math.isfinite(value)
        ):
            return value
        return default

    @staticmethod
    def _integer(value, default=0):
        if isinstance(value, int) and not isinstance(value, bool):
            return value
        return default

    def state(self, source):
        source = source if isinstance(source, dict) else {}
        self._collect_state(source)
        result = {
            key: source.get(key)
            for key in ("version", "last_decay", "created", "closes", "review_seq")
        }
        result["version"] = 2

        result["exes"] = {}
        exes = source.get("exes", {})
        if isinstance(exes, dict):
            allowed = (
                "seen",
                "shared_hits",
                "killed",
                "sigkill_needed",
                "respawned",
                "user_keep",
                "user_kill",
                "term_exit_ms",
                "idle_grace_scale",
                "stops",
                "last_seen",
            )
            for key, record in sorted(exes.items()):
                if isinstance(key, str) and isinstance(record, dict):
                    result["exes"][self.app(key)] = {
                        name: record[name]
                        for name in allowed
                        if name in record and self._safe_value(record[name])
                    }

        result["pairs"] = {}
        pairs = source.get("pairs", {})
        if isinstance(pairs, dict):
            allowed = (
                "stop",
                "keep",
                "ex_stop",
                "ex_keep",
                "ex_last",
                "ex_ts",
                "closes",
                "kills",
                "launches",
                "stop_ok",
                "respawn",
                "days",
                "probation",
                "first_seen",
                "last_seen",
                "last_asked",
                "last_auto_stop",
                "last_keep",
                "suspended_until",
            )
            for key, record in sorted(pairs.items()):
                if (
                    not isinstance(key, str)
                    or "\0" not in key
                    or not isinstance(record, dict)
                ):
                    continue
                owner, leftover = key.split("\0", 1)
                pair = {
                    name: record[name]
                    for name in allowed
                    if name in record and self._safe_value(record[name])
                }
                invalid = record.get("source") == "legacy-invalid" or bool(
                    policy.bad_owner(owner, self.deny)
                )
                pair["source"] = "legacy-invalid" if invalid else "legacy"
                result["pairs"][self.app(owner) + "\0" + self.app(leftover)] = pair

        standalone = source.get("standalone", {})
        result["standalone"] = (
            {
                self.app(key): self._safe_record(value, ("n", "ts"))
                for key, value in sorted(standalone.items())
                if isinstance(standalone, dict) and isinstance(key, str)
            }
            if isinstance(standalone, dict)
            else {}
        )
        noise = source.get("noise", {})
        result["noise"] = (
            {
                self.app(key): self._integer(value)
                for key, value in sorted(noise.items())
                if isinstance(noise, dict) and isinstance(key, str)
            }
            if isinstance(noise, dict)
            else {}
        )
        asked = source.get("asked", {})
        result["asked"] = (
            {
                "day": self._integer(asked.get("day")),
                "n": self._integer(asked.get("n")),
            }
            if isinstance(asked, dict)
            else {"day": 0, "n": 0}
        )

        result["reviews"] = []
        reviews = source.get("reviews", [])
        if isinstance(reviews, list):
            for review in reviews:
                if not isinstance(review, dict):
                    continue
                sanitized = {
                    "id": len(result["reviews"]) + 1,
                    "kind": review.get("kind")
                    if review.get("kind") in ("close", "scope", "legacy-invalid")
                    else "close",
                    "created": self._number(review.get("created")),
                    "expires": self._number(review.get("expires")),
                    "shown": self._number(review.get("shown")),
                    "state": review.get("state")
                    if review.get("state")
                    in ("open", "answered", "expired", "dismissed")
                    else "open",
                }
                if isinstance(review.get("owner"), str):
                    sanitized["owner"] = self.app(review["owner"])
                survivors = review.get("survivors", [])
                if isinstance(survivors, list):
                    sanitized["survivors"] = [
                        self.app(value) for value in survivors if isinstance(value, str)
                    ]
                if isinstance(review.get("scope"), str):
                    sanitized["scope"] = self.scope(review["scope"])
                if isinstance(review.get("pids"), list):
                    sanitized["pids"] = [
                        token
                        for value in review["pids"]
                        if (token := self.pid(value)) is not None
                    ]
                if review.get("answer") in ("stop", "keep"):
                    sanitized["answer"] = review["answer"]
                if sanitized["kind"] == "legacy-invalid":
                    sanitized["reason"] = "legacy owner identity needs confirmation"
                elif sanitized["kind"] == "scope":
                    sanitized["reason"] = "anonymized"
                result["reviews"].append(sanitized)

        result["review_seq"] = len(result["reviews"])
        result["vetoes"] = []
        vetoes = source.get("vetoes", [])
        if isinstance(vetoes, list):
            for index, veto in enumerate(vetoes):
                if not isinstance(veto, dict):
                    continue
                kind = (
                    veto.get("kind")
                    if veto.get("kind") in ("app", "scope", "pid")
                    else "app"
                )
                value = veto.get("value")
                if kind == "app":
                    value = self.app(value)
                elif kind == "scope":
                    value = self.scope(value)
                else:
                    try:
                        pid_value = int(value)
                    except (TypeError, ValueError):
                        continue
                    if pid_value <= 1:
                        continue
                    token = self.pid(pid_value)
                    if token is None:
                        continue
                    value = str(token)
                result["vetoes"].append(
                    {
                        "id": self.identifier(veto.get("id", str(index)), "veto"),
                        "kind": kind,
                        "value": value,
                        "start": 1 if kind == "pid" else None,
                        "created": self._number(veto.get("created")),
                        "expires": self._number(veto.get("expires")),
                        "reason": "anonymized",
                        "source": "legacy",
                    }
                )

        result["auto_actions"] = []
        actions = source.get("auto_actions", [])
        if isinstance(actions, list):
            for index, action in enumerate(actions):
                if not isinstance(action, dict):
                    continue
                sanitized = {
                    "id": self.identifier(action.get("id", str(index)), "action"),
                    "ts": self._number(action.get("ts")),
                    "why": "anonymized",
                    "pairs": [],
                    "apps": [],
                }
                if isinstance(action.get("scope"), str):
                    sanitized["scope"] = self.scope(action["scope"])
                for pair in action.get("pairs", []):
                    if isinstance(pair, (list, tuple)) and len(pair) >= 2:
                        sanitized["pairs"].append(
                            [self.app(pair[0]), self.app(pair[1])]
                        )
                if isinstance(action.get("apps"), list):
                    sanitized["apps"] = [
                        self.app(value)
                        for value in action["apps"]
                        if isinstance(value, str)
                    ]
                result["auto_actions"].append(sanitized)

        result["feedback_ids"] = (
            [
                self.identifier(value, "feedback")
                for value in source.get("feedback_ids", [])
                if isinstance(source.get("feedback_ids"), list)
            ]
            if isinstance(source.get("feedback_ids"), list)
            else []
        )
        expiries = source.get("leftover_expiries", {})
        result["leftover_expiries"] = (
            {
                self.scope(key): self._number(value, 0)
                for key, value in sorted(expiries.items())
                if isinstance(expiries, dict) and isinstance(key, str)
            }
            if isinstance(expiries, dict)
            else {}
        )
        return result

    def _safe_record(self, value, allowed):
        if not isinstance(value, dict):
            return {"n": self._integer(value)}
        return {
            key: value[key]
            for key in allowed
            if key in value and self._safe_value(value[key])
        }

    @classmethod
    def _safe_value(cls, value):
        if isinstance(value, (str, int, float, bool)) or value is None:
            return not isinstance(value, float) or math.isfinite(value)
        if isinstance(value, list):
            return all(cls._safe_value(item) for item in value)
        if isinstance(value, dict):
            return all(
                isinstance(key, str) and cls._safe_value(item)
                for key, item in value.items()
            )
        return False

    def events(self, state_dir):
        lines = deque(maxlen=EVENT_LIMIT)
        for name in ("decisions.log.1", "decisions.log"):
            try:
                with open(
                    Path(state_dir) / name, encoding="utf-8", errors="replace"
                ) as source:
                    lines.extend(source)
            except OSError:
                continue
        events = []
        for line in lines:
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if not isinstance(record, dict):
                continue
            event = record.get("event", "legacy")
            if not isinstance(event, str) or not SAFE_EVENTS.fullmatch(event):
                event = "legacy"
            item = {"event": event, "ts": self._number(record.get("ts"))}
            for field in ("mode", "action", "authority", "outcome"):
                value = record.get(field)
                if isinstance(value, str) and SAFE_EVENTS.fullmatch(value):
                    item[field] = value
            if isinstance(record.get("stage"), int) and not isinstance(
                record.get("stage"), bool
            ):
                item["stage"] = record["stage"]
            if isinstance(record.get("freed"), int) and not isinstance(
                record.get("freed"), bool
            ):
                item["freed"] = record["freed"]
            events.append(item)
        return events


def _write_private_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".anonymized-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            os.fchmod(output.fileno(), 0o600)
            json.dump(value, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _write_private_jsonl(path, values):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".anonymized-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            os.fchmod(output.fileno(), 0o600)
            for value in values:
                output.write(json.dumps(value, separators=(",", ":"), sort_keys=True))
                output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def main(argv=None):
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    default_state = (
        Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state")) / "taema"
    )
    parser.add_argument(
        "--state-dir",
        type=Path,
        default=default_state,
        help="read-only state directory",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=ROOT / "tests/fixtures/legacy-v2",
        help="fixture directory to write",
    )
    args = parser.parse_args(argv)
    state_dir = args.state_dir.expanduser().resolve()
    output_dir = args.output_dir.expanduser().resolve()
    if output_dir == state_dir or state_dir in output_dir.parents:
        parser.error("output directory must be outside the source state directory")
    try:
        with open(state_dir / "knowledge.json", encoding="utf-8") as source:
            legacy = json.load(source)
        config = policy.load_config()
        anonymizer = Anonymizer(policy.owner_deny(config))
        safe_state = anonymizer.state(legacy)
        safe_events = anonymizer.events(state_dir)
        _write_private_json(output_dir / "knowledge.json", safe_state)
        _write_private_jsonl(output_dir / "decisions.log", safe_events)
    except (OSError, UnicodeError, ValueError) as error:
        parser.error("could not anonymize the read-only state: %s" % error)
    print(
        "wrote anonymized fixture (%d pairs, %d audit events)"
        % (len(safe_state.get("pairs", {})), len(safe_events))
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
