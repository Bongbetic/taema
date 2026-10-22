"""Versioned envelopes and strict request validation for the Unix socket API."""

import math

MAX_REQUEST_ID = (1 << 53) - 1

_COMMANDS = {
    "status": ({}, ()),
    "doctor": ({}, ()),
    "memory_budget": ({}, ()),
    "reload": ({"reason": "string"}, ()),
    "review": ({}, ()),
    "subscribe": ({"topics": "array", "since_seq": "integer"}, ("topics", "since_seq")),
    "register": ({"scope": "string", "owner": "integer"}, ("scope", "owner")),
    "attach": ({"scope": "string", "pids": "array"}, ("scope", "pids")),
    "job_done": (
        {
            "shell_pid": "integer",
            "tag": "string",
            "status": "integer",
            "word": "string",
        },
        ("shell_pid", "tag", "status", "word"),
    ),
    "kill_done": ({"shell_pid": "integer", "word": "string"}, ("shell_pid", "word")),
    "ask": ({"shell_pid": "integer"}, ("shell_pid",)),
    "answer": (
        {"nonce": "string", "choice": "string", "owner": "string"},
        ("nonce", "choice"),
    ),
    "gc": ({"dry_run": "boolean", "memory": "boolean"}, ()),
    "reclaim": (
        {"scope": "string", "force_veto": "boolean", "dry_run": "boolean"},
        ("scope",),
    ),
    "freeze": ({"scope": "string"}, ("scope",)),
    "thaw": ({"scope": "string", "all": "boolean"}, ()),
    "feedback": ({}, ()),
}


class ProtocolError(ValueError):
    """A request rejected before command dispatch, with a stable wire error code."""

    def __init__(self, code, message, hint):
        super().__init__(message)
        self.code = code
        self.hint = hint


def is_v2(message):
    return isinstance(message, dict) and message.get("v") == 2


def is_legacy(message):
    """Recognize unversioned v1, including the old feedback operation's own v1 marker."""
    return isinstance(message, dict) and (
        "v" not in message
        or (
            message.get("v") == 1
            and message.get("cmd") == "feedback"
            and isinstance(message.get("id"), str)
        )
    )


def request_id(message):
    value = message.get("id") if isinstance(message, dict) else None
    if (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= MAX_REQUEST_ID
    ):
        return value
    return 0


def _fail(message, hint="Check the command and its arguments."):
    raise ProtocolError("invalid_request", message, hint)


def _is_type(value, kind):
    if kind == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if kind == "array":
        return isinstance(value, list)
    if kind == "boolean":
        return isinstance(value, bool)
    if kind == "string":
        return isinstance(value, str)
    return False


def _finite_number(value):
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def _validate_target(target, allow_pid_wildcard=False):
    if not isinstance(target, dict):
        _fail("feedback target must be an object")
    if set(target) - {"kind", "value", "start", "owner", "leftover"}:
        _fail("feedback target contains an unknown field")
    if not {"kind", "value"} <= set(target):
        _fail("feedback target requires kind and value")
    if target["kind"] not in (
        "pid",
        "scope",
        "pair",
        "signature",
        "app",
        "owner",
        "unit",
        "cgroup",
        "path",
    ):
        _fail("feedback target kind is invalid")
    value = target["value"]
    if not isinstance(value, (str, int)) or isinstance(value, bool):
        _fail("feedback target value must be a string or integer")
    if not str(value) or len(str(value)) > 256:
        _fail("feedback target value is out of range")
    start = target.get("start")
    if target["kind"] == "pid":
        try:
            pid = int(value)
        except (TypeError, ValueError):
            _fail("pid veto requires a positive pid and start time")
        if pid <= 1 or (
            not (allow_pid_wildcard and start is None)
            and (not _is_type(start, "integer") or start <= 0)
        ):
            _fail("pid veto requires a positive pid and start time")
    elif start is not None:
        _fail("only a pid veto may have a start time")
    if target["kind"] == "pair":
        owner, leftover = target.get("owner"), target.get("leftover")
        if (
            not _is_type(owner, "string")
            or not owner
            or len(owner) > 256
            or not _is_type(leftover, "string")
            or not leftover
            or len(leftover) > 256
            or str(value) != leftover
        ):
            _fail("pair veto requires owner and leftover keys")
    elif "owner" in target or "leftover" in target:
        _fail("only a pair veto may have owner and leftover keys")


def _validate_feedback(args):
    legacy_fields = {"op", "key"}
    versioned_fields = {
        "v",
        "id",
        "op",
        "key",
        "target",
        "action_id",
        "restore",
        "reason",
        "trigger",
        "owner",
        "review_id",
        "leftovers",
        "choice",
        "all",
        "app",
        "muted",
        "scope",
        "held",
        "until",
        "reason",
        "expires",
    }
    if "v" not in args:
        if set(args) != legacy_fields:
            _fail("legacy feedback requires only op and key")
        if args["op"] not in ("keep", "forget", "kill"):
            _fail("feedback operation is invalid")
        if not _is_type(args["key"], "string") or not args["key"]:
            _fail("feedback key must be a non-empty string")
        return
    if set(args) - versioned_fields:
        _fail("feedback contains an unknown field")
    version = args.get("v")
    if not _is_type(version, "integer") or version not in (1, 2):
        _fail("versioned feedback requires a supported version and string id")
    if (
        not _is_type(args.get("id"), "string")
        or not args["id"]
        or len(args["id"]) > 128
    ):
        _fail("versioned feedback requires a supported version and string id")
    op = args.get("op")
    common = {"v", "id", "op"}
    operation_fields = (
        {
            "veto": common | {"target", "reason"},
            "unveto": common | {"target"},
            "undo": common | {"action_id"},
            "vetoed": common | {"target", "trigger"},
        }
        if version == 1
        else {
            "keep": common | {"key"},
            "forget": common | {"key", "all"},
            "kill": common | {"key"},
            "veto": common | {"target", "reason", "expires"},
            "unveto": common | {"target"},
            "undo": common | {"action_id", "restore"},
            "answer": common | {"owner", "leftovers", "choice"},
            "teach": common | {"owner", "leftovers", "choice"},
            "review_answer": common | {"review_id", "choice", "owner"},
            "review_shown": common | {"review_id", "owner"},
            "mute": common | {"app", "muted"},
            "hold": common | {"scope", "held", "reason"},
            "snooze": common | {"until", "reason"},
        }
    )
    if op not in operation_fields:
        _fail("feedback operation is invalid")
    if set(args) - operation_fields[op]:
        _fail("feedback contains an unknown field")
    if op in ("veto", "unveto", "vetoed"):
        if "target" not in args:
            _fail("feedback target is required")
        _validate_target(args["target"], allow_pid_wildcard=op == "unveto")
    if op == "undo" and (
        not _is_type(args.get("action_id"), "string") or not args["action_id"]
    ):
        _fail("undo requires an action id")
    if op == "undo" and "restore" in args and not _is_type(args["restore"], "boolean"):
        _fail("undo restore must be a boolean")
    for field in ("action_id", "reason", "trigger"):
        if field in args and not _is_type(args[field], "string"):
            _fail("feedback %s must be a string" % field)
    if op == "veto" and "reason" in args and len(args["reason"]) > 256:
        _fail("feedback reason must be at most 256 characters")
    if op == "veto" and "expires" in args and not _finite_number(args["expires"]):
        _fail("feedback veto expiry must be a finite timestamp")
    if op in ("keep", "forget", "kill"):
        if not _is_type(args.get("key"), "string") or not args["key"]:
            _fail("feedback key must be a non-empty string")
    if op == "forget" and "all" in args and not _is_type(args["all"], "boolean"):
        _fail("forget all must be a boolean")
    if op in ("answer", "teach"):
        owner, leftovers, choice = (
            args.get("owner"),
            args.get("leftovers"),
            args.get("choice"),
        )
        if not _is_type(owner, "string") or not owner or len(owner) > 256:
            _fail("feedback owner must be a non-empty string")
        if (
            not _is_type(leftovers, "array")
            or not leftovers
            or len(leftovers) > 64
            or any(
                not _is_type(key, "string") or not key or len(key) > 256
                for key in leftovers
            )
        ):
            _fail("feedback leftovers must be one to 64 non-empty strings")
        if choice not in ("stop", "keep", "standalone", "never"):
            _fail("feedback choice is invalid")
    if op in ("review_answer", "review_shown"):
        if not _is_type(args.get("review_id"), "integer") or args["review_id"] <= 0:
            _fail("review operation requires a positive review id")
    if op == "review_answer":
        if args.get("choice") not in ("stop", "keep", "standalone", "never"):
            _fail("feedback choice is invalid")
    if (
        op in ("review_answer", "review_shown")
        and "owner" in args
        and (
            not _is_type(args["owner"], "string")
            or not args["owner"]
            or len(args["owner"]) > 256
        )
    ):
        _fail("review owner is invalid")
    if op == "mute":
        if (
            not _is_type(args.get("app"), "string")
            or not args["app"]
            or len(args["app"]) > 256
        ):
            _fail("feedback app must be a non-empty string")
        if not _is_type(args.get("muted"), "boolean"):
            _fail("feedback muted must be a boolean")
    if op == "hold":
        if "scope" in args and (
            not _is_type(args["scope"], "string")
            or not args["scope"]
            or len(args["scope"]) > 256
        ):
            _fail("feedback scope must be a non-empty string")
        if not _is_type(args.get("held"), "boolean"):
            _fail("feedback held must be a boolean")
        if "reason" in args and (
            not _is_type(args["reason"], "string") or len(args["reason"]) > 256
        ):
            _fail("feedback reason must be a string of at most 256 characters")
    if op == "snooze":
        until = args.get("until")
        if not _finite_number(until) or until < 0:
            _fail("feedback snooze expiry must be a finite timestamp")
        if "reason" in args and (
            not _is_type(args["reason"], "string") or len(args["reason"]) > 256
        ):
            _fail("feedback reason must be a string of at most 256 characters")
    if op == "vetoed" and not _is_type(args.get("trigger"), "string"):
        _fail("vetoed feedback requires a trigger")


def validate_feedback(args):
    """Validate a legacy, v1, or v2 offline feedback operation."""
    if not isinstance(args, dict):
        _fail("feedback operation must be an object")
    _validate_feedback(args)


def _validate_args(command, args):
    definition = _COMMANDS.get(command)
    if definition is None:
        raise ProtocolError(
            "unknown_command", "Unknown command.", "Use a supported command."
        )
    fields, required = definition
    if command == "feedback":
        _validate_feedback(args)
        return
    if set(args) - set(fields):
        _fail("command arguments contain an unknown field")
    if not set(required) <= set(args):
        _fail("command arguments are missing a required field")
    for key, value in args.items():
        if not _is_type(value, fields[key]):
            _fail("argument %s has the wrong type" % key)
    if command == "reload" and len(args.get("reason", "")) > 256:
        _fail("reload reason must be at most 256 characters")
    if command == "subscribe":
        from .events import TOPICS

        topics = args["topics"]
        if (
            not topics
            or len(topics) > len(TOPICS)
            or any(
                not _is_type(topic, "string") or topic not in TOPICS for topic in topics
            )
            or len(set(topics)) != len(topics)
        ):
            _fail("subscribe topics must be unique supported topic names")
        if not 0 <= args["since_seq"] <= MAX_REQUEST_ID:
            _fail("subscribe sequence must be a non-negative safe integer")
    if command in ("register", "attach", "job_done", "kill_done", "ask"):
        pid = args.get("owner") if command == "register" else args.get("shell_pid")
        if pid is not None and pid <= 1:
            _fail("process id must be greater than one")
    if command == "attach":
        if not 0 < len(args["pids"]) <= 64 or any(
            not _is_type(pid, "integer") or pid <= 1 for pid in args["pids"]
        ):
            _fail("attach requires one to 64 process ids greater than one")
        if not args["scope"] or len(args["scope"]) > 256:
            _fail("attach scope is out of range")
    if command == "job_done":
        if (
            not 0 <= args["status"] <= 255
            or not args["tag"]
            or len(args["tag"]) > 128
            or len(args["word"]) > 32
        ):
            _fail("job status or command word is out of range")
    if command == "reclaim" and (not args["scope"] or len(args["scope"]) > 96):
        _fail("reclaim scope is empty or too long")
    if command == "freeze" and (not args["scope"] or len(args["scope"]) > 96):
        _fail("freeze scope is empty or too long")
    if command == "thaw":
        scope = args.get("scope")
        all_scopes = args.get("all") is True
        if all_scopes == (scope is not None):
            _fail("thaw requires exactly one of scope or all=true")
        if scope is not None and (not scope or len(scope) > 96):
            _fail("thaw scope is empty or too long")
    if command == "kill_done" and args["word"] not in (
        "kill",
        "pkill",
        "killall",
        "taema",
    ):
        _fail("kill command word is invalid")
    if command == "answer":
        if not args["nonce"] or len(args["nonce"]) > 64:
            _fail("answer nonce is invalid")
        if args["choice"] not in ("stop", "keep", "standalone", "never"):
            _fail("answer choice is invalid")
        if "owner" in args and len(args["owner"]) > 256:
            _fail("answer owner is out of range")


def decode_v2(message):
    """Validate a v2 envelope and return the legacy-shaped command for dispatch."""
    if not isinstance(message, dict):
        _fail("request must be an object")
    if set(message) - {"v", "id", "cmd", "args"}:
        _fail("request envelope contains an unknown field")
    if set(message) != {"v", "id", "cmd", "args"}:
        _fail("request envelope is missing a required field")
    if message["v"] != 2 or not _is_type(message["v"], "integer"):
        raise ProtocolError(
            "unsupported_version", "Unsupported protocol version.", "Use v=2."
        )
    identifier = message["id"]
    if not _is_type(identifier, "integer") or not 0 <= identifier <= MAX_REQUEST_ID:
        _fail("request id must be a non-negative safe integer")
    command = message["cmd"]
    if not _is_type(command, "string"):
        _fail("command must be a string")
    args = message["args"]
    if not isinstance(args, dict):
        _fail("args must be an object")
    _validate_args(command, args)
    return {"cmd": command, **args}


def error_reply(identifier, error):
    return {
        "v": 2,
        "id": identifier,
        "ok": False,
        "error": {
            "code": error.code,
            "message": str(error),
            "hint": error.hint,
        },
    }


def reply_v2(identifier, result):
    if isinstance(result, dict) and "error" in result:
        message = str(result["error"])
        if message == "unknown command":
            code, hint = "unknown_command", "Use a supported command."
        elif message == "forbidden" or message.endswith("gone or not yours"):
            code, hint = (
                "forbidden",
                "The daemon only serves processes owned by this user.",
            )
        elif "nonce" in message:
            code, hint = "invalid_nonce", "Request a fresh review before answering."
        elif message == "bad request":
            code, hint = "invalid_request", "Check the command and its arguments."
        else:
            code, hint = "operation_failed", "Inspect current state before retrying."
        return error_reply(identifier, ProtocolError(code, message, hint))
    return {"v": 2, "id": identifier, "ok": True, "result": result}
