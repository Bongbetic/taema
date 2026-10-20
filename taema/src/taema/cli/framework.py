"""Lightweight CLI registry and dispatch.

This module stays independent of the command implementation so ``--help`` and
``--version`` do not import the process, cgroup, database, or daemon modules.
"""

import os
import sys
from types import SimpleNamespace

from .registry import COMMANDS, GLOBAL_OPTIONS


class UsageError(ValueError):
    """A command-line parsing error with a user-facing hint."""


def _add_options(parser, definitions, defaults):
    import argparse

    for names, options in definitions:
        values = dict(options)
        values["default"] = (
            False if defaults and values.get("action") == "store_true" else None
        )
        if not defaults:
            values["default"] = argparse.SUPPRESS
        parser.add_argument(*names, **values)


def _add_output_options(parser, defaults):
    import argparse

    for name in ("--json", "--jsonl"):
        parser.add_argument(
            name,
            action="store_true",
            default=False if defaults else argparse.SUPPRESS,
            help="write schema-tagged JSON"
            if name == "--json"
            else "write one JSON object per line",
        )


def command_names():
    return tuple(name for spec in COMMANDS for name in (spec["name"], *spec["aliases"]))


def _parser(selected=None, include_all=True):
    import argparse

    from .. import __version__

    class Parser(argparse.ArgumentParser):
        def error(self, message):
            raise UsageError(message)

    parser = Parser(
        prog="taema",
        description="Dependency-aware cgroup v2 process scopes",
        allow_abbrev=False,
    )
    _add_options(parser, GLOBAL_OPTIONS, defaults=True)
    _add_output_options(parser, defaults=True)
    version = "taema " + __version__
    parser.add_argument("--version", action="version", version=version)
    parser.add_argument(
        "--do-not-kill",
        dest="_legacy_veto_target",
        nargs="?",
        const="",
        metavar="TARGET",
        help="veto a target, or the latest automatic stop",
    )
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")
    for spec in COMMANDS:
        if not include_all and selected not in (
            spec["name"],
            *spec["aliases"],
        ):
            continue
        command_parser = subparsers.add_parser(
            spec["name"],
            aliases=list(spec["aliases"]),
            help=spec["help"],
            allow_abbrev=False,
        )
        _add_options(command_parser, GLOBAL_OPTIONS, defaults=False)
        command_parser.add_argument("--version", action="version", version=version)
        if spec.get("read"):
            _add_output_options(command_parser, defaults=False)
        _add_arguments(command_parser, spec.get("arguments", ()))
        children = spec.get("children", ())
        if children:
            child_parsers = command_parser.add_subparsers(
                dest="child_command", required=True
            )
            for child in children:
                child_parser = child_parsers.add_parser(
                    child["name"], help=child["help"], allow_abbrev=False
                )
                _add_options(child_parser, GLOBAL_OPTIONS, defaults=False)
                _add_arguments(child_parser, child.get("arguments", ()))
                child_parser.set_defaults(
                    _handler=child["handler"],
                    _command=spec["name"] + " " + child["name"],
                )
        command_parser.set_defaults(_handler=spec["handler"], _command=spec["name"])
    return parser


def _selected_command(argv):
    value_options = {"--socket", "--config"}
    flags = {
        "--plain",
        "--wide",
        "--no-color",
        "--quiet",
        "--yes",
        "--verbose",
        "--json",
        "--jsonl",
        "--version",
        "-h",
        "--help",
    }
    index = 0
    while index < len(argv):
        token = argv[index]
        if token in value_options:
            index += 2
            continue
        if token.startswith("--socket=") or token.startswith("--config="):
            index += 1
            continue
        if token == "--do-not-kill":
            index += 1
            if index < len(argv) and not argv[index].startswith("-"):
                index += 1
            continue
        if token.startswith("--do-not-kill=") or token in flags:
            index += 1
            continue
        if token.startswith("-"):
            index += 1
            continue
        return token
    return None


def _add_arguments(parser, definitions):
    import argparse

    for names, options in definitions:
        values = dict(options)
        remainder = values.pop("remainder", False)
        if remainder:
            values["nargs"] = argparse.REMAINDER
        parser.add_argument(*names, **values)


def _suggestion(message):
    import difflib
    import re

    match = re.search(r"invalid choice: '([^']+)'", message)
    candidates = command_names()
    if match:
        close = difflib.get_close_matches(match.group(1), candidates, n=1, cutoff=0.55)
        if close:
            return "Did you mean `taema %s`?" % close[0]
    match = re.search(r"unrecognized arguments?: (.+)", message)
    if match:
        token = match.group(1).split()[0]
        options = [
            "--%s" % name
            for name in (
                "plain",
                "wide",
                "no-color",
                "quiet",
                "yes",
                "socket",
                "config",
                "verbose",
                "json",
                "jsonl",
                "help",
                "version",
            )
        ]
        close = difflib.get_close_matches(token, options, n=1, cutoff=0.55)
        if close:
            return "Did you mean `%s`?" % close[0]
    return "Run `taema --help` to see the available commands and options."


def _usage_error(parser, message):
    print("taema: %s" % message, file=sys.stderr)
    print(
        "hint: check the command spelling and its required arguments.", file=sys.stderr
    )
    print("suggestion: %s" % _suggestion(message), file=sys.stderr)
    return 1


def _invoke(args):
    from . import commands
    from . import view

    handler = getattr(commands, args._handler)
    args._color = view.color_enabled(args, sys.stdout)
    args._width = view.terminal_width(args)
    capture = args.quiet or bool(getattr(args, "_read", False)) or args.command is None
    if not capture:
        try:
            return handler(args) or 0
        except (OSError, ValueError) as error:
            return commands.die(str(error))

    import io
    from contextlib import redirect_stdout

    output = io.StringIO()
    try:
        with redirect_stdout(output):
            result = handler(args)
    except (OSError, ValueError) as error:
        return commands.die(str(error))
    rendered = output.getvalue()
    if rendered and not args.quiet:
        if bool(getattr(args, "_read", False)) and not (args.json or args.jsonl):
            if _page(rendered):
                return result or 0
        sys.stdout.write(rendered)
    return result or 0


def _fast_status_args(argv):
    """Parse only the common options for status without importing argparse."""
    value_options = {}
    flag_options = {}
    for names, options in GLOBAL_OPTIONS:
        dest = options.get("dest") or names[0][2:].replace("-", "_")
        if options.get("action") == "store_true":
            for name in names:
                flag_options[name] = dest
        else:
            for name in names:
                value_options[name] = dest
    flag_options.update({"--json": "json", "--jsonl": "jsonl"})

    values = {
        "command": None,
        "_command": None,
        "_handler": "cmd_status",
        "_read": True,
        "_summary": True,
        "_fast": True,
        "plain": False,
        "wide": False,
        "no_color": False,
        "quiet": False,
        "yes": False,
        "verbose": False,
        "socket": None,
        "config": None,
        "json": False,
        "jsonl": False,
    }
    explicit_status = False
    index = 0
    while index < len(argv):
        token = argv[index]
        if token == "status" and not explicit_status:
            explicit_status = True
            values["command"] = "status"
            values["_command"] = "status"
            values["_summary"] = False
            index += 1
            continue
        if token in flag_options:
            values[flag_options[token]] = True
            index += 1
            continue
        matched_value = False
        for option, dest in value_options.items():
            if token == option:
                if index + 1 >= len(argv) or argv[index + 1].startswith("-"):
                    return None
                values[dest] = argv[index + 1]
                index += 2
                matched_value = True
                break
            if token.startswith(option + "="):
                values[dest] = token[len(option) + 1 :]
                index += 1
                matched_value = True
                break
        if matched_value:
            continue
        return None
    if values["json"] and values["jsonl"]:
        return None
    return SimpleNamespace(**values)


def _page(rendered):
    pager = os.environ.get("PAGER")
    if not pager or not sys.stdout.isatty():
        return False
    import shlex
    import subprocess

    try:
        command = shlex.split(pager)
        if not command:
            return False
        return (
            subprocess.run(command, input=rendered, text=True, check=False).returncode
            == 0
        )
    except (OSError, ValueError):
        return False


def main(argv):
    fast_args = _fast_status_args(argv)
    if fast_args is not None:
        return _invoke(fast_args)
    selected = _selected_command(argv)
    parser = _parser(
        selected,
        include_all=selected is None and any(arg in ("-h", "--help") for arg in argv),
    )
    try:
        args = parser.parse_args(argv)
    except UsageError as error:
        return _usage_error(parser, str(error))
    if not hasattr(args, "quiet"):
        args.quiet = False
    if not hasattr(args, "json"):
        args.json = False
    if not hasattr(args, "jsonl"):
        args.jsonl = False
    if not hasattr(args, "_command"):
        args._command = None
    if args.json and args.jsonl:
        return _usage_error(parser, "--json and --jsonl cannot be combined")
    if args.command is None:
        if args._legacy_veto_target is not None:
            args.target = args._legacy_veto_target or None
            args._handler = "cmd_do_not_kill"
            args._read = False
        else:
            args._handler = "cmd_status"
            args._read = True
            args._summary = True
    else:
        args._read = bool(
            next(
                (
                    spec.get("read", False)
                    for spec in COMMANDS
                    if args._command == spec["name"]
                ),
                False,
            )
        )
    if (args.json or args.jsonl) and not args._read:
        return _usage_error(parser, "JSON output is only available for read commands")
    if args._handler is None:
        return _usage_error(parser, "a command is required")
    if args._command == "run" and args.cmd and args.cmd[0] == "--":
        args.cmd = args.cmd[1:]
    if args._command == "run" and not args.cmd:
        print("taema: run requires a command to execute", file=sys.stderr)
        print("hint: use `taema run NAME COMMAND...`.", file=sys.stderr)
        print("suggestion: run `taema run --help` for examples.", file=sys.stderr)
        return 1
    return _invoke(args)
