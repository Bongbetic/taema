"""Tiny top-level help path that does not import argparse or command handlers."""

from .registry import COMMANDS, GLOBAL_OPTIONS


def help_text():
    commands = []
    for spec in COMMANDS:
        if spec.get("hidden"):
            continue
        names = [spec["name"], *spec["aliases"]]
        commands.append("  %-30s %s" % (", ".join(names), spec["help"]))
    options = [
        "  %-30s %s" % (names[0], values.get("help", ""))
        for names, values in GLOBAL_OPTIONS
    ]
    options.extend(
        (
            "  %-30s %s" % ("--json", "write schema-tagged JSON"),
            "  %-30s %s" % ("--jsonl", "write one JSON object per line"),
            "  %-30s %s" % ("--version", "show the version"),
            "  %-30s %s"
            % ("--do-not-kill [TARGET]", "veto a target or latest automatic stop"),
            "  %-30s %s" % ("-h, --help", "show this help message"),
        )
    )
    return (
        "usage: taema [OPTIONS] COMMAND [ARGS]...\n\n"
        "Dependency-aware cgroup v2 process scopes\n\n"
        "Commands:\n%s\n\nOptions:\n%s\n" % ("\n".join(commands), "\n".join(options))
    )


def main():
    import sys

    sys.stdout.write(help_text())
    return 0
