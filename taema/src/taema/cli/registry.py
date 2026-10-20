"""Single source for public command names, aliases, help, and arguments."""

from typing import Any

GLOBAL_OPTIONS = (
    (("--plain",), {"action": "store_true", "help": "use plain, accessible output"}),
    (("--wide",), {"action": "store_true", "help": "do not truncate terminal output"}),
    (("--no-color",), {"action": "store_true", "help": "disable color output"}),
    (("--quiet",), {"action": "store_true", "help": "suppress successful output"}),
    (("--yes",), {"action": "store_true", "help": "assume yes for confirmations"}),
    (("--pick",), {"action": "store_true", "help": "use fzf for ambiguous targets"}),
    (("--socket",), {"metavar": "PATH", "help": "connect to this daemon socket"}),
    (("--config",), {"metavar": "PATH", "help": "load this configuration file"}),
    (("--verbose",), {"action": "store_true", "help": "show additional details"}),
)

COMMANDS: tuple[dict[str, Any], ...] = (
    {
        "name": "run",
        "aliases": (),
        "help": "run CMD inside scope-NAME",
        "handler": "cmd_run",
        "arguments": (
            (("--join",), {"action": "store_true"}),
            (("--dry-run",), {"action": "store_true"}),
            (("--owner",), {"type": int, "help": "stop the scope when this pid exits"}),
            (
                ("--bind",),
                {
                    "action": "store_true",
                    "help": "stop the scope when CMD itself exits",
                },
            ),
            (("name",), {}),
            (("cmd",), {"remainder": True}),
        ),
    },
    {
        "name": "kill",
        "aliases": ("stop",),
        "help": "stop a scope; shared members are moved aside, not killed",
        "handler": "cmd_kill",
        "arguments": (
            (("-t", "--timeout"), {"type_name": "duration", "metavar": "DURATION"}),
            (("--dry-run",), {"action": "store_true"}),
            (
                ("--do-not-kill",),
                {
                    "action": "store_true",
                    "help": "conflicts with kill; use the do-not-kill command separately",
                },
            ),
            (
                ("--force",),
                {"action": "store_true", "help": "ignore learned/seed defaults"},
            ),
            (
                ("--hard",),
                {"action": "store_true", "help": "also ignore detected outside users"},
            ),
            (
                ("--keep",),
                {"help": "comma list of exe names to move aside instead of killing"},
            ),
            (("name",), {"nargs": "?"}),
        ),
    },
    {
        "name": "ls",
        "aliases": ("ps",),
        "help": "list scopes",
        "handler": "cmd_ls",
        "read": True,
    },
    {
        "name": "explain",
        "aliases": ("why",),
        "help": "explain a process, scope, or app",
        "handler": "cmd_explain",
        "read": True,
        "arguments": ((("target",), {}),),
    },
    {
        "name": "keep",
        "aliases": ("allow",),
        "help": "keep an executable",
        "handler": "cmd_keep",
        "arguments": ((("--dry-run",), {"action": "store_true"}), (("exe",), {})),
    },
    {
        "name": "forget",
        "aliases": (),
        "help": "forget an executable or veto",
        "handler": "cmd_forget",
        "arguments": (
            (("--veto",), {"action": "store_true"}),
            (("--dry-run",), {"action": "store_true"}),
            (("exe",), {}),
        ),
    },
    {
        "name": "do-not-kill",
        "aliases": ("dnk", "never"),
        "help": "veto a target or the latest automatic stop",
        "handler": "cmd_do_not_kill",
        "arguments": (
            (("--dry-run",), {"action": "store_true"}),
            (("target",), {"nargs": "?"}),
        ),
    },
    {
        "name": "undo",
        "aliases": (),
        "help": "undo the latest automatic stop",
        "handler": "cmd_undo",
        "arguments": ((("--dry-run",), {"action": "store_true"}),),
    },
    {
        "name": "doctor",
        "aliases": (),
        "help": "check system support and report setup problems",
        "handler": "cmd_doctor",
        "read": True,
    },
    {
        "name": "config",
        "aliases": (),
        "help": "show or edit layered configuration",
        "handler": None,
        "children": (
            {
                "name": "show",
                "help": "show effective configuration",
                "handler": "cmd_config_show",
                "arguments": ((("--sources",), {"action": "store_true"}),),
            },
            {
                "name": "get",
                "help": "print one effective value",
                "handler": "cmd_config_get",
                "arguments": ((("key",), {}),),
            },
            {
                "name": "set",
                "help": "set a value in the managed drop-in",
                "handler": "cmd_config_set",
                "arguments": ((("key",), {}), (("value",), {})),
            },
            {
                "name": "unset",
                "help": "remove a value from the managed drop-in",
                "handler": "cmd_config_unset",
                "arguments": ((("key",), {}),),
            },
            {
                "name": "edit",
                "help": "edit and validate the managed drop-in",
                "handler": "cmd_config_edit",
            },
            {
                "name": "diff",
                "help": "compare effective config with system defaults",
                "handler": "cmd_config_diff",
            },
        ),
    },
    {
        "name": "reload",
        "aliases": (),
        "help": "reload configuration and units in the daemon",
        "handler": "cmd_reload",
    },
    {
        "name": "mode",
        "aliases": (),
        "help": "switch lifecycle mode without restarting the daemon",
        "handler": "cmd_mode",
        "arguments": (
            (
                ("mode",),
                {"choices": ("observe", "adopt", "enforce", "auto")},
            ),
        ),
    },
    {
        "name": "profile",
        "aliases": (),
        "help": "select a configuration profile or return to automatic selection",
        "handler": "cmd_profile",
        "arguments": (
            (
                ("name",),
                {},
            ),
        ),
    },
    {
        "name": "hold",
        "aliases": (),
        "help": "pause taema actions without changing mode",
        "handler": "cmd_hold",
        "arguments": (
            (("--dry-run",), {"action": "store_true"}),
            (("--reason",), {"default": "", "help": "why actions are being held"}),
            (("target",), {"nargs": "?"}),
        ),
    },
    {
        "name": "resume",
        "aliases": (),
        "help": "resume taema actions",
        "handler": "cmd_resume",
        "arguments": (
            (("--dry-run",), {"action": "store_true"}),
            (("--reason",), {"default": "", "help": "why actions are resuming"}),
            (("target",), {"nargs": "?"}),
        ),
    },
    {
        "name": "snooze",
        "aliases": (),
        "help": "hold all taema actions for a duration or until a local time",
        "handler": "cmd_snooze",
        "arguments": (
            (("--dry-run",), {"action": "store_true"}),
            (("when",), {"nargs": "+", "metavar": "DURATION|until TIME"}),
        ),
    },
    {
        "name": "status",
        "aliases": (),
        "help": "show daemon and policy status",
        "handler": "cmd_status",
        "read": True,
    },
    {
        "name": "watch",
        "aliases": (),
        "help": "print live changes as plain lines",
        "handler": "cmd_watch",
    },
    {
        "name": "events",
        "aliases": (),
        "help": "query or follow the event log",
        "handler": "cmd_events",
        "read": True,
        "arguments": (
            (("--since",), {"type": int, "default": 0, "metavar": "SEQ"}),
            (("--event",), {"metavar": "NAME"}),
            (("--follow",), {"action": "store_true"}),
        ),
    },
    {
        "name": "prompt",
        "aliases": (),
        "help": "print the cached prompt summary without contacting the daemon",
        "handler": "cmd_prompt",
    },
    {
        "name": "review",
        "aliases": (),
        "help": "list pending close reviews",
        "handler": "cmd_review",
        "read": True,
    },
    {
        "name": "learn",
        "aliases": (),
        "help": "inspect or export learned state",
        "handler": None,
        "children": (
            {
                "name": "export",
                "help": "export state for a 0.2 downgrade",
                "handler": "cmd_learn_export",
                "arguments": (
                    (("--format",), {"choices": ("v2",), "required": True}),
                    (
                        ("--output",),
                        {"help": "write atomically to PATH instead of stdout"},
                    ),
                ),
            },
        ),
    },
    {
        "name": "gc",
        "aliases": (),
        "help": "show or collect idle scopes",
        "handler": "cmd_gc",
        "read": True,
        "arguments": ((("--dry-run",), {"action": "store_true"}),),
    },
    {
        "name": "adopt",
        "aliases": (),
        "help": "adopt eligible processes into scopes",
        "handler": "cmd_adopt",
        "arguments": (
            (("--all",), {"action": "store_true"}),
            (("--dry-run",), {"action": "store_true"}),
        ),
    },
    {
        "name": "daemon",
        "aliases": (),
        "help": "run the per-user daemon",
        "handler": "cmd_daemon",
    },
    {
        "name": "__complete",
        "aliases": (),
        "help": "internal shell completion interface",
        "handler": "cmd_complete",
        "hidden": True,
        "arguments": (
            (("--shell",), {"choices": ("bash", "zsh", "fish"), "required": True}),
            (("--word",), {"default": ""}),
            (("--line",), {"default": ""}),
            (("--cursor",), {"type": int}),
        ),
    },
)
