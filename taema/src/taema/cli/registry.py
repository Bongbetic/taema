"""Single source for public command names, aliases, help, and arguments."""

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

# String annotation: keeps the type visible to checkers without importing typing
# on the latency-sensitive CLI path.
COMMANDS: "tuple[dict[str, object], ...]" = (
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
        "name": "launch",
        "aliases": (),
        "help": "launch CMD inside its own reserved app scope",
        "handler": "cmd_launch",
        "arguments": (
            (("--app",), {"metavar": "NAME", "help": "app name for the scope"}),
            (("--unit",), {"metavar": "UNIT", "help": "unit to record on the app"}),
            (
                ("--bind",),
                {
                    "action": "store_true",
                    "help": "stop the scope when CMD itself exits",
                },
            ),
            (("--dry-run",), {"action": "store_true"}),
            (("cmd",), {"remainder": True}),
        ),
    },
    {
        "name": "desktop",
        "aliases": (),
        "help": "wrap launcher entries with taema launch",
        "handler": "cmd_desktop",
        "children": (
            {
                "name": "wrap",
                "help": "wrap NAME.desktop with taema launch",
                "handler": "cmd_desktop_wrap",
                "arguments": ((("name",), {}),),
            },
            {
                "name": "unwrap",
                "help": "remove the wrapper for NAME",
                "handler": "cmd_desktop_unwrap",
                "arguments": (
                    (("name",), {"nargs": "?"}),
                    (("--all",), {"action": "store_true"}),
                ),
            },
            {
                "name": "list",
                "help": "list wrapped launcher entries",
                "handler": "cmd_desktop_list",
                "read": True,
                "arguments": (),
            },
        ),
    },
    {
        "name": "bar",
        "aliases": (),
        "help": "stream bar state in waybar, i3bar, json, or plain",
        "handler": "cmd_bar",
        "read": True,
        "arguments": (
            (
                ("--format",),
                {
                    "metavar": "FORMAT",
                    "default": "plain",
                    "choices": ("waybar", "i3bar", "json", "plain"),
                    "help": "output format",
                },
            ),
            (
                ("--follow",),
                {
                    "action": "store_true",
                    "help": "stream one line per state change",
                },
            ),
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
                ("--force-veto",),
                {
                    "action": "store_true",
                    "help": "show and explicitly confirm an audited veto override",
                },
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
        "help": "explain a process, scope, app, pair, or latest decision",
        "handler": "cmd_explain",
        "read": True,
        "arguments": (
            (("--pair",), {"nargs": 2, "metavar": ("OWNER", "LEFTOVER")}),
            (("target",), {"nargs": "?"}),
        ),
    },
    {
        "name": "keep",
        "aliases": ("allow",),
        "help": "keep an executable or owner/survivor pair",
        "handler": "cmd_keep",
        "arguments": (
            (("--dry-run",), {"action": "store_true"}),
            (("--pair",), {"nargs": 2, "metavar": ("OWNER", "LEFTOVER")}),
            (("exe",), {"nargs": "?"}),
        ),
    },
    {
        "name": "forget",
        "aliases": (),
        "help": "forget an executable or veto",
        "handler": "cmd_forget",
        "arguments": (
            (("--veto",), {"action": "store_true"}),
            (("--dry-run",), {"action": "store_true"}),
            (
                ("--all",),
                {"action": "store_true", "help": "remove all learned records for APP"},
            ),
            (("--scope",), {"metavar": "SCOPE"}),
            (("--pid",), {"metavar": "PID"}),
            (("--pair",), {"nargs": 2, "metavar": ("OWNER", "LEFTOVER")}),
            (("--signature",), {"metavar": "ID"}),
            (("--app",), {"metavar": "APP"}),
            (("--owner",), {"metavar": "APP"}),
            (("--unit",), {"metavar": "UNIT"}),
            (("--cgroup",), {"metavar": "PREFIX"}),
            (("--path",), {"metavar": "EXECUTABLE"}),
            (("exe",), {"nargs": "?"}),
        ),
    },
    {
        "name": "do-not-kill",
        "aliases": ("dnk", "never"),
        "help": "veto a target or the latest automatic stop",
        "handler": "cmd_do_not_kill",
        "arguments": (
            (("--dry-run",), {"action": "store_true"}),
            (
                ("--all",),
                {"action": "store_true", "help": "veto every matching target"},
            ),
            (("--scope",), {"metavar": "SCOPE"}),
            (("--pid",), {"metavar": "PID"}),
            (("--pair",), {"nargs": 2, "metavar": ("OWNER", "LEFTOVER")}),
            (("--signature",), {"metavar": "ID"}),
            (("--app",), {"metavar": "APP"}),
            (("--owner",), {"metavar": "APP"}),
            (("--unit",), {"metavar": "UNIT"}),
            (("--cgroup",), {"metavar": "PREFIX"}),
            (("--path",), {"metavar": "EXECUTABLE"}),
            (
                ("--for",),
                {
                    "dest": "for_duration",
                    "type_name": "duration",
                    "metavar": "DURATION",
                },
            ),
            (("--until",), {"metavar": "DATE"}),
            (("--reason",), {"metavar": "TEXT"}),
            (("target",), {"nargs": "?"}),
        ),
    },
    {
        "name": "mute",
        "aliases": (),
        "help": "mute an app's notifications, or list muted apps",
        "handler": "cmd_mute",
        "arguments": ((("app",), {"nargs": "?", "metavar": "APP"}),),
    },
    {
        "name": "unmute",
        "aliases": (),
        "help": "unmute an app's notifications",
        "handler": "cmd_unmute",
        "arguments": ((("app",), {"metavar": "APP"}),),
    },
    {
        "name": "undo",
        "aliases": (),
        "help": "undo the latest automatic action or a decision by id",
        "handler": "cmd_undo",
        "arguments": (
            (("--dry-run",), {"action": "store_true"}),
            (
                ("--restore",),
                {"action": "store_true", "help": "relaunch a stopped root"},
            ),
            (("decision_id",), {"nargs": "?", "metavar": "ID"}),
        ),
    },
    {
        "name": "restore",
        "aliases": (),
        "help": "relaunch a stopped root by decision id",
        "handler": "cmd_restore",
        "arguments": ((("decision_id",), {"metavar": "ID"}),),
    },
    {
        "name": "doctor",
        "aliases": (),
        "help": "check system support and report setup problems",
        "handler": "cmd_doctor",
        "read": True,
        "arguments": (
            (
                ("--fix",),
                {
                    "action": "store_true",
                    "help": "repair safe items; print root commands unless --sudo",
                },
            ),
            (
                ("--sudo",),
                {
                    "action": "store_true",
                    "help": "run the printed root commands for doctor --fix",
                },
            ),
        ),
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
        "name": "memory",
        "aliases": (),
        "help": "show host and per-scope memory accounting",
        "handler": "cmd_memory",
        "read": True,
        "optional_children": True,
        "children": (
            {
                "name": "budget",
                "help": "show the memory budget and live scope shares",
                "handler": "cmd_memory_budget",
                "read": True,
            },
            {
                "name": "top",
                "help": "show scopes ranked by current memory use",
                "handler": "cmd_memory_top",
                "read": True,
                "arguments": ((("--limit",), {"type": int, "default": 10}),),
            },
            {
                "name": "watch",
                "help": "watch memory snapshots",
                "handler": "cmd_memory_watch",
                "read": True,
                "arguments": (
                    (("--interval",), {"type": float, "default": 5.0}),
                    (
                        ("--count",),
                        {"type": int, "help": "stop after this many snapshots"},
                    ),
                ),
            },
            {
                "name": "pressure",
                "help": "show host and per-scope memory pressure",
                "handler": "cmd_memory_pressure",
                "read": True,
            },
            {
                "name": "reclaim",
                "help": "reclaim bounded page cache from an eligible scope",
                "handler": "cmd_memory_reclaim",
                "read": True,
                "arguments": (
                    (("--force-veto",), {"action": "store_true"}),
                    (("--dry-run",), {"action": "store_true"}),
                    (("name",), {"metavar": "NAME"}),
                ),
            },
        ),
    },
    {
        "name": "watch",
        "aliases": (),
        "help": "print live changes as plain lines",
        "handler": "cmd_watch",
    },
    {
        "name": "agent",
        "aliases": (),
        "help": "relay this session's desktop facts to the daemon",
        "handler": "cmd_agent",
    },
    {
        "name": "dash",
        "aliases": (),
        "help": "show scopes, learning, memory, and events in one screen",
        "handler": "cmd_dash",
        "read": True,
        "arguments": (
            (
                ("--once",),
                {"action": "store_true", "help": "print one snapshot and exit"},
            ),
        ),
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
        "help": "list pending reviews or answer them interactively",
        "handler": "cmd_review",
        "read": True,
        "arguments": ((("--interactive",), {"action": "store_true"}),),
    },
    {
        "name": "answer",
        "aliases": (),
        "help": "answer a pending review",
        "handler": "cmd_answer",
        "arguments": (
            (("id",), {}),
            (
                ("choice",),
                {
                    "choices": (
                        "stop",
                        "keep",
                        "standalone",
                        "never",
                        "1",
                        "2",
                        "3",
                        "4",
                    )
                },
            ),
            (("--owner",), {"help": "choose the owner for an ambiguous review"}),
        ),
    },
    {
        "name": "teach",
        "aliases": (),
        "help": "teach an owner/survivor relationship without a review",
        "handler": "cmd_teach",
        "arguments": (
            (("owner",), {}),
            (("leftover",), {}),
            (("choice",), {"choices": ("stop", "keep", "standalone")}),
        ),
    },
    {
        "name": "learn",
        "aliases": (),
        "help": "inspect or export learned state",
        "handler": None,
        "read": True,
        "children": (
            {
                "name": "show",
                "help": "show learned apps, pairs, and signatures",
                "handler": "cmd_learn",
                "arguments": ((("--legacy",), {"action": "store_true"}),),
                "read": True,
            },
            {
                "name": "apps",
                "help": "list learned app records",
                "handler": "cmd_learn",
                "read": True,
            },
            {
                "name": "pairs",
                "help": "list learned owner and leftover pairs",
                "handler": "cmd_learn",
                "read": True,
            },
            {
                "name": "signatures",
                "help": "list learned survivor signatures",
                "handler": "cmd_learn",
                "read": True,
            },
            {
                "name": "export",
                "help": "export learned answers",
                "handler": "cmd_learn_export",
                "arguments": (
                    (
                        ("--format",),
                        {
                            "choices": ("learn-v1", "v2"),
                            "default": "learn-v1",
                            "help": "learn-v1 (default) or v2 for a 0.2 downgrade",
                        },
                    ),
                    (
                        ("--output",),
                        {"help": "write atomically to PATH instead of stdout"},
                    ),
                    (
                        ("--redact",),
                        {
                            "action": "store_true",
                            "help": "strip argv, cwd, titles, and environment values",
                        },
                    ),
                ),
            },
            {
                "name": "import",
                "help": "import learned answers from an export file",
                "handler": "cmd_learn_import",
                "arguments": (
                    (("file",), {}),
                    (("--merge",), {"action": "store_true"}),
                    (("--replace",), {"action": "store_true"}),
                ),
            },
        ),
    },
    {
        "name": "report",
        "aliases": (),
        "help": "summarize a day, week, or month of cleanup activity",
        "handler": "cmd_report",
        "read": True,
        "arguments": (
            (("--day",), {"action": "store_true"}),
            (("--week",), {"action": "store_true"}),
            (("--month",), {"action": "store_true"}),
        ),
    },
    {
        "name": "top",
        "aliases": (),
        "help": "live process table sorted by CPU, memory, then PID",
        "handler": "cmd_top",
        "read": True,
        "arguments": (
            (
                ("count",),
                {"nargs": "?", "help": "snapshots to show, then exit"},
            ),
            (
                ("--interval",),
                {"help": "seconds between snapshots (default 1)"},
            ),
            (
                ("--once",),
                {
                    "action": "store_true",
                    "help": "print one snapshot and exit",
                },
            ),
            (
                ("--sort",),
                {
                    "metavar": "COLUMN",
                    "help": "sort by cpu, mem, delta, psi, scope, or pid",
                },
            ),
        ),
    },
    {
        "name": "tree",
        "aliases": (),
        "help": "process trees grouped under scope headers",
        "handler": "cmd_tree",
        "read": True,
        "arguments": (
            (
                ("target",),
                {"nargs": "?", "help": "only scopes whose name contains TARGET"},
            ),
        ),
    },
    {
        "name": "unit",
        "aliases": (),
        "help": "unit authoring tools",
        "handler": "cmd_unit",
        "children": (
            {
                "name": "new",
                "help": "draft a unit from a running process, scope, or app",
                "handler": "cmd_unit_new",
                "arguments": (
                    (
                        ("--from",),
                        {
                            "dest": "from_target",
                            "required": True,
                            "help": "PID, scope:REL, or app comm",
                        },
                    ),
                    (
                        ("--name",),
                        {"help": "unit name (default: from the process)"},
                    ),
                    (
                        ("--force",),
                        {"action": "store_true", "help": "overwrite an existing file"},
                    ),
                ),
            },
            {
                "name": "test",
                "help": "dry-run a unit file or name through the ladder",
                "handler": "cmd_unit_test",
                "read": True,
                "arguments": ((("target",), {}),),
            },
            {
                "name": "draft",
                "help": "generate a unit file from a running process",
                "handler": "cmd_unit_draft",
                "arguments": (
                    (("name",), {}),
                    (
                        ("--from",),
                        {
                            "dest": "from_pid",
                            "required": True,
                            "help": "draft from PID",
                        },
                    ),
                    (
                        ("--force",),
                        {"action": "store_true", "help": "overwrite an existing file"},
                    ),
                ),
            },
            {
                "name": "dry-run",
                "help": "show what a unit file would match, changing nothing",
                "handler": "cmd_unit_dry_run",
                "read": True,
                "arguments": ((("file",), {}),),
            },
            {
                "name": "lint",
                "help": "lint one unit file",
                "handler": "cmd_unit_lint",
                "read": True,
                "arguments": ((("file",), {}),),
            },
            {
                "name": "list",
                "help": "list units with source and active state",
                "handler": "cmd_unit_list",
                "read": True,
            },
            {
                "name": "enable",
                "help": "unmask a unit so it loads again",
                "handler": "cmd_unit_enable",
                "arguments": ((("name",), {}),),
            },
            {
                "name": "disable",
                "help": "mask a unit with a user tombstone",
                "handler": "cmd_unit_disable",
                "arguments": ((("name",), {}),),
            },
            {
                "name": "install",
                "help": "install a curated pack to the user units",
                "handler": "cmd_unit_install",
                "arguments": (
                    (
                        ("name",),
                        {},
                    ),
                    (
                        ("--force",),
                        {
                            "action": "store_true",
                            "help": "overwrite an existing unit file",
                        },
                    ),
                ),
            },
        ),
    },
    {
        "name": "recent",
        "aliases": (),
        "help": "list the latest automatic actions",
        "handler": "cmd_recent",
        "read": True,
        "arguments": (),
    },
    {
        "name": "history",
        "aliases": (),
        "help": "show the timeline of one app or scope",
        "handler": "cmd_history",
        "read": True,
        "arguments": (
            (("target",), {"help": "APP, SCOPE, app:APP, or scope:SCOPE"}),
            (
                ("--since",),
                {"help": "epoch timestamp or relative Ns/Nm/Nh/Nd"},
            ),
        ),
    },
    {
        "name": "suggest",
        "aliases": (),
        "help": "list ranked improvements, or apply one by id",
        "handler": "cmd_suggest",
        "read": True,
        "optional_children": True,
        "children": (
            {
                "name": "apply",
                "help": "apply one suggestion by id after confirmation",
                "handler": "cmd_suggest_apply",
                "arguments": (
                    (
                        ("identifier",),
                        {},
                    ),
                    (
                        ("--choice",),
                        {
                            "choices": ("stop", "keep", "standalone", "never"),
                            "help": "answer for a stale-review suggestion",
                        },
                    ),
                    (
                        ("--force",),
                        {
                            "action": "store_true",
                            "help": "overwrite an existing unit file",
                        },
                    ),
                ),
            },
        ),
    },
    {
        "name": "setup",
        "aliases": (),
        "help": "walk from install to a working setup",
        "handler": "cmd_setup",
        "read": True,
    },
    {
        "name": "restore-backup",
        "aliases": (),
        "help": "restore state, config, and units from a backup tarball",
        "handler": "cmd_restore_backup",
        "arguments": ((("file",), {}),),
    },
    {
        "name": "reset",
        "aliases": (),
        "help": "clear learning, vetoes, history, or all state after a backup",
        "handler": "cmd_reset",
        "arguments": (
            (("--learning",), {"action": "store_true"}),
            (("--vetoes",), {"action": "store_true"}),
            (("--history",), {"action": "store_true"}),
            (("--all",), {"action": "store_true"}),
        ),
    },
    {
        "name": "backup",
        "aliases": (),
        "help": "write a tarball with the database, user config, and user units",
        "handler": "cmd_backup",
        "read": True,
        "arguments": (
            (
                ("--to",),
                {"help": "write to PATH instead of the state backups directory"},
            ),
        ),
    },
    {
        "name": "freeze",
        "aliases": (),
        "help": "manually freeze a safe leftover scope",
        "handler": "cmd_freeze",
        "arguments": ((("name",), {}),),
    },
    {
        "name": "thaw",
        "aliases": (),
        "help": "thaw a scope managed by taema, or all managed freezes",
        "handler": "cmd_thaw",
        "arguments": (
            (("--all",), {"action": "store_true"}),
            (("name",), {"nargs": "?"}),
        ),
    },
    {
        "name": "gc",
        "aliases": (),
        "help": "show or collect idle scopes",
        "handler": "cmd_gc",
        "read": True,
        "arguments": (
            (("--dry-run",), {"action": "store_true"}),
            (("--memory",), {"action": "store_true"}),
        ),
    },
    {
        "name": "adopt",
        "aliases": (),
        "help": "adopt eligible processes into scopes",
        "handler": "cmd_adopt",
        "arguments": (
            (("--all",), {"action": "store_true"}),
            (("--standalone",), {"action": "store_true"}),
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
        "name": "help",
        "aliases": (),
        "help": "show a topic: modes, learning, veto, ladder, memory, units, agent, profiles, privacy, safety",
        "handler": "cmd_help",
        "arguments": (
            (("topic",), {"nargs": "?", "metavar": "TOPIC"}),
        ),
    },
    {
        "name": "bug-report",
        "aliases": (),
        "help": "write a sanitized support bundle (versions, doctor, redacted config, units, metrics, events)",
        "handler": "cmd_bug_report",
        "read": True,
        "arguments": (
            (("--to",), {"metavar": "PATH", "help": "write to PATH instead of the state directory"}),
        ),
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

# Two to three real examples per command (issue #83). Keys are the
# `_command` value ("learn export" for children); missing keys fall back
# to the generic pair below.
EXAMPLES = {
    "run": ("taema run editor -- code .", "taema run --owner 4242 shell -- bash"),
    "launch": ("taema launch --app firefox -- firefox", "taema launch --bind -- ./app --serve"),
    "desktop": ("taema desktop wrap firefox.desktop", "taema desktop list"),
    "bar": ("taema bar --format waybar", "taema bar --format plain --follow"),
    "kill": ("taema kill scope-editor", "taema kill scope-editor --dry-run"),
    "ls": ("taema ls", "taema ls --json"),
    "explain": ("taema why scope-firefox", "taema explain app:firefox"),
    "keep": ("taema keep firefox", "taema keep --pair npm vite"),
    "forget": ("taema forget firefox", "taema forget --veto scope-x"),
    "do-not-kill": ("taema do-not-kill scope-x", "taema do-not-kill app:firefox --for 2h"),
    "mute": ("taema mute firefox", "taema mute"),
    "unmute": ("taema unmute firefox", "taema mute"),
    "undo": ("taema undo", "taema undo --restore"),
    "restore": ("taema restore 123", "taema recent"),
    "doctor": ("taema doctor", "taema doctor --fix"),
    "config": ("taema config show", "taema config get mode"),
    "reload": ("taema reload", "taema config show"),
    "mode": ("taema mode adopt", "taema status"),
    "profile": ("taema profile focus", "taema profile auto"),
    "hold": ("taema hold --reason lunch", "taema hold scope-x"),
    "resume": ("taema resume", "taema resume scope-x"),
    "snooze": ("taema snooze 2h", "taema snooze until 18:00"),
    "status": ("taema status", "taema status --json"),
    "memory": ("taema memory", "taema memory top"),
    "watch": ("taema watch", "taema events --follow"),
    "agent": ("taema agent", "taema status"),
    "dash": ("taema dash --once", "taema dash"),
    "events": ("taema events --since 0", "taema events --follow"),
    "prompt": ("taema prompt", "taema status"),
    "review": ("taema review", "taema review --interactive"),
    "answer": ("taema answer 12 keep", "taema review"),
    "teach": ("taema teach npm vite keep", "taema learn pairs"),
    "learn": ("taema learn show", "taema learn export --redact"),
    "report": ("taema report --day", "taema report --week"),
    "top": ("taema top --once", "taema top --sort mem"),
    "tree": ("taema tree", "taema tree firefox"),
    "unit": ("taema unit list", "taema unit lint file.toml"),
    "recent": ("taema recent", "taema history app:firefox"),
    "history": ("taema history app:firefox", "taema recent"),
    "suggest": ("taema suggest", "taema suggest apply 3"),
    "setup": ("taema setup", "taema doctor"),
    "restore-backup": ("taema restore-backup file.tar.gz", "taema backup"),
    "reset": ("taema reset --learning", "taema backup"),
    "backup": ("taema backup", "taema backup --to /tmp/taema-backup.tar.gz"),
    "freeze": ("taema freeze scope-x", "taema thaw scope-x"),
    "thaw": ("taema thaw scope-x", "taema thaw --all"),
    "gc": ("taema gc --dry-run", "taema gc --memory"),
    "adopt": ("taema adopt --dry-run", "taema adopt --all"),
    "daemon": ("taema daemon", "taema status"),
    "help": ("taema help modes", "taema help units"),
    "bug-report": ("taema bug-report", "taema bug-report --to /tmp/taema-bug.tar.gz"),
}
GENERIC_EXAMPLES = ("taema status", "taema doctor")
