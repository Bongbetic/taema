"""Command-line package with lazy legacy exports."""

from importlib import import_module

__all__ = (
    "nullcontext",
    "count",
    "json",
    "os",
    "socket",
    "sys",
    "tempfile",
    "time",
    "uuid",
    "authorization",
    "cgroup",
    "inspect",
    "lineage",
    "engine",
    "knowledge",
    "policy",
    "sock_paths",
    "sock_path",
    "ask",
    "feedback",
    "feedback_action",
    "veto_target",
    "veto_label",
    "die",
    "cmd_run",
    "cmd_kill",
    "cmd_hold",
    "cmd_resume",
    "cmd_snooze",
    "cmd_ls",
    "cmd_explain",
    "cmd_keep",
    "cmd_do_not_kill",
    "cmd_undo",
    "cmd_forget",
    "print_pairs",
    "print_auto",
    "cmd_status",
    "cmd_doctor",
    "cmd_config_show",
    "cmd_config_get",
    "cmd_config_set",
    "cmd_config_unset",
    "cmd_config_edit",
    "cmd_config_diff",
    "cmd_reload",
    "cmd_mode",
    "cmd_profile",
    "cmd_review",
    "cmd_learn_export",
    "cmd_gc",
    "cmd_adopt",
    "cmd_daemon",
    "cmd_complete",
    "main",
)


def __getattr__(name):
    if name in ("commands", "framework", "view"):
        return import_module("." + name, __name__)
    if name in ("socket", "tempfile", "time", "uuid"):
        return import_module(name)
    if name not in __all__:
        raise AttributeError("module %r has no attribute %r" % (__name__, name))
    return getattr(import_module(".commands", __name__), name)
