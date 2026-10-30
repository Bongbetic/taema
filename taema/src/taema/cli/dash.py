"""Curses dashboard over the shared view model.

Every action dispatches through the same ``taema ...`` argv parsing as the
CLI, so the dashboard refuses exactly as the CLI does (vetoes, mode gates).
Without curses (or without a terminal) ``main`` falls back to ``watch``.
"""

import io
import queue
import sys
import threading
from contextlib import redirect_stderr, redirect_stdout
from types import SimpleNamespace

REFRESH_MS = 2000


def _registered():
    from .registry import COMMANDS

    names = set()
    for spec in COMMANDS:
        names.add(spec["name"])
        for child in spec.get("children", ()):
            names.add(child["name"])
    return names


def key_help():
    """Key table; governor keys appear only for registered commands."""
    registered = _registered()
    keys = {
        "j": "move down",
        "k": "move up",
        "enter": "why (explain selection)",
        "s": "stop selection (confirm shows veto/edge/memory facts)",
        "n": "veto selection (do-not-kill)",
        "u": "undo latest automatic action",
        "a": "answer a review",
        "f": "filter scopes",
        "/": "search events",
        "?": "help",
        "q": "quit",
    }
    governors = (
        ("R", "reclaim", "reclaim page cache from selection (memory reclaim)"),
        ("Z", "freeze", "freeze selection"),
        ("T", "thaw", "thaw selection"),
        ("P", "profile", "switch profile"),
        ("G", "gc", "GC dry run"),
    )
    for key, command, text in governors:
        if command in registered:
            keys[key] = text
    return keys


def run_action(argv, base):
    """Run one CLI argv exactly as the CLI would; return (code, text)."""
    from . import commands

    full = list(argv)
    socket = getattr(base, "socket", None)
    config = getattr(base, "config", None)
    if socket:
        full += ["--socket", socket]
    if config:
        full += ["--config", config]
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            code = commands.main(full)
        except SystemExit as exit:
            code = exit.code if isinstance(exit.code, int) else 1
    return (code or 0), out.getvalue() + err.getvalue()


def stop_preview(name, base):
    """Confirmation text for stopping a scope: dry-run facts plus veto/memory."""
    from . import commands

    code, text = run_action(["kill", name, "--dry-run"], base)
    edges = [
        line.strip()
        for line in text.splitlines()
        if "outside users" in line or "edge" in line.lower()
    ]
    if code == 4:
        veto = next(
            (line.strip() for line in text.splitlines() if line.strip()),
            "vetoed",
        )
        edge_text = "not evaluated (vetoed)"
    else:
        veto = "none"
        edge_text = "; ".join(edges) if edges else "none"
    try:
        model = commands.dash_snapshot(base)
    except (OSError, ValueError):
        memory_text = "unavailable"
    else:
        row = next(
            (
                scope
                for scope in model.get("scopes", [])
                if scope.get("name", "").endswith(name)
            ),
            None,
        )
        if row is None:
            memory_text = "scope not listed"
        else:
            memory = row.get("memory_bytes")
            memory_text = "%s procs=%s" % (
                "-" if memory is None else _mem(memory),
                row.get("procs", row.get("processes", 0)),
            )
    return "stop %s -- confirm\nveto: %s\nedge: %s\nmemory: %s\n%s" % (
        name,
        veto,
        edge_text,
        memory_text,
        text,
    )


def _mem(value):
    amount = float(value)
    for unit in ("B", "K", "M", "G", "T"):
        if amount < 1024 or unit == "T":
            return "%d" % amount if unit == "B" else "%.1f%s" % (amount, unit)
        amount /= 1024.0
    return "%dT" % amount


class EventPump(threading.Thread):
    """Drain the daemon subscription stream into a queue in the background."""

    daemon = True

    def __init__(self, cfg, since_seq):
        super().__init__(name="taema-dash-pump")
        self._cfg = cfg
        self._since = since_seq
        self._items = queue.Queue()
        self._stop = threading.Event()

    def run(self):
        from . import commands
        from .. import events as event_views

        try:
            for item in commands.subscribe(self._cfg, event_views.TOPICS, self._since):
                if self._stop.is_set():
                    return
                self._items.put(item)
        except OSError:
            self._items.put({"error": "subscription failed"})

    def drain(self):
        items = []
        try:
            while True:
                items.append(self._items.get_nowait())
        except queue.Empty:
            pass
        return items

    def stop(self):
        self._stop.set()


_MISSING = object()


def main(args, curses_module=_MISSING):
    """Run the dashboard, or fall back to ``watch --plain`` without curses."""
    from . import commands

    if curses_module is _MISSING:
        try:
            import curses as curses_module
        except ImportError:
            curses_module = None
    if curses_module is None or not sys.stdout.isatty():
        watch_args = SimpleNamespace(
            socket=getattr(args, "socket", None),
            config=getattr(args, "config", None),
            plain=True,
            wide=getattr(args, "wide", False),
            json=False,
            jsonl=False,
            event=None,
        )
        return commands.cmd_watch(watch_args)
    curses_module.wrapper(run_screen, args)
    return 0


def run_screen(screen, args):
    """Curses main loop; ``screen`` is the stdscr window (injectable)."""
    state = {
        "selected": 0,
        "filter": "",
        "search": "",
        "message": "",
        "model": None,
    }
    pump = _start_pump(args)
    live_events = []
    try:
        screen.timeout(REFRESH_MS)
        while True:
            state["model"] = _refresh(args, state)
            if pump is not None:
                for item in pump.drain():
                    if "error" in item:
                        state["message"] = "daemon: %s" % item["error"]
                    elif isinstance(item.get("event"), dict):
                        live_events.append(item["event"])
            _draw(screen, args, state, live_events[-50:])
            key = screen.getch()
            if key == -1:
                continue
            if _handle_key(screen, args, state, live_events, key) == "quit":
                return
    finally:
        if pump is not None:
            pump.stop()


def _start_pump(args):
    from . import commands

    try:
        cfg, store, _units = commands._load_events(args)
    except (OSError, ValueError):
        return None
    try:
        since = store.events_since(0, limit=1)["latest_seq"]
    except (OSError, ValueError):
        since = 0
    pump = EventPump(cfg, since)
    pump.start()
    return pump


def _refresh(args, state):
    from . import commands

    try:
        return commands.dash_snapshot(args)
    except (OSError, ValueError) as error:
        state["message"] = str(error)
        return state["model"]


def _visible_scopes(model, state):
    rows = list((model or {}).get("scopes") or [])
    needle = state["filter"].lower()
    if needle:
        rows = [row for row in rows if needle in str(row.get("name", "")).lower()]
    return rows


def _selected_name(state):
    rows = _visible_scopes(state["model"], state)
    if not rows:
        return None
    state["selected"] = max(0, min(state["selected"], len(rows) - 1))
    return rows[state["selected"]].get("name")


def _draw(screen, args, state, live_events):
    height, width = screen.getmaxyx()
    width = max(20, width)
    model = state["model"] or {}
    screen.erase()
    header = "taema dash  scopes=%d daemon=%s  [?]help [q]uit" % (
        len(model.get("scopes") or []),
        model.get("daemon", "?"),
    )
    screen.addstr(0, 0, header[:width])
    rows = _visible_scopes(model, state)
    line = 1
    for index, row in enumerate(rows[: max(0, height - 8)]):
        marker = ">" if index == state["selected"] else " "
        memory = row.get("memory_bytes")
        windows = row.get("windows") or {}
        if windows.get("count"):
            win = " win=%s" % ("F" if windows.get("focused") else windows["count"])
        else:
            win = ""
        text = "%s %s procs=%s mem=%s%s%s" % (
            marker,
            row.get("name", "?"),
            row.get("procs", row.get("processes", 0)),
            "-" if memory is None else _mem(memory),
            " frozen" if row.get("frozen") else "",
            win,
        )
        screen.addstr(line, 0, text[:width])
        line += 1
    learned = model.get("learned") or {}
    screen.addstr(
        line,
        0,
        ("learned apps=%d pairs=%d signatures=%d  reviews=%d")
        % (
            len(learned.get("apps") or []),
            len(learned.get("pairs") or []),
            len(learned.get("signatures") or []),
            len(model.get("reviews") or []),
        )[:width],
    )
    line += 1
    events = list(model.get("events") or [])
    needle = state["search"].lower()
    for raw in live_events:
        events.append(
            {
                "seq": raw.get("seq", "?"),
                "event": raw.get("event", "unknown"),
                "scope": raw.get("scope", ""),
            }
        )
    if needle:
        events = [item for item in events if needle in repr(item).lower()]
    for item in events[-(max(1, height - line - 1)) :]:
        text = "  #%s %s %s" % (
            item.get("seq", "?"),
            item.get("event", "unknown"),
            item.get("scope") or "",
        )
        screen.addstr(line, 0, text[:width].rstrip()[:width])
        line += 1
        if line >= height - 1:
            break
    footer = state["message"] or "j/k move  enter why  s stop  n veto  u undo"
    screen.addstr(height - 1, 0, footer[:width])
    screen.refresh()


def _handle_key(screen, args, state, live_events, key):
    if key in (ord("q"), ord("Q")):
        return "quit"
    if key in (ord("j"),):
        state["selected"] += 1
        state["message"] = ""
    elif key in (ord("k"),):
        state["selected"] = max(0, state["selected"] - 1)
        state["message"] = ""
    elif key in (ord("?"),):
        _overlay(screen, "keys", _help_lines())
    elif key in (ord("f"),):
        state["filter"] = _prompt(screen, "filter scopes: ", state["filter"])
        state["selected"] = 0
    elif key in (ord("/"),):
        state["search"] = _prompt(screen, "search events: ", state["search"])
    elif key in (10, 13):
        name = _selected_name(state)
        if name is None:
            state["message"] = "no scope selected"
        else:
            code, text = run_action(["explain", name], args)
            _overlay(screen, "why %s" % name, text.splitlines() or ["(no output)"])
            state["message"] = "why exited %d" % code
    elif key in (ord("s"),):
        _stop_flow(screen, args, state)
    elif key in (ord("n"),):
        name = _selected_name(state)
        if name is None:
            state["message"] = "no scope selected"
        else:
            code, text = run_action(["do-not-kill", "--scope", name], args)
            state["message"] = _one_line(text) or ("veto exited %d" % code)
    elif key in (ord("u"),):
        code, text = run_action(["undo"], args)
        state["message"] = _one_line(text) or ("undo exited %d" % code)
    elif key in (ord("a"),):
        identifier = _prompt(screen, "review id: ", "")
        if identifier:
            choice = _prompt(screen, "choice (stop/keep/standalone/never): ", "")
            if choice:
                code, text = run_action(["answer", identifier, choice], args)
                state["message"] = _one_line(text) or ("answer exited %d" % code)
    elif key in (ord("R"),):
        name = _selected_name(state)
        if name is None:
            state["message"] = "no scope selected"
        else:
            code, text = run_action(["memory", "reclaim", name], args)
            state["message"] = _one_line(text) or ("reclaim exited %d" % code)
    elif key in (ord("Z"),):
        name = _selected_name(state)
        if name is None:
            state["message"] = "no scope selected"
        else:
            code, text = run_action(["freeze", name], args)
            state["message"] = _one_line(text) or ("freeze exited %d" % code)
    elif key in (ord("T"),):
        name = _selected_name(state)
        if name is None:
            state["message"] = "no scope selected"
        else:
            code, text = run_action(["thaw", name], args)
            state["message"] = _one_line(text) or ("thaw exited %d" % code)
    elif key in (ord("P"),):
        profile = _prompt(screen, "profile: ", "")
        if profile:
            code, text = run_action(["profile", profile], args)
            state["message"] = _one_line(text) or ("profile exited %d" % code)
    elif key in (ord("G"),):
        code, text = run_action(["gc", "--dry-run"], args)
        state["message"] = _one_line(text) or ("gc exited %d" % code)
    return None


def _stop_flow(screen, args, state):
    name = _selected_name(state)
    if name is None:
        state["message"] = "no scope selected"
        return
    preview = stop_preview(name, args)
    lines = preview.splitlines() or [""]
    if _overlay(screen, "stop %s -- confirm [y/N]" % name, lines) not in (
        ord("y"),
        ord("Y"),
    ):
        state["message"] = "stop cancelled"
        return
    code, text = run_action(["kill", name], args)
    state["message"] = _one_line(text) or ("stop exited %d" % code)


def _help_lines():
    return ["%s: %s" % (key, text) for key, text in sorted(key_help().items())]


def _one_line(text):
    for line in text.splitlines():
        if line.strip():
            return line.strip()[:200]
    return ""


def _overlay(screen, title, lines):
    height, width = screen.getmaxyx()
    width = max(20, width)
    screen.erase()
    screen.addstr(0, 0, title[:width])
    for index, line in enumerate(lines[: max(0, height - 2)]):
        screen.addstr(index + 1, 0, str(line)[:width])
    screen.refresh()
    return screen.getch()


def _prompt(screen, label, initial):
    height, width = screen.getmaxyx()
    width = max(20, width)
    value = list(initial)
    while True:
        screen.addstr(height - 1, 0, (label + "".join(value))[:width])
        screen.refresh()
        key = screen.getch()
        if key in (10, 13):
            return "".join(value)
        if key == 27:
            return initial
        if key in (8, 127, 263):
            if value:
                value.pop()
        elif 32 <= key <= 126:
            value.append(chr(key))
