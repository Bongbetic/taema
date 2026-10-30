# tæma bar widget (quickshell)

A pill showing tæma's state with a popup for acting on it. It consumes
`taema bar --follow --format json`, one JSON object per line, and every
action runs the existing CLI: `answer`, `hold`, `resume`, `snooze`,
`profile`, `agent`, and `dash` in a terminal.

The pill shows the bar text (`tæma ⟲2 ❄1 ↓3 9.3G`) with a border color
for the class: ok, review, pressure, hold, or error. The popup shows
mode, profile, reviews, frozen count, memory freed today, and pressure;
reviews carry Stop, Keep, and Never buttons; Hold/Resume, Snooze 1h, a
profile switcher, a Start agent button (only when no agent is up), and
Open dashboard.

## Standalone

```sh
quickshell -p taema/widgets/taema-bar
```

`TAEMA_BIN` overrides the `taema` executable path.

## DankMaterialShell

Copy `TaemaBar.qml` and `TaemaPopup.qml` into your shell (for example
`~/.config/quickshell/taema/`), feed the pill the parsed stream, and
anchor the popup to it:

```qml
TaemaBar {
    barState: taemaState // parsed `taema bar --format json` line
    onToggled: taemaPopup.visible = !taemaPopup.visible
}
```

See `shell.qml` for the stream wiring (`Process` + `SplitParser`) and
the popup anchor.

## Recorded feed

`feed.json` holds three recorded `bar --format json` lines. Replay them
to exercise the widget without a daemon:

```sh
TAEMA_BAR_FEED=taema/widgets/taema-bar/feed.json quickshell -p taema/widgets/taema-bar
```

In feed mode the shell shows the popup once, prints `TAEMA_WIDGET_OK`,
and quits; the suite's `WidgetLoadTest` asserts that load has no QML
errors.
