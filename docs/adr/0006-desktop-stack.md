# ADR-0006: Desktop stack — notify-send first, niri windows first, curses first

- Status: Accepted
- Date: 2026-10-19
- Source: spec issue #1 §6; `taema-v2.md` §11.8
- Related decisions: D6 (curses first, web optional in M7 or later, Textual deferred), D15 (DMS widget in-tree), D16 (notifications default on), D11 (last-window policy defaults to ask)

## Context

The daemon must stay off the session bus and off any mandatory desktop dependency: headless
and terminal-only installs are first-class, and 0.2.1 has no desktop integration at all.
The v2 line adds notifications, window tracking, a status widget, and a curses dashboard,
but Void packaging has no "recommends" mechanism, desktop Python libraries would become
hard dependencies, and implementing every compositor at once would multiply maintenance on
untested code paths. Niri is the reference compositor for this project, so window work can
start there without pretending other backends are release gates.

## Options considered

| Area | Options | Verdict |
|---|---|---|
| Notifications | `notify-send -A` only; `python3-jeepney` as a hard D-Bus client; a custom gdbus wrapper | **Accepted:** `notify-send -A` default, jeepney as an optional richer backend, gdbus as one-way fallback — no mandatory desktop Python dependency |
| Windows | Implement niri, sway, i3, and Hyprland together; generic Wayland pid mapping; **one `WindowBackend` contract with niri first** | **Accepted:** niri first behind the contract; others are follow-ons, not release gates; generic Wayland pid mapping is not a planned requirement |
| Widget | External widget project; in-tree QML plugin; none | **Accepted:** in-tree QML plugin for DMS and quickshell under `contrib/dms/`, an example/contrib artifact released with the core (D15); waybar/i3bar JSON comes from `taema bar` |
| TUI | stdlib `curses`; **Textual**; `ratatui` | **Accepted:** `curses` as the baseline (D6); Textual deferred (about 0.3 s start-up, extra RSS, and a second UI to maintain); `ratatui` only if G-Core ports the clients |

## Decision

- One `WindowBackend` snapshot/events contract serves all compositors, with the niri
  backend first; window pids map to scopes and instances, desktop identity is retained,
  and titles are dropped by default (D14).
- Notification backends degrade in capability, never in correctness: `notify-send -A` is
  the default, jeepney validates the notification-server sender when installed, gdbus
  provides one-way fallback, and without any of them CLI reviews remain fully functional.
- The dashboard is stdlib `curses` first; the read-only web view is optional in M7 or
  later; Textual stays deferred (D6).
- The DMS/quickshell widget is maintained in-tree and released in lockstep with the core
  (D15), fed by the `taema bar --follow` stream.
- Loss of the agent or any backend degrades to process-only behavior without blocking the
  daemon or deciding anything from stale window facts; last-window policy defaults to ask
  for every app with no curated tray list (D11).

## Consequences

- Headless installs gain nothing mandatory and lose nothing required: every desktop feature
  has a graceful no-capability path back to the CLI.
- Each new compositor backend is an isolated adapter against a fixed contract, so sway,
  i3, and Hyprland can land as community or M7 follow-ons without touching lifecycle code.
- Maintaining in-tree QML means the project owns widget code, but it guarantees the widget
  ships with the core instead of drifting externally.
- Deferring Textual avoids a second maintained UI; the curses baseline constrains visual
  ambition until G-Core potentially brings `ratatui`.
- Notification defaults (caps, quiet hours, batching) remain user-visible configuration,
  and the notify-send/jeepney/gdbus matrix must be covered by scripted notifier tests.
