# Decision record

The append-only record of accepted product decisions for the tæma v2 line. Reviews,
commits, issues, and ADRs cite these ids (for example "per D10") so every change rests on
an explicit decision.

Rules for this record:

- It is append-only. A row is never edited in place; when a decision changes, a new row
  with a fresh id supersedes the old one, and the superseding row says so explicitly.
- D1–D18 are reproduced unchanged from spec issue #1, where they were accepted as the
  decomposition of the spec into tickets.
- D19 onward were added while breaking issue #1 into tickets; further questions raised
  during implementation are appended as D22 and onward, with the milestone that needs the
  answer.
- Architectural decisions with their context, options considered, and consequences live
  separately in `docs/adr/`.

| Id | Decision |
|---|---|
| D1 | `adopt` contains/deprioritizes/learns/asks/reclaims and honors binding; learning authority defaults to `answered`. |
| D2 | Remove unlearned idle stops from `auto`; leftover expiry defaults off. |
| D3 | Soft memory management defaults on in `adopt`/`auto`; hard limits require explicit unit opt-in. |
| D4 | SIGKILL is restricted to explicitly answered pairs; learned/probation stops are SIGTERM-only. |
| D5 | `learn.remember_argv=false`; restore requires opt-in. |
| D6 | Curses first; web optional in M7 or later; Textual deferred. |
| D7 | “v2” is the product line; packages progress from 0.3.0 to 1.0.0. |
| D8 | `auto` collects eligible idle shared/unit scopes; `adopt` reviews them. |
| D9 | Runtime identity is cgroup/socket-first; CLI probing requires `mem.probe=true`, default false. |
| D10 | Freezing in `adopt` defaults off; revisit after M7 evidence. |
| D11 | Last-window policy defaults to ask for every app; no curated tray list. |
| D12 | Rust helper/fast clients/optional eventd now; core port only through G-Core. |
| D13 | Eventd is optional and disabled by default. |
| D14 | Titles and argv/cwd are not stored by default. |
| D15 | DMS widget maintained in-tree and released with the core. |
| D16 | Notifications default on with an agent/action-capable server, subject to caps and user choice. |
| D17 | Python floor remains 3.11; test current Void Python too. |
| D18 | Focus boost off normally, on only in the focus profile. |
| D19 | Freezing works without the session agent. When no window backend is connected, a member connected to the compositor or X server socket counts as having an open window. |
| D20 | Once native components land, packages are built only for x86_64 glibc and x86_64 musl. |
| D21 | There is no 30-day dogfood gate; releases are verified with automated VM, replay, and benchmark evidence. Supersedes the 30-day dogfood gate in issue #1's testing decisions and completion criteria. |
