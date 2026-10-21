# tæma v2 — autonomous cleanup, resource governance, desktop integration, and observability

> **Status:** design proposal, **revision 2.1** (2026-10-19): revision 2 plus the decisions accepted in §22. This document changes no code.
> **Baseline:** tæma 0.2.1 (`10b7264`), 331 tests passing. Verified on Void Linux, kernel 7.2.11, Python 3.14.8, niri + DankMaterialShell.
> **Scope:** the whole product: learner, resource governor, desktop and session integration, commands and dashboard, quality of life, technology stack, packaging, migration. Stack changes are in scope and are decided in §11.
> **Companion docs:** `taema/README.md` and `taema/docs/design.md` describe 0.2.x behaviour. This document describes what changes, why, and in what order.
> **Reading order:** §0 summary · §1–§2 current state and diagnosis · §3–§5 vision, rules, authority · §6–§10 features · §11 technology stack · §12–§16 specifications · §17 delivery plan · §18–§22 quality, metrics, risks, compatibility, decisions · appendices.

---

## 0. Executive summary

tæma is a per-user cgroup v2 scope manager for Void Linux and runit. It gives each app and
everything the app spawns its own cgroup leaf. It detects when a member is still used by an
outside process, and it stops what an app left behind when that app closes. It runs
unprivileged, with one small sudo helper for the one step that needs root: moving a process
out of the login-session cgroup.

The 0.2.x design is sound, but the product does not do its job in the mode most people run.
In `adopt` it only moves apps that have a hand-written unit. It never contains or reviews
what a GUI app leaves behind, and it ignores explicit owner binding (`--bind`, `--owner`,
`binds_to`): all 47 owner exits in the live log became `would_stop`. The learner gets almost
no evidence: 17 of 18 learned pairs have zero weight, and the only rule with authority is
attached to a thread name (`MainThread`). Memory is not measured or managed at all, even
though one idle scope on this machine holds 634 MiB. The daemon cannot reach the desktop
either, and it does not know which windows are open.

**What v2 is:** a self-driving process and memory janitor for a single-user desktop without
systemd. It knows which app owns every process. It cleans up after an app once it has learned
or been told that this is safe. It prefers reversible actions (deprioritize, freeze, reclaim)
over killing. It keeps the machine responsive under memory pressure. It can always explain
itself, and one command overrules it: `taema --do-not-kill`.

The plan has six pillars:

1. **Learning v2: provenance, not process names (§6).** A durable ledger records who started
   what, what survived a close, and what happened after a stop. Survivor signatures,
   validated identities, per-pair burn-in, and an outcome loop replace name pairs. A
   first-class veto (`taema --do-not-kill`), `taema undo`, and `taema why` let the user
   correct and inspect every decision.
2. **Resource governor (§7, §5.6).** Accounting of memory, CPU, IO, and pressure per scope.
   An action ladder that goes contain → deprioritize → freeze → reclaim → stop, with
   wake-on-connect thawing. PSI-triggered pressure handling that works with earlyoom (which
   runs on this machine). `oom_score_adj` shaping so leftovers die before the app you are
   using. Units and quit detection for podman, libvirt, docker, incus, and VirtualBox, with
   save-state hooks and budget rebalancing.
3. **Commands and dashboard (§8).** A coherent verb set, JSON on every read command, a curses
   dashboard, `doctor`, `events`, and completions.
4. **Desktop and session integration (§9).** A session agent (`taema agent`) that can reach
   D-Bus and the compositor. Actionable notifications (verified: the quickshell/DMS server
   supports actions). niri window awareness, so a closed window counts as a close. Scoping at
   launch time (`taema launch`, desktop-entry wrapping). A status-bar feed and a DMS widget.
5. **Quality of life (§10).** A setup wizard, `doctor --fix`, mode and profile switching
   without `sudo sv restart`, drop-in config, fuzzy targets and pickers, unit generation from
   a running process, `top`, `tree`, `history`, `report`, `suggest`, recent and restore,
   backup and export, man pages, and `bug-report`.
6. **Technology stack (§11).** A SQLite store (stdlib, WAL) instead of JSON. Event-driven
   collectors (pidfd, cgroup events, PSI triggers, niri events, and an optional netlink proc
   connector) instead of polling. A typed and restructured Python core with JSON-Schema IPC
   v2. Rust for the components where safety or latency matters most: the root helper, the
   fast clients (hook, prompt, launch), and the optional event forwarder. CI runs on glibc
   and musl. A defined gate decides whether the daemon core is later ported to Rust.

**Delivery:** eight milestones (M0–M7), about 61–92 focused developer-days. That is roughly
3–4.5 months for one developer, or about 2–3 months for two developers working the parallel
tracks in §17. M0 is a 3–5 day safety and behaviour hotfix that alone makes `adopt` useful.
Every milestone has acceptance criteria and exit artifacts. The work breakdown is in
Appendix G.

### 0.1 What changed in revision 2

This revision is the result of a full review of revision 1 against the code and the live
desktop. The findings and what they changed:

| # | Review finding | Evidence | Change in this revision |
|---|---|---|---|
| 1 | Notifications as written could not work: the daemon has no session-bus address | `taemad-user` runs `setpriv --reset-env`; the daemon env has no `DBUS_*`, `WAYLAND_*`, or `NIRI_*`; the bus is `unix:path=/tmp/dbus-…` (dbus-run-session); `/run/user/1000/bus` does not exist | Session agent (§9.1); the daemon never talks to D-Bus |
| 2 | Close detection is slow and window-blind | adopt pass every 15 s, `MIN_AGE` 5 s; tray apps never exit; niri IPC exposes `pid` per window plus an event stream | Event collectors (§11.4), window-aware lifecycle (§9.3), launch-time scoping (§9.4) |
| 3 | Killing was the only actuator, so a cautious mode could only do nothing | `engine.stop` is the only action; `cgroup.freeze`, `cpu.idle`, `io.weight` are user-writable but unused | Reversible action ladder (§5.6), CPU and IO QoS (§7.9) |
| 4 | No OOM coordination | earlyoom runs with `-m 8 -s 8 --prefer (node\|python\|java…) --avoid (…qemu-system\|steam\|claude…)`; raising `oom_score_adj` without privilege works | Pressure guard, `oom_score_adj` shaping, earlyoom coordination (§7.10) |
| 5 | Swap is configured but compression is off | 24 GiB swapfile, zswap `N`, 15.5 GB RAM | Swap and zswap advisor (§7.11); freeze-then-reclaim |
| 6 | The stack was locked to stdlib and JSON | history, report, dashboard, and concurrent readers need queries; `sqlite3` 3.53.4 is in stdlib | SQLite store (§11.3, §13), staged stack evolution (§11) |
| 7 | Changing anything is ceremony | mode change = edit TOML + `sudo sv restart taema`; units hand-written | Hot reload, drop-ins, `taema mode`/`profile`, unit generator, setup wizard (§10) |
| 8 | Client latency is too high for prompts and bars | `taema --version`/`status` ≈ 0.09–0.10 s wall | Lazy imports and Rust fast clients (§10.10, §11.5) |
| 9 | No product framing for an implementer | the plan jumped from bugs to features | Vision, principles, personas, day-in-the-life (§3), current architecture map (§1.5), environment baseline (§1.6) |
| 10 | No security or privacy model for the new surfaces | notifications, agent, eventd, hooks, web view | §15 |
| 11 | Inconsistencies | M0 excluded `enforce` from adopt-all while the matrix included it; Appendix A differed from §5.1; one wrapped line in §6.3 | Fixed; Appendix A now mirrors §5.1 |
| 12 | Milestones did not cover stack, desktop, or QoL | five milestones, no work breakdown | M0–M7 with dependencies, parallel tracks, exit artifacts, Appendix G |

**Revision 2.1 (same day).** All 18 open questions were decided as recommended. §22 is now a
decision record (D1–D18), and the plan body was aligned with it: soft memory caps apply in
`adopt` (D3), and `[mem] probe` gates runtime CLI probing (D9). Nothing blocks M0.

### 0.2 Request → plan map

| User request | Where this plan answers it |
|---|---|
| Automatic learning of which app owns which process, and stopping it | §6 (provenance, signatures, outcome loop), §9.3 (windows as close signal), §9.4 (exact provenance at launch) |
| `taema --do-not-kill` when the system gets it wrong | §6.4 (veto), §6.5 (undo/regret), §10.7 (undo toast, countdown, recent/restore) |
| Memory management for containers and VMs on Void | §7 (accounting, budget, reclaim ladder, units), §7.10 (pressure guard) |
| GC that saves and reallocates memory after a container or VM quits | §7.5–§7.6 (save-state, quit detection, reclaim, rmdir, rebalance) |
| Easier commands | §8.1–§8.2, §10.1–§10.4 |
| Dashboard of what it has learned | §8.3–§8.4, §9.5 (widget), §10.5–§10.6 (top, history, report) |
| Fix `adopt` doing nothing | §2, §5.1, M0 in §17 |
| Quality-of-life improvements | §10 (and §9 for the desktop) |
| Tech-stack changes | §11 (ADRs, target architecture, migration path) |

---

## 1. What tæma is today (the 0.2.x contract)

**One sentence:** every managed program gets a cgroup v2 leaf; stopping the leaf stops the
whole tree, but a member that an outside process still uses is moved to `shared/` instead of
being killed.

### 1.1 Layout

```
/sys/fs/cgroup/user/<uid>/
  manager/                  the user's taema daemon, delegated by the runit service
  app-<name>/               adopted apps; may contain session-<pid>/ and job-<id>/
  app-podman-<hash>/        one per rootless podman runtime dir: pause + conmon-<pid>/
  scope-<name>/             explicit project scopes created by `taema run`
  shared/<comm>-<pid>/      members kept alive because something outside used them
  leftover/<owner>-<id>/    survivors of a closed app (auto mode only today)
```

### 1.2 Modes as documented

| Mode | README promise |
|---|---|
| `observe` | log what it would do, change nothing |
| `adopt` | give apps their own scopes; never stop anything |
| `auto` | adopt, learn, and clean up: stop only a pair you answered or strong evidence after burn-in |
| `enforce` | manual mode: stop by unit rules, GC, owner watch, logout |

### 1.3 The learner as implemented

The learner is a bounded JSON store (`~/.local/state/taema/knowledge.json`) with counters per
executable and per `(owner_key, leftover_key)` pair. `knowledge.decide()` turns a pair into
`ask | stop | keep | standalone` from explicit answers (weight 3, no decay), inferred shell
kills (weight 0.25), and a silent-stop threshold. Every decision is written to
`decisions.log` as JSON lines. There is no model and no network; that is a feature.

### 1.4 Safety rules that must survive v2

- Only the user's own processes; never root, other users, or kernel threads.
- Protected session infrastructure is never adopted or signalled.
- A scope containing the caller is never stopped.
- Learned data can only delay a kill; it cannot override a detected dependency or a hard rule.
- The root helper validates every request independently.

These are non-negotiable. The memory governor adds one: **a veto always wins**.

### 1.5 Current architecture and code map

Runtime processes (0.2.1):

```
runsv taema (root)                       sv/taema/run: delegates user/<uid>, rescans group every 60 s
└─ runsvdir /run/taema/sv
   └─ runsv <user>
      └─ taemad-user <user> (root)       moves itself to user/<uid>/manager, then setpriv --reset-env
         └─ taema daemon (uid)           all decisions and signals; single-threaded selector loop
            └─ sudo -n taema-attach      the one privileged step (move out of a session cgroup)
shell (bash/zsh/fish) ── taema-hook done|kill|ask ──▶ $XDG_RUNTIME_DIR/taema.sock (JSON lines)
taema CLI ───────────────────────────────────────────▶ same socket; read-only knowledge.json
```

Modules (`taema/src/taema`, 3,702 lines; tests 4,100 lines, 331 tests):

| Module | Lines | Responsibility | v2 fate |
|---|---|---|---|
| `cgroup.py` | 130 | delegated tree helpers: leaf create/move/rmdir, `tree_procs`, `is_prefix` self-guard | kept; gains memory/QoS/freeze helpers → `core/cgroup.py` |
| `inspect.py` | 338 | `/proc` reads, `ProcTable` snapshot, `ss` parsing, dependency edges | split: `core/proc.py`, `core/edges.py`; new edge kinds (QMP, API sockets, audio) |
| `policy.py` | 290 | config layering, hard rules, `exe_key`/`app_key` | split: `config/`, `model/identity.py`; drop-ins, validation |
| `knowledge.py` | 539 | JSON store, counters, pair `decide()`, decay, caps, feedback replay | `model/decide.py` (pure) + `store/` (SQLite) |
| `lineage.py` | 412 | live-only lineage: roots, co-birth, jobs, ptmx hosts, leftovers | `model/provenance.py` (durable instances + signatures) |
| `engine.py` | 665 | `plan_stop`/`stop`, adopt/carve plans, GC candidates, auto authority | `daemon/authorize.py` (one ladder) + `governor/` actuators |
| `daemon.py` | 997 | loop, owner watch, adopt/GC passes, jobs/questions, socket API | `daemon/` package: loop, collectors, api, passes |
| `cli.py` | 326 | `run kill ls explain keep forget status gc adopt daemon` | `cli/` package with registry, renderers, completions |

Main loop today: `tick()` runs the deadlines (job settle after 1.5 s, question expiry after
60 s), then `adopt_pass` every 15 s, then `gc_pass` every 60 s, then a routine save every
300 s. `adopt_pass` takes a fork-gate signature, scans `/proc` once, and calls
`lineage.observe`. It then runs `after_observe` (closes, respawns, regret, GUI close),
`adopt_plan`/`carve_plan` + `run_ops`, and `auto_adopt` in `auto`. A pidfd per owner and an
epoll on each leaf's `cgroup.events` are the only event-driven parts.

State today: `knowledge.json` (≤ 512 exes, ≤ 256 pairs, saved at most every 300 s),
`decisions.log` (JSON lines, rotates at 1 MiB), `feedback.jsonl` (CLI writes while the daemon
is down), and `$XDG_RUNTIME_DIR/taema/q.<shellpid>` question flags.

Timing constants that shape behaviour: adopt 15 s, GC 60 s, `idle_grace` 600 s, `MIN_AGE`
5 s, co-birth 2 s, job settle 1.5 s, `respawn_window` 60 s, regret window 30 min, question
TTL 60 s, 3 questions per day.

### 1.6 Environment baseline (verified 2026-10-19)

Everything below was measured on the maintainer's machine while writing revision 2. Design
choices in §7, §9, and §11 depend on these facts. `taema doctor` (§8.6) must re-check them on
every machine.

| Area | Fact | Why it matters |
|---|---|---|
| Kernel and cgroups | 7.2.11_1; root controllers `cpuset cpu io memory hugetlb pids rdma misc`; `user/1000` enables `cpuset cpu io memory pids` | memory, CPU, and IO governance are all available |
| Delegated files | `cgroup.freeze`, `memory.high`, `memory.pressure` are user rw; `memory.reclaim` is user-writable (`--w-------`); `cpu.idle`, `io.weight`, `io.bfq.weight` exist | freeze, reclaim, and QoS need no new privilege |
| PSI triggers | an unprivileged `some 150000 2000000` trigger on `app-herdr/memory.pressure` was accepted | pressure handling can be event-driven at zero idle cost |
| Memory | MemTotal 15.5 GB, MemAvailable 9.4 GB; 24 GiB swapfile; zswap **disabled**; `zramctl` present | freeze-then-reclaim works; compressed swap would make it cheap (§7.11) |
| OOM | earlyoom 1.9 running: `-r 60 -m 8 -s 8 --prefer (^\|/)(node\|python\|java\|docker\|containerd\|codex\|cline\|opencode) --avoid (^\|/)(runit\|sshd\|greetd\|niri\|Xwayland\|dbus-daemon\|elogind\|qemu-system\|steam\|gamescope\|wine\|claude\|claude-desktop)` | tæma must act before 8% and must shape `oom_score_adj`, not fight earlyoom (§7.10) |
| `oom_score_adj` | an unprivileged process raised its own value to 500 | leftovers can be made the preferred OOM victim without root; lowering needs the helper |
| Desktop | niri; quickshell + DankMaterialShell (`dms` CLI, `dms-guard`); no waybar/mako/dunst | the widget targets DMS/quickshell first (§9.5) |
| Notifications | server `quickshell 1.2`; capabilities include `actions`, `action-icons`, `persistence`, `inline-reply`, `body-markup` | actionable notifications are possible (§9.2) |
| Session bus | `DBUS_SESSION_BUS_ADDRESS=unix:path=/tmp/dbus-…`; `/run/user/1000/bus` absent; daemon env has no DBUS/WAYLAND/NIRI vars | only a session-side process can notify (§9.1) |
| Window IPC | `niri msg --json windows` returns `id, app_id, pid, title, is_focused, workspace_id, …`; `event-stream` works | windows map to scopes; closing a window is a close signal (§9.3) |
| libnotify | `notify-send` 0.8.8 with `-A/--action`, `-w`, `-p`, `-r` | zero-dependency actionable notifications |
| Runtimes | `podman`, `virsh` present; docker, incus, VirtualBox absent | podman and libvirt units are first-class; others ship as examples |
| Toolchains | Python 3.14.8, `sqlite3` 3.53.4; `rustc`/`cargo` in `~/.cargo`; Void repos carry `rust`/`cargo` 1.99, `ruff` 0.15.7, `python3-mypy` 2.1, `python3-hypothesis`, `python3-pytest-cov`, `python3-build`, `python3-jeepney` 0.9, `python3-textual` 8.2.7, `python3-rich` 15, `scdoc` 1.11.4 | every stack option in §11 can be built from official packages |
| Footprint | daemon RSS 25,124 kB after 40 min (2 s CPU); `taema --version` 0.093–0.102 s, `taema status` 0.092 s | sets the baselines for §10.10 and gate G-Core (§11.5) |
| Tools and CI | `fzf` and `pytest` installed; CI runs in `ghcr.io/void-linux/void-glibc:latest` | picker integration; CI matrix (§11.9) |

---

## 2. Diagnosis: why `adopt` looks dead, and why the learner does not learn

This section is based on the 0.2.1 source, the tests, and a live snapshot of the maintainer's
machine, where the daemon has been running in `adopt` mode for days. The live numbers are in
Appendix E. The short version: **`adopt` moves only apps that have a hand-written unit, moves
survivors only in `auto`, stops nothing at all, and records almost no positive evidence for the
learner.** It is not a gentler `auto`; it is a different, much smaller program.

### 2.1 The mode gates, line by line

`Daemon` has three predicates:

```python
# daemon.py:88-93
def may_move(self):   return self.mode in ("adopt", "enforce", "auto")
def may_kill(self):   return self.mode == "enforce"
def auto(self):       return self.mode == "auto"
```

Every meaningful action is behind one of them. The actual matrix is:

| Work item | Code path | `observe` | `adopt` | `auto` | `enforce` |
|---|---|---|---|---|---|
| Adopt unit-matched apps (`[match]`) | `adopt_pass` → `engine.adopt_plan` (`daemon.py:150`) | log only | **yes** | yes | yes |
| Carve child scopes (`[[children]]`) | `engine.carve_plan` | log only | **yes** | yes | yes |
| Auto-adopt arbitrary app roots | `if self.auto(): self.auto_adopt` (`daemon.py:169`) | no | **no** | yes | **no** |
| Move leftovers to `leftover/` | `gui_close`, called only under `if self.auto()` (`daemon.py:229`, `:270`) | no | **no** | yes | no |
| Adopt a survivor answered `standalone` | `adopt_standalone` (auto paths only) | no | **no** | yes | no |
| Stop an owner-bound scope (`--bind`/`--owner`) | `stop_leaf` requires `may_kill()` or `auto()` (`daemon.py:123`) | log only | **log only** | yes | yes |
| Ask a terminal-job question | `decide_job` (`daemon.py:407`) is **not** mode-gated | yes | yes | yes | yes |
| Ask a GUI-close question | **does not exist** | no | no | no | no |
| Stop by learned/answered pair | `auto_stop_path` (auto/enforce only) | no | **no** | yes | no |
| GC idle `shared/*` / unit `stop_when_unneeded` | `gc_pass` non-leftover branch (`daemon.py:689`) | log only | **log only** | **log only (bug)** | yes |
| Stop a leftover by idle rule | `gc_pass` auto branch (`daemon.py:689`) | no | no | **yes, even unlearned** | no |
| Stop by enforce rules (all unit/GC/session) | `may_kill()` | no | no | no | yes |
| Session-end stop | `end_session` (`daemon.py:752`) | log only | **log only** | pair-gated | yes |
| Remove empty leaves | `_gc_empty` (`may_move`) | no | yes | yes | yes |
| **Memory accounting / reclaim / limits** | **no such code** | no | no | no | no |

Three consequences follow directly:

1. **`adopt` does not do the core job.** It adopts only apps named by a unit in
   `/etc/taema/units` or `~/.config/taema/units`. The README says “Gives apps their own
   scopes” (`taema/README.md:243`), but an arbitrary app is left in the login cgroup. The
   Android emulator case that motivated the project is untouched unless the user writes a
   unit or launches it with `taema run`.
2. **`adopt` silently breaks a user's explicit request.** `taema run --bind` and `--owner`
   register a pidfd watch, and when the owner exits `stop_leaf` logs `would_stop` and returns.
   In the live log there are 47 `would_stop` events, and all 47 are owner exits (checked by
   reason). They include `app-claude-desktop/cowork-vm-3398`, a VM child scope that the user's own
   unit binds to its root (`binds_to = "root"`).
   That is not a documented “never stop”; it is a broken contract for an explicit flag.
3. **`adopt` has side effects but no payoff.** It moves processes into scopes (91 `adopt`
   events live), carves child scopes, and then leaves the memory and the survivors exactly
   where they were. Worse, it keeps finding the same idle scopes: 1,176 `gc_would_stop` log
   lines for three podman scopes in the live log, because the dry “would” path is not
   deduplicated (unlike `adopt_would`, which uses `store.changed`).

### 2.2 The learner is starved by the same gates

`knowledge.decide()` (`knowledge.py:45`) needs evidence. Here is where evidence can come from:

| Evidence | Written by | Effect | Available in `adopt`? |
|---|---|---|---|
| Explicit answer in the prompt | `Store.answer` (`knowledge.py:364`) | `ex_stop/ex_keep +3`, no decay | Only for terminal jobs (`decide_job` asks); never for GUI closes |
| Inferred manual kill in a shell | `observe_kill_inferred` (`knowledge.py:398`) | `stop +0.25`, `kills +1`, day recorded | Yes, if the user types `kill` in a hooked shell |
| Leftover observed after a close | `observe_close` (`knowledge.py:385`) | `closes +1`, **weight 0** | Yes, for roots lineage saw exit; the pair is created with zero authority |
| Launcher flag | `observe_close(launcher=True)` | `launches +1`; decision `keep` when there are no kills | Yes |
| Stopped key came back | `respawn` / `gc_outcome` | exe `respawned`, idle-grace scale | Only when a stop happens |
| Automatic stop happened | `auto_stopped` (`knowledge.py:418`) | `last_auto_stop` | **No** (no auto stops) |
| Regret (relaunch within 30 min) | `regret` (`knowledge.py:422`) | `keep +3`, suspend 7 days | **No** |
| Shared member moved aside | `engine.stop` | exe `shared_hits +1` | **No** (no stops) |
| Graceful-exit timing | `engine.stop` | `term_exit_ms` history | **No** (no stops) |
| **The system's own stop succeeded** | **missing** | — | — |
| `taema keep EXE` | `cli.cmd_keep` (`cli.py:206`) | exe `user_keep +3` | Yes, but exe-level only; not a pair decision |

In `adopt` mode the only non-zero pair evidence available is an explicit answer for a terminal
job, or a manual `kill` typed in a hooked shell. GUI closes — the main event — produce a pair
with `closes` and nothing else, and there is no question to answer. The live store proves it:

- 18 pairs, 20 closes.
- 17 pairs have `stop == keep == ex_stop == ex_keep == 0`; they will answer `ask` forever.
- 1 answer exists: `MainThread > sh/sort/head` (`ex_stop = 3`). The owner is a thread name,
  not an application. The only rule with authority in `adopt` is therefore **wrong**.
- `exes` is empty: every per-exe counter is zero, so `enforce_caps()` dropped them.

And the silent-stop path is unreachable from the system's own actions:

```python
# knowledge.decide, silent stop requires:
if kills >= SILENT_KILLS and days >= SILENT_DAYS and ratio >= SILENT_RATIO and quiet and old and burn:
```

`kills` is only incremented by `observe_kill_inferred` (the user manually killing a process in
a hooked shell). It is **not** incremented by an automatic stop, a question answer, an
`enforce` stop, or a `taema kill`. So a GUI app whose leftovers tæma stops correctly every
time can never teach the silent path. The only route to “learned” is the user manually killing
leftovers five times on three days, after a seven-day burn-in. That is not an automatic
learning system.

### 2.3 The `auto` mode also has a hidden guess

The README says “It never guesses about stopping” and “stops only what you told it to”. The
code is more aggressive. `gc_candidates(auto=True)` includes `leftover/*`; `_leftover_verdict`
(`engine.py:528`) returns `held` only when a pair is decided `keep`. If the pair is `ask`, it
returns `idle`, the leaf starts an idle timer, and after `idle_grace` `gc_pass` calls
`auto_stop_path(..., require_pair=False)`. That path checks edges, protection, pty and CPU,
but **not** pair authority, and stops the scope. `tests/test_phase4.py:test_idle_for_learned_grace_then_stop`
pins this behaviour.

This is the wrong-kill vector that makes a veto necessary. v2 removes it: an unlearned
leftover is contained, surfaced in the review queue, and kept. A pair must be answered or
learned before an automatic stop.

The same `auto_leaf` condition (`leaf.startswith("leftover/")`) has a second, opposite bug:
`shared/*` leaves and unit-declared `stop_when_unneeded` scopes are never stopped in `auto`.
`gc_pass` only logs `gc_would_stop` for them, because `auto_leaf` is false and `may_kill()` is
`enforce`-only. The README's StopWhenUnneeded promise is therefore implemented only in
`enforce`: an idle podman pause scope, or an idle `stop_when_unneeded` app, lives forever in
`auto`. The live log's 1,176 `gc_would_stop` lines for three podman scopes show the same branch:
in `adopt` they are expected (nothing is stopped), but in `auto` that branch is a bug. v2
makes the shared/unit branch stop in `auto` after the idle checks, with veto and hold applied.

### 2.4 Attribution is noisy because identity is a basename

`policy.app_key()` (`policy.py:255`) is clever for interpreters (`node:vite.js`,
`python3:http.server`, `java:app.jar`) but falls back to `comm` when the process renamed
itself. Live examples:

| Learned pair | What it should have been | Why it happened |
|---|---|---|
| `MainThread > sh`, `MainThread > sort`, `MainThread > head` | the Java/Gradle app that owns the thread | `comm` is a thread name; it passed the “process title” branch |
| `2.1.300 > wl-copy` | a clipboard manager / the app that called it | `comm` is a version string |
| `sleep > bash`, `sleep > qemu-system-x86_64-headless`, `sleep > virt-manager` | the command that was run (or nothing) | `job_info.root_key` is the first tagged process; a `sleep` wrapper becomes the “owner” |
| `bash > podman`, `bash > conformance` | the shell job, not `bash` itself | the job root was a shell because the real command had already exited |

The deeper problem is structural: `lineage.py` keeps live-only entries. The durable store has
no parent→child history, no application instance, no survivor signature. After a process
exits, the only memory is `(owner_key, leftover_key)` plus counters. That is not enough to
answer “which application is linked to which parent process”, and it is why the plan's first
feature is a provenance ledger, not a better threshold.

Other learning defects worth fixing while we are here:

- **Burn-in is global, not per pair.** `decide()` receives `created` (store creation) and
  `closes` (store total) from `pair_decision` (`knowledge.py:445`). A pair created yesterday
  can become “silent stop” because the store is old and busy.
- **Regret is keyed by leftover only.** `Daemon.auto_recent` is `leftover key -> (owner, ts)`
  (`daemon.py:75`); a second owner overwrites the first. Any relaunch of that binary within
  30 minutes is treated as regret for the wrong pair.
- **`default_action` and pairs use different keys.** `engine.plan_stop` uses `policy.exe_key`
  (`node`), while pairs use `policy.app_key` (`node:vite.js`). `taema keep node` cannot
  express “keep vite”, and pair evidence cannot influence a stop plan.
- **Launcher pairs are still stored.** A short job sets `launches += 1` but still creates a
  pair with `closes`. Live has many `sleep` pairs; they are noise.
- **One bad answer poisons the pair.** The only live answer is attached to `MainThread`; v2
  must refuse to bind answers to generic identities and ask a provenance-backed candidate
  question instead.

### 2.5 Memory is completely unmanaged

`grep -ri 'memory\|reclaim\|pressure\|swap' taema/src` returns nothing. The service enables
the `memory` controller on `/sys/fs/cgroup/user/<uid>` (`taema/sv/taema/run`), so the kernel
exposes `memory.current`, `memory.peak`, `memory.stat`, `memory.events`, `memory.pressure`,
`memory.reclaim`, `memory.swap.*`, and `memory.zswap.*` in each leaf. On the live machine:

```
/sys/fs/cgroup/user/1000/cgroup.subtree_control   -> cpuset cpu io memory pids
/sys/fs/cgroup/user/1000/memory.current           -> 694,620,160   (~663 MiB)
/sys/fs/cgroup/user/1000/app-herdr/memory.current -> 664,375,296   (~634 MiB)
/sys/fs/cgroup/user/1000/app-herdr/memory.stat    -> anon 562,335,744; file 73,089,024; kernel 27,594,752
memory.reclaim, memory.pressure, memory.peak, memory.zswap.* all present
```

One idle adopted app holds 95% of the user's accounted memory. tæma cannot see it, cannot
reclaim its page cache, cannot cap it, and cannot report it. The GC's only inputs are process
edges and `cpu.stat`; it has no memory or pressure input at all.

Container/VM support is one podman unit. There is no unit for libvirt/QEMU, docker/containerd,
incus/lxc, VirtualBox, or a generic “container/VM” class. The podman unit has a good idea
(`env_dir_missing` = the runtime directory is gone, `keep_while_children` = conmon is a
container) but it only stops in `enforce`; in `adopt` it is a `gc_would_stop` line repeated
hundreds of times.

Two hierarchy facts matter for the design:

- A cgroup that holds processes cannot enable a controller in its own
  `cgroup.subtree_control` (the no-internal-process rule). Child scopes such as
  `app-x/session-<pid>` therefore have no `memory.*` files while `app-x` holds processes.
  v2 uses **aggregate accounting at the app scope** first, and an optional layout v2 later if
  per-child accounting is needed.
- Writing `memory.high`/`memory.max` in a leaf is unprivileged because the user owns the
  delegated subtree. No helper change is required for memory.

### 2.6 UX and operations

Today's command surface is `run, kill, ls, explain, keep, forget, status, gc, adopt, daemon`.
It is a good start, but:

- `status` prints a JSON blob plus a pair table; there is no memory column, no provenance, no
  review queue, no event feed, no dashboard.
- `keep` bumps an exe counter in a **read-only local store** (`cli.py:206`) and queues feedback;
  it does not express “never kill this pair”, and it does not stop an in-flight stop.
- There is no `--json` on read commands, so scripting is awkward.
- `gc --dry-run` is useful, but the daemon's own `gc_would_stop` path is not deduplicated;
  the live log grew 1,176 lines from three scopes.
- Pending questions only appear at a shell prompt. A GUI close has no prompt, so it is never
  reviewed. There is no `taema review`.
- There are no shell completions.

### 2.7 Platform and product gaps

Revision 1 diagnosed the code. Revision 2 also checked the platform the code runs on, and
found gaps that no amount of tuning the learner would fix:

1. **Detection is poll-driven and slow.** A close is noticed only on the next adopt pass, up
   to 15 s later. Nothing younger than 5 s gets a root (`MIN_AGE`). A leftover can spawn,
   detach, and do its damage inside that window. An app that starts and exits within 5 s is
   never rooted at all.
2. **The daemon cannot reach the desktop.** It is started by runit with
   `setpriv --reset-env`, so it has no `DBUS_SESSION_BUS_ADDRESS`, `WAYLAND_DISPLAY`, or
   `NIRI_SOCKET`. The session bus is created by `dbus-run-session` at a random `/tmp/dbus-…`
   path, and `/run/user/<uid>/bus` does not exist. Any design that has the daemon call
   `notify-send` fails silently.
3. **The daemon is window-blind.** For a GUI app, "the user closed it" means "the last
   window closed". tæma only sees a root process exit. Tray and background apps (Electron
   apps, Claude Desktop, Discord, Steam) keep running after their window closes, so their
   helpers are never treated as leftovers, and a closed-but-running app is invisible. niri
   already publishes window→pid and close events.
4. **Killing is the only actuator.** There is no intermediate, reversible action. A cautious
   system can therefore only do nothing or kill, which is exactly why `adopt` feels inert.
   The kernel offers `cpu.idle`, `io.weight`, `cgroup.freeze`, and `memory.reclaim` in every
   delegated leaf.
5. **No QoS.** The `cpu` and `io` controllers are enabled, but tæma sets no weights. A
   leftover build daemon competes on equal terms with the focused app.
6. **No OOM coordination.** earlyoom runs with `--prefer node|python|java…`. It cannot tell
   the leftover `node` from the dev server you are using; tæma can. tæma could raise the
   leftover's `oom_score_adj` (no privilege needed) and free memory before earlyoom's 8%
   threshold.
7. **Configuration is ceremony.** Switching the mode means editing TOML and running
   `sudo sv restart taema`. Units are hand-written TOML with no generator and no validator.
   There is no onboarding and no man page.
8. **Storage cannot answer product questions.** The JSON store holds counters only.
   Questions like "what happened yesterday", "how much memory did I save this week", or
   "when did vite last get left behind" have no answer. `decisions.log` is the only history,
   and it rotates at 1 MiB.
9. **Clients are slow for always-on surfaces.** About 95 ms per CLI call is fine for a human,
   but too slow for a prompt segment, a 1 Hz bar, or a launcher wrapper that runs on every
   app start.

### 2.8 Root causes (design level)

| # | Root cause | Fix |
|---|---|---|
| R1 | Mode gates conflate *capability* (move, contain, stop, reclaim) with *authority* (who may stop). `adopt` is defined as “no stop”, so it also loses contain, review, and owner-bound stop. | Capability matrix + independent `[learn] authority`; `adopt` contains and asks, `auto` stops with authority. |
| R2 | Learning is keyed on process names and live-only lineage. | Durable provenance ledger + survivor signatures + identity validation. |
| R3 | Learning has no positive outcome signal from its own stops, and no GUI-close question. | Outcome records (`stop_ok`, `respawn`) and a review queue for GUI closes. |
| R4 | There is no resource model. | `memory.py` + `budget.py` + PSI/reclaim + container/VM units. |
| R5 | There is no feedback vocabulary for “wrong”. | Veto (`do-not-kill`), undo, review, per-pair suspension. |
| R6 | Observability is a log file and a JSON dump. | `taema why`, `memory`, `learn`, `events`, `dash`, JSON everywhere. |
| R7 | The `auto` idle rule stops unlearned leftovers, contradicting the docs. | Remove it; contain + review. |
| R8 | `auto` never stops idle `shared/*` or unit `stop_when_unneeded` scopes; only `enforce` does. | Route shared/unit GC through the same authorization ladder and stop them in `auto` (veto-aware). |
| R9 | Detection is poll-driven and window-blind. | Event collectors (§11.4), the agent's window backend (§9.3), launch-time scoping (§9.4); `/proc` polling becomes reconciliation. |
| R10 | The daemon has no presence in the user session. | `taema agent` (§9.1): a session companion with no authority. |
| R11 | The only actuator is kill. | The action ladder: contain → deprioritize → freeze → reclaim → stop (§5.6). |
| R12 | The store has no history and no query model. | SQLite with retention and rollups (§13). |
| R13 | Configuration and unit authoring are manual. | Hot reload, drop-ins, `mode`/`profile` commands, unit generator, setup wizard (§10). |

---

## 3. Product vision, users, and target experience

### 3.1 What we are building

A **self-driving process and memory janitor** for a single-user Linux desktop without
systemd. It knows which app owns every process. It cleans up what an app leaves behind once
it has learned, or been told, that this is safe. It keeps the machine responsive under memory
pressure, and it treats containers and VMs as first-class citizens. It is quiet when things
are fine, it explains itself when asked, and one command (`taema --do-not-kill`) or one click
overrules it.

### 3.2 Product principles

These principles decide trade-offs when a section below is unclear:

1. **Earned autonomy.** Start cautious. Gain authority from explicit answers and observed
   outcomes, per app and per survivor set, never globally.
2. **Reversible before destructive.** Deprioritize, then freeze, then reclaim, and stop
   only last. Every stage can be undone except the final stop, and even that can be relaunched
   when the user opts in.
3. **One-step overrule.** Any automatic action can be vetoed or undone with one command, one
   key in the dashboard, or one notification button.
4. **Explain everything.** Every action has a decision id, inputs, and a human sentence
   (`taema why`).
5. **Quiet by default.** Batch, rate-limit, and summarize. A question is a cost to the user,
   so spend it only where the answer teaches something reusable.
6. **Local, deterministic, private.** No network, no model, no telemetry. Window titles and
   command lines are not stored unless the user opts in.
7. **Cheap.** An idle daemon must cost less than the leftovers it removes: ≤ 30 MB RSS and
   ≤ 0.2% of one core.
8. **Works without the desktop.** The agent, widget, and notifications are additive. Without
   them, tæma still works on a tty, over ssh, or on a headless box.

### 3.3 Users and jobs to be done

| Persona | Situation (this machine as reference) | Job to be done | What v2 gives them |
|---|---|---|---|
| **P1 Developer** | IDE, terminals, `vite`/`esbuild`, Gradle and Kotlin daemons, Android emulator (`qemu-system-x86_64`) | "When I close the project, give me my RAM back without breaking the adb server I still use." | provenance + signatures, contain/deprioritize/freeze, `keep adb` as a shared helper, project scopes |
| **P2 Container/VM user** | rootless podman, libvirt (`virsh`), pause processes whose runtime dir is gone | "Idle VMs and dead pause processes should not hold gigabytes." | quit detection, save-state hooks, reclaim, budget rebalance |
| **P3 Desktop user** | niri + DMS, GUI apps with tray modes | "Closing the window should mean closing the app, unless it is a tray app I want." | window-aware lifecycle, actionable notifications, widget |
| **P4 Gamer / low RAM** | earlyoom avoids `steam`, `gamescope`, `wine`; 15.5 GB RAM | "While I play, freeze the background and never let OOM hit the game." | `game` profile, pressure guard, `oom_score_adj` shaping |
| **P5 Maintainer / tinkerer** | edits units, reads logs | "Show me what it learned, let me edit it, and let me move it to my laptop." | `why`, `learn`, `history`, unit generator, export/import, SQLite |

### 3.4 A day with tæma v2 (target experience)

| Time | What happens | Feature |
|---|---|---|
| 09:00 | Login. niri's `spawn-at-startup` starts `taema agent`. The DMS widget shows `tæma · auto · 9.3G free`. | §9.1, §9.5 |
| 09:05 | VS Code starts from the launcher. Its desktop entry is wrapped, so it is born in `app-code-…` and provenance is exact. | §9.4 |
| 11:30 | The last VS Code window closes. `node:vite.js` and `esbuild` survive. They are contained in `leftover/code-…` and deprioritized at once (`cpu.idle`, `oom_score_adj +500`). | §5.6, §7.9 |
| 11:32 | Still idle, so they are frozen with wake-on-connect armed. A notification appears: "VS Code left 2 processes (812 MB) · Stop when it closes · Keep · Never". | §5.6, §9.2 |
| 11:33 | The user clicks *Stop when it closes*. The signature is answered, the scope is stopped gracefully, and a toast offers "Freed 812 MB · Undo". | §6.3, §10.7 |
| next day | The same close is stopped silently once probation rules pass. The widget counter rises: "freed 2.1 GB today". | §6.7 |
| 14:00 | `gamescope` starts and the profile switches to `game`: idle leftovers and an idle VM are frozen and reclaimed, and notifications are held. | §10.2, §7.10 |
| 16:00 | virt-manager has closed and the VM has been idle for 30 min. The unit's `managedsave` hook runs, the scope is removed, 4 GB is freed, and the budget rebalances. | §7.6 |
| 16:10 | Wrong call: the user wanted a frozen `python3:http.server`. One command, `taema --do-not-kill`, thaws it, vetoes the pair, and logs a regret. | §6.4, §6.5 |
| Friday | `taema report --week` shows 9.8 GB freed, 14 automatic stops, 1 undo, and 3 suggestions. | §10.6 |

### 3.5 What "done" means for v2

v2 is done when the success metrics in §19 hold for 30 days of real use on this machine.
In short:

- every eligible app has a scope;
- every GUI close with survivors is contained and reviewed or decided;
- no automatic stop happens without authority;
- fewer than 2 in 100 automatic actions are undone;
- idle containers and VMs give back their memory;
- the daemon stays inside its footprint budget.

---

## 4. Goals, non-goals, invariants

### 4.1 Goals

- **G1 — Adopt is useful.** In `adopt`, every app root longer than 5 s gets a scope, every
  close with survivors is contained and reviewed, memory is reclaimed from idle scopes, and
  an explicit `--bind`/`--owner` stop works.
- **G2 — The learner knows provenance.** `taema why` can show the app instance, its parent
  chain, the survivor signature, the evidence, the last outcome, and the vetoes.
- **G3 — Automatic stops are earned.** No stop without an explicit answer or learned
  evidence. Own outcomes refine confidence; they do not create authority unless the user
  opts into `allow_self_authority`.
- **G4 — A veto always wins.** `taema --do-not-kill` blocks stop and reclaim at every layer,
  including a CLI kill while the daemon is down, unless `--force-veto` is explicit.
- **G5 — Memory is visible and governed.** Per-scope current/peak/stat/swap/PSI, a budget,
  safe reclaim, save-state hooks, and container/VM units.
- **G6 — One command to understand.** `taema why`, `taema ls`, `taema status --json`, and
  `taema dash` tell the same story from the same data.
- **G7 — Bounded and fast.** The daemon stays under 30 MB RSS and 0.2% CPU at idle; state
  stays bounded; every new structure has a cap.
- **G8 — Reversible.** Every automatic action has an undo path and an audit record.
- **G9 — Event-driven.** With the agent or `taema-eventd`, closes and births are noticed in
  under 1 s. Without them, within one adopt interval.
- **G10 — Present on the desktop.** Actionable notifications, a widget, and window awareness,
  without the daemon ever touching the session bus.
- **G11 — Reversible first.** Every automatic action passes through a reversible stage
  (deprioritize, freeze, or reclaim) before a stop. The only exception is a pair the user
  explicitly answered with "stop".
- **G12 — Zero ceremony.** Changing the mode or profile, and writing a unit, needs no TOML
  editing and no service restart. First-run setup takes under 2 minutes.
- **G13 — Fast clients.** `taema status` p50 < 50 ms. The prompt hook spawns no process when
  idle. The bar feed streams instead of polling. `taema launch` adds < 30 ms.
- **G14 — Maintainable stack.** A typed core, schema'd IPC and storage, CI on glibc and musl,
  and each component written in the language that fits its risk profile (§11).

### 4.2 Non-goals

- No ML model, no network, no telemetry. The learner stays deterministic and local.
- No privileged daemon. The only root step remains the `taema-attach` move.
- No hard memory limits by default. `memory.max` is opt-in per unit; `memory.high` is soft.
- No systemd dependency, and no podman/docker/libvirt client libraries. The core keeps the
  Python standard library as its only runtime dependency. Optional features may use
  packages from the official Void repositories (for example `libnotify`). Rust components are
  compiled at package build time and add no runtime dependency (§11).
- No compositor lock-in. niri is the first window backend; sway, i3, and Hyprland plug in
  behind the same interface. Without a backend, tæma works process-only.
- No graphical settings app in v2. The DMS widget is a status and actions surface, not a
  settings editor.
- No replacement for podman/docker/libvirt management. tæma observes and cleans up; it does
  not become a container runtime.
- No killing of protected session infrastructure, ever.

### 4.3 Invariants

1. Same-uid only; never pid 1, root, other users, kernel threads.
2. Protected comm/cgroup/env prefixes are never adopted, moved, signalled, or reclaimed.
3. A scope containing the caller is never stopped (`self_guard`).
4. A veto blocks stop and reclaim; `--force-veto` is the only override and is logged.
5. Unknown is never “yes”: unreadable `/proc`, failed `ss`, unknown CPU, unknown memory → keep.
6. Memory writes only to leaves the user owns; never `manager`; never a limit below
   `current + min_headroom`.
7. One writer for `state.db` (the daemon). The CLI, agent, dashboard, and widget either read it
   read-only or go through the socket. Mutations made while the daemon is down queue in
   `feedback.jsonl`.
8. Every action is logged with a `decision_id` and its inputs.
9. Bounded state: every table has a cap and a retention period (§13.4), every in-memory
   structure has a cap, and logs rotate.
10. The existing safe defaults stay safe: `observe` mutates nothing; `auto` never SIGKILLs a
    pair that was not explicitly answered.
11. The session agent has no authority. It relays answers, window facts, and launches, and
    every action is still decided by the daemon's ladder (§5.5).
12. Freeze never applies to a scope with outside edges, a pty host, protected members, a
    focused or visible window, or the agent itself. A frozen scope is always thawed before
    it is signalled for a graceful stop, so SIGTERM handlers can run.
13. `oom_score_adj` is only ever raised by the daemon, only for contained leftovers and
    shared helpers. Restoring a lower value goes through the validated root helper (§7.10).

---

## 5. Modes, authority, and the action ladder

### 5.1 Capability matrix (proposed)

| Capability | `observe` | `adopt` | `auto` | `enforce` |
|---|---|---|---|---|
| Observe lineage | yes | yes | yes | yes |
| Adopt unit-matched apps | log | yes | yes | yes |
| Auto-adopt app roots | log | **yes** | yes | yes |
| Contain survivors in `leftover/` | log | **yes** | yes | yes |
| Ask terminal questions | yes | yes | yes | yes |
| Queue GUI review | yes | **yes** | yes | yes |
| Stop owner-bound scope | log | **yes** (explicit request) | yes | yes |
| Stop by answered pair | no | **yes** | yes | yes |
| Stop by learned pair | no | `authority=learned` | yes | yes |
| Stop by enforce rules (all unit/GC/session) | no | no | no | yes |
| Stop idle `shared/*` / unit `stop_when_unneeded` | log | no (review) | **yes** | yes |
| Reclaim memory | log | **yes** | yes | yes |
| Set `memory.high` | log | yes (`mem.manage = soft`, D3) | yes | yes |
| Set `memory.max` | no | unit opt-in | unit opt-in | unit opt-in |
| Deprioritize leftovers (`cpu.idle`, `io.weight`, `oom_score_adj`) | log | **yes** | yes | yes |
| Freeze idle leftovers (quarantine, wake-on-connect, §5.6) | log | opt-in (`freeze.adopt`) | yes | yes |
| Pressure guard (§7.10) | log | reclaim, deprioritize; freeze opt-in | full ladder | full ladder |
| Window close counts as a close (§9.3) | observe | **yes** | yes | yes |
| Launch-time scoping (`taema launch`, §9.4) | yes (explicit) | yes | yes | yes |

`adopt` becomes **“contain, deprioritize, learn, ask, reclaim; stop only what you asked for”**. It is safe
because it never guesses, and useful because it does everything except the guess. `auto` is
`adopt` plus learned authority. `enforce` stays the manual escape hatch.

### 5.2 Authority is a separate knob

```toml
[learn]
authority = "answered"   # answered | learned | aggressive ; adopt defaults to answered
```

- `answered`: only `ex_stop` (explicit answers) authorizes a stop.
- `learned`: answered or silent thresholds (inferred manual kills, signature confirmation).
- `aggressive`: also own-stop outcomes after probation (`allow_self_authority = true`),
  off by default, for users who want the fastest learning.

`auto` defaults to `learned`; `adopt` defaults to `answered`; `enforce` ignores this knob and
uses unit rules. This solves “adopt never acts” without making adopt a second auto.

### 5.3 Runtime hold (kill switch)

`taema hold` sets a daemon flag (and a `$XDG_RUNTIME_DIR/taema/HOLD` file for the CLI). All
stops and reclaims are skipped; observe/learn/queue continue. `taema resume` clears it.
SIGUSR1 toggles it. The service `conf` can set `TAEMA_HOLD=1` for a cautious boot. `hold` is
not a mode: it does not change policy, it just stops the daemon's hands.

### 5.4 Per-scope overrides

- `taema hold NAME` / `taema resume NAME`: runtime hold for one scope.
- `taema do-not-kill NAME`: permanent veto for the scope/unit/pair.
- Unit `[kill] never_stop = true`: unit-level veto, equivalent to `persist` but explicit and
  visible in `taema why`.
- `taema stop --force-veto NAME`: the only way past a veto; prints the veto record, asks for
  confirmation, and logs `veto_override`.

### 5.5 Decision pipeline

Every action goes through the same ladder, so `observe`, `adopt`, `auto`, `enforce`, `hold`,
and vetoes compose instead of being scattered `if` statements:

```
collect facts (lineage, windows, edges, CPU, memory, PSI, unit, pair, signature, veto, profile)
        │
        ├─ hard rule?           → skip / keep                 (never learned)
        ├─ veto?                → vetoed                     (absolute)
        ├─ hold?                → logged, no action
        ├─ mode cannot act?     → would_* log (deduped)
        ├─ pair decision keep?  → keep + suppress (no freeze; page-cache reclaim only)
        ├─ pair decision stop?  → reversible stages first unless explicit, then stop (grace, probation)
        ├─ pair decision ask?   → contain + deprioritize (+ freeze when idle) + review / ask
        └─ unknown              → keep + learn (deprioritize only if contained)
```

This ladder lives in one module (`policy.decide_action` or `engine.authorize`), not in the
call sites. That is the structural fix for R1.

### 5.6 The action ladder: reversible before destructive

Revision 1 had one actuator, the stop. Revision 2 gives the daemon five, ordered from
harmless to final. Every stage is logged with a `decision_id`, and every stage except the
last can be undone at once.

| Stage | Action | Kernel interface | Undo | Default trigger |
|---|---|---|---|---|
| 1 Contain | move survivors to `leftover/<owner>-<id>` | `cgroup.procs` (no root inside `user/<uid>`) | `taema adopt --standalone`, answer `standalone` | every close with survivors (all modes except `observe`) |
| 2 Deprioritize | `cpu.idle = 1` (fallback `cpu.weight = 10`), `io.weight = 10` when present, `oom_score_adj` +500 | `cpu.idle`, `io.weight`/`io.bfq.weight`, `/proc/PID/oom_score_adj` | write back the defaults (OOM value restored through the helper) | immediately on contain |
| 3 Freeze | `cgroup.freeze = 1` with wake-on-connect | `cgroup.freeze`, `cgroup.events` (`frozen 1`) | `taema thaw`, veto, focus, or a connection attempt | idle for `freeze.after` (120 s) and freeze-eligible |
| 4 Reclaim | push the frozen or idle scope's pages to swap/zswap and drop its page cache | `memory.reclaim`, `memory.swap.max` | none needed: pages fault back in on thaw | pressure gate, `game`/`battery` profile, or VM/container idle rules (§7.5) |
| 5 Stop | thaw → SIGTERM → learned grace → SIGKILL (explicit pairs only) → rmdir | signals via pidfd, `cgroup.kill` | `taema restore` when `remember_argv` is on | authority only: answered, learned, unit, or `enforce` rules |

**Freeze eligibility.** All of these must hold, and unknown means "not eligible":

- no outside edges;
- not a pty host;
- no protected member;
- no window open (from the agent);
- CPU ≤ 0.5% over the last 60 s;
- no PipeWire/Pulse client socket (audio or video in use);
- no established TCP connection;
- the pair is not decided `keep` or `standalone`;
- no veto.

Shared helpers in `shared/` are never frozen, because something outside depends on them by
definition.

**Wake-on-connect.** A frozen server cannot accept connections, and a client that connects
to it hangs. That would be the worst failure mode of freezing, so it is designed out:

- The daemon records the frozen scope's listening sockets (`ss -tlnH`, `ss -xlH` filtered to
  member pids) when it freezes the scope.
- While at least one frozen scope has listeners, the daemon samples the listeners' accept
  queue (`Recv-Q` of the LISTEN row) every 2 s.
- A non-zero queue thaws the scope at once and logs `thaw reason=connect`. The client sees a
  delay of at most about 2 s instead of a hang. Unix listeners are handled the same way.
- Scopes with listeners are frozen only when `freeze.wake_on_connect = true`. Otherwise they
  stop at stage 2.
- The sampling cost is two `ss` calls per 2 s, and only while such scopes exist. It is
  bounded by `freeze.max_frozen`.

**Other thaw triggers:**

- a veto, `taema thaw`, or `taema hold`;
- a window of the scope being opened or focused (agent);
- a profile change that disables freezing;
- a stop (thaw first, so SIGTERM handlers run);
- a `ptrace` attach attempt seen as a new edge;
- daemon shutdown (every scope tæma froze is thawed on exit, and a crash-recovery pass on
  start thaws scopes recorded as frozen by a previous instance).

**Defaults per mode:**

| Stage | `observe` | `adopt` | `auto` | `enforce` |
|---|---|---|---|---|
| Contain | log | on | on | on |
| Deprioritize | log | on | on | on |
| Freeze | log | off (`freeze.adopt = false`) | on | on |
| Reclaim | log | page cache only; swap opt-in | on (gated) | on (gated) |
| Stop | never | answered, owner-bound | answered, learned, idle shared/unit | all rules |

---

## 6. Feature 1 — provenance learner, signatures, veto, and undo

### 6.1 Provenance model

The unit of learning becomes an **application instance** and a **survivor signature**, not a
pair of names.

```python
@dataclass(frozen=True)
class AppIdentity:
    key: str              # stable learning key: unit name | exe:inode | interp:script | container:<name>
    kind: str             # unit | exe | interp | container | vm | shell | unknown
    exe: str              # resolved path (no " (deleted)")
    dev: int              # st_dev of the exe, when readable
    ino: int              # st_ino of the exe
    comm: str             # raw kernel comm (for display/debug only)
    argv_hash: str        # sha1 of argv (no env)
    unit: str | None

@dataclass
class AppInstance:
    id: str               # "pid.start"
    app: str              # AppIdentity.key
    pid: int
    start: int            # jiffies from /proc/PID/stat
    born: float           # wall clock, derived from uptime
    exited: float | None
    parent_app: str | None
    scope: str | None     # cgroup leaf
    terminal: bool        # tty or under an interactive shell
    runtime: str | None   # sha1(XDG_RUNTIME_DIR) when it matters
    class_: str           # app | vm | container | service | shell

@dataclass
class SurvivorSignature:
    id: str               # sha1 of the canonical body, 12 hex chars
    members: tuple[tuple[str, int], ...]   # (key, count), sorted
    runtime: str | None
    tty: bool
    scope: str | None
```

**Persistence (logical model).** Revision 2 stores these records in SQLite tables (§13.2). The
JSON below shows their logical shape, which is also the format of `taema learn export`:

```json
{
  "version": 3,
  "apps": {
    "firefox": {
      "identity": {"kind": "exe", "exe": "/usr/lib/firefox/firefox", "dev": 66305, "ino": 123456, "argv_hash": "…"},
      "first_seen": 1792000000.0, "last_seen": 1792380000.0, "instances": 42,
      "lifetime_ms": {"p50": 1800000, "p95": 14400000},
      "parents": {"niri": {"co_birth": 8, "cgroup": 42, "job": 0, "runtime": 2, "last": 1792379000.0}},
      "children": {"node:vite.js": {"instances": 7, "last": 1792379000.0}},
      "survivors": {"a1b2c3d4e5f6": {"members": [["node:esbuild", 1], ["node:vite.js", 1]],
                                   "closes": 7, "stop_ok": 5, "respawn": 1, "veto": false,
                                   "first_seen": 1792200000.0, "last_seen": 1792379000.0}},
      "mem": {"current_p50": 812000000, "peak_p95": 1100000000, "reclaimable_p50": 120000000},
      "veto": false
    }
  },
  "instances": [
    {"id": "4242.123456", "app": "firefox", "pid": 4242, "start": 123456, "born": 1792378000.0,
     "exited": 1792379000.0, "parent_app": "niri", "scope": "app-firefox-3f2a1c",
     "terminal": false, "runtime": "sha1:…", "class": "app", "survivors": "a1b2c3d4e5f6"}
  ],
  "pairs": {
    "firefox\u0000node:vite.js": {
      "sig": "a1b2c3d4e5f6", "first_seen": 1792200000.0, "stop": 0.5, "keep": 0.0,
      "ex_stop": 3.0, "ex_keep": 0.0, "closes": 7, "kills": 1, "launches": 0,
      "stop_ok": 5, "respawn": 1, "last_outcome": "stop_ok", "probation": 1,
      "last_asked": 1792300000.0, "last_auto_stop": 1792370000.0, "suspended_until": 0.0
    }
  },
  "vetoes": {"v-7f3a": {"match": {"kind": "pair", "owner": "firefox", "leftover": "node:vite.js"},
                       "created": 1792379500.0, "expires": 0, "reason": "user", "source": "cli"}},
  "review": [{"id": "r-9c1", "owner": "firefox", "sig": "a1b2c3d4e5f6", "pids": [501, 502],
               "created": 1792379000.0, "expires": 1792983800.0, "asked": 0}]
}
```

**What the daemon writes when a root exits** (one pass, batched at most every adopt pass):

```python
def observe_root_exit(self, rid, owner, survivors, now):
    sig = signature_of(survivors)
    self.store.record_instance_end(owner, rid, survivors, sig, now)
    self.store.observe_close(owner, sig, survivors, now)      # closes + signature counters
    if survivors and self.may_move():
        self.contain(survivors, "leftover/%s-%d" % (leaf_slug(owner), rid[0]))
    if survivors and self.review_enabled():
        self.queue_review(owner, sig, survivors)
    if self.authority_permits_stop(owner, sig, survivors):
        self.stop_contained(owner, sig, survivors)
```

The key difference from 0.2.x: the pair key can be `(owner, signature)` as well as
`(owner, key)`. A signature is stable across renames and re-launches of the same survivor set
(one node version bump, for example). An answer to a signature applies to every pair in it.

### 6.2 Identity resolution (fixing `MainThread`, `sleep`, `2.1.300`)

1. **Unit wins.** If a process matches a unit, its key is the unit name (`app-firefox`).
2. **Exe inode wins for GUI apps.** Key = `<basename>:<dev>:<ino>` internally; display as the
   basename. An upgraded binary gets a new inode and a new identity, deliberately: a new
   version is a new thing to learn about.
3. **Interpreter script.** Keep the existing `interp:script` logic, but resolve the script to
   a real path and include a short path hash, so `vite.js` in two projects do not collide.
4. **Container/VM identity.** Use what cgroups and sockets reveal (runtime dir, QMP socket
   path, conmon arguments), else the runtime-dir hash. Friendly names from the runtime CLIs
   (`virsh`, `podman`, `incus`) are fetched only when `[mem] probe = true` (D9).
5. **Validated fallback.** `comm` is used only if it passes `identity_ok()`:

```python
def identity_ok(comm: str, exe: str, argv: list[str]) -> bool:
    if not comm or len(comm) > 15: return False
    if re.match(r"^[0-9]", comm): return False          # "2.1.300"
    if comm in GENERIC_THREAD_NAMES: return False       # MainThread, Thread-*, pool-*, GC, Finalizer
    if comm in SHELLS: return False                     # bash, sh, zsh, fish, dash
    if comm in TRIVIAL_COMMANDS: return False           # sleep, cat, head, sort, grep, true
    if comm.startswith(("python", "node", "java")) and not script_of(argv): return False
    return True
```

6. **Owner must be an app, not a command word.** For a terminal job, the owner is the job's
   *root* only if it is a real app (not a shell/trivial command); otherwise use the shell's
   parent app, or mark the close `launcher` and do not create a pair. This removes the live
   `sleep > …` pairs.
7. **Answers bind only to validated identities.** If the owner is generic, the question is
   replaced by a review with provenance candidates; it is not answerable until the daemon can
   name a real app.
8. **Window and launcher identity.** When the agent reports a window (niri `app_id`), or
   `taema launch --app NAME` names the app, that name seeds the identity (`desktop_id`) and
   becomes the display name. This removes most guessing for GUI apps and gives the review
   and notification text a name the user recognizes.

### 6.3 Survivor signatures and matching

- Compute a signature from the survivor set: sorted `(key, count)` pairs + runtime-dir hash +
  tty flag. Do not include pids or start times.
- Match order:
  1. exact signature id;
  2. same key set with counts within ±1 and the same runtime class;
  3. per-pair keys (0.2.x fallback).
- A signature's counters (`closes`, `stop_ok`, `respawn`, `veto`) are updated by every close
  and every stop. An explicit answer on a signature sets `ex_stop` on the signature; every
  pair currently in it inherits the decision for display, but only the signature gets the
  no-decay weight. This is how the learner generalizes without guessing.
- Signature example: `firefox` closes → `{node:esbuild ×1, node:vite.js ×1}` → signature
  `a1b2c3d4e5f6`. A later close with `{node:esbuild ×1, node:vite.js ×1, node:eslint ×1}` is
  the same class; if the user answered stop, the new member is a **candidate**, not an
  automatic kill. It goes to review unless its own pair is already decided.

### 6.4 The veto: `taema --do-not-kill`

This is the user's escape hatch and the highest-priority rule after hard safety.

#### Command forms

```sh
taema --do-not-kill                     # veto the last automatic action (stop, freeze, countdown) or review
taema --do-not-kill app-firefox         # veto a scope
taema --do-not-kill 4242                # veto a pid (until it exits)
taema --do-not-kill firefox             # veto the app identity (all pairs/owners)
taema do-not-kill --pair firefox node:vite.js      # veto one pair
taema do-not-kill --owner firefox                  # all leftovers of an owner
taema do-not-kill --signature a1b2c3d4e5f6         # a survivor signature
taema do-not-kill --unit app-podman                # a unit
taema do-not-kill --cgroup /user/1000/app-herdr    # a cgroup subtree
taema do-not-kill --path /usr/lib/firefox/firefox  # an executable path
taema do-not-kill --last --for 7d --reason "I need it for CI"
```

`dnk` and `never` are aliases. The global flag is also accepted after a subcommand where it
makes sense (`taema stop --do-not-kill NAME` is rejected: stopping and vetoing are separate).

#### Match record and precedence

```python
{"id": "v-7f3a", "kind": "pair", "owner": "firefox", "leftover": "node:vite.js",
 "created": 1792379500.0, "expires": 0, "reason": "user", "source": "cli"}
```

Precedence: `pid+start` > `scope` > `pair` > `signature` > `app identity` > `owner` > `unit`
> `cgroup prefix` > `path`. Any hit blocks. A veto is checked in:

- `engine.plan_stop` (per member, before `share`/`kill`);
- `engine.auto_stop_ok`;
- `engine.gc_candidates` / `_leftover_verdict` (returns `held`);
- `daemon.stop_leaf`, `daemon.auto_stop_path`, `daemon.auto_stop_survivors`,
  `daemon.end_session`;
- `memory.reclaim` and `budget.apply` (veto blocks reclaim unless `--force-veto`);
- `cli.cmd_kill` (read-only store, so a veto works while the daemon is down).
- `governor.freeze` (a veto thaws a frozen scope at once and blocks a new freeze);
- the agent's countdowns and notifications (a veto cancels a pending stop).

#### Persistence and offline behaviour

- Vetoes live in `state.db` (`vetoes` table, §13.2), written only by the daemon.
- While the daemon is down, `taema do-not-kill` appends `{op:"veto", ...}` to
  `feedback.jsonl`. The CLI reads the store read-only plus the pending feedback file to
  enforce the veto locally, so a kill cannot bypass it.
- Expiry: `--for 7d`, `--until 2026-11-01`, default forever. Expired vetoes are pruned by the
  GC pass. `taema forget --veto TARGET` removes one; `taema forget TARGET` does not.
- Every veto is logged (`event: "veto"`), and every block is logged (`event: "vetoed"`, with
  `source`).

#### Why a veto is not `taema keep`

`keep` is a *preference* on an exe (`user_keep +3`), used by `default_action` when choosing
`share` vs `kill`. It does not affect pair decisions today and does not override a stop that
is already in flight. A veto is a *hard block* on a specific object, with precedence, expiry,
and offline enforcement. Both exist; they answer different questions.

### 6.5 Undo and regret

- `taema undo` (default `--last`) finds the most recent stop decision, adds a veto for the
  stopped scope/signature, adds `keep +3` to the pair, clears `last_auto_stop` and
  `suspended_until`, and logs `undo`. If the stop has a saved argv/cwd (see §12.4), it offers
  `--restore` to relaunch the root in a fresh scope; it never restores environment variables.
- `taema undo <decision-id>` works for any stop in the retained decision ring (last 256).
- Regret becomes per **pair or signature**, not per leftover key: a relaunch only counts when
  the new instance's provenance points to the same owner/signature or the user marks it with
  `--restore`/`undo`. This removes the false regrets from unrelated binaries.
- Automatic authority is suspended for 7 days after a regret (existing idea, corrected scope).
- Undo covers every stage of the action ladder (§5.6). Undoing a freeze thaws the scope.
  Undoing a deprioritize restores the weights. Undoing a stop adds the veto and keep evidence,
  and offers `restore`. An undo from the toast, within `notify.undo_toast_seconds` of the
  action, counts as a regret with full weight.

### 6.6 Questions, review queue, and the prompt

- **Terminal job closes** keep the existing immediate prompt via `taema-hook done`.
- **GUI closes** (no shell) create a review entry and a `$XDG_RUNTIME_DIR/taema/review` flag.
  The shell hook checks the flag with `[[ -e … ]]` (no process) and prints one line:
  `tæma: 2 closes waiting for a decision — taema review` at most once per session/day.
- `taema review` lists entries with provenance, signature, memory, and age:

```
ID     OWNER              SURVIVORS                         CLOSES  MEM     AGE
r-9c1  firefox            node:esbuild, node:vite.js             7   812M    2h
        ↳ last seen under app-firefox-3f2a1c; sig a1b2c3d4e5f6; answered? no
        1 stop on close    2 keep    3 standalone    4 never (do-not-kill)    Enter later
```

- `taema answer r-9c1 stop` (or `taema review --interactive`) applies the answer to the
  signature and its pairs. `never` adds an app veto; `standalone` adopts the survivors into their
  own app scopes. `taema teach OWNER LEFTOVER stop|keep|standalone` records a relationship without
  a pending review. The dashboard and notifications use the same answer operation.
- Rate limits stay: at most 3 questions/day, one per pair/signature per 7 days. A review is
  not a question until it is shown; it does not consume the daily budget.
- **Desktop notifications go through the session agent (§9.1), never from the daemon**,
  because the daemon has no session-bus address (§1.6). With the agent running and an
  action-capable server (verified: quickshell/DMS advertises `actions`), a GUI close produces
  one actionable notification: *Stop when it closes* / *Keep* / *Never* / *Details*. Closes
  are batched over 60 s, capped at `notify.max_per_hour`, and silent during quiet hours or
  the `game` profile. Without an agent, reviews wait for the shell hint and `taema review`.
- A review can expire (`review_ttl = 14d`); when it expires, the survivors are **kept** and the
  entry is marked `expired`, never silently stopped.

### 6.7 The learning state machine

```
watch ──close with survivors──▶ contain (leftover/) ──▶ review/ask
  ▲                                   │                    │
  │                                   │              answer │
  │                                   ▼                    ▼
  │                              keep (no authority)   probation (graceful only)
  │                                                        │
  │                                          stop succeeds │ stop respawns
  │                                                        ▼
  └──────────────── learn signature/pair ◀── stop_ok ── learned
                                                           │
                                              regret/undo  ▼
                                                        ask + 7d suspend + veto
```

- **Probation:** the first `probation_stops = 3` automatic stops of a learned pair are
  SIGTERM-only, even if the pair is explicit; SIGKILL remains explicit-only. This gives the
  user a window to notice a wrong stop.
- **Outcome loop:** after every stop, record a `stop_record` and watch for `respawn_window`
  (60 s) and `revive_window` (30 min). No reappearance → `stop_ok +1` on the pair/signature;
  reappearance → `respawn +1`, `keep +1`, suspend. `stop_ok` is confidence, not authority
  (unless `allow_self_authority`).
- **Manual kill evidence** remains 0.25, but it is now attached to the validated identity and
  the signature, not to a raw `comm`.
- **Windowless closes** (§9.3) enter the same machine. "Last window closed, root still
  alive" is recorded as a close of kind `windowless`. Its survivors are the root's whole
  scope, and its answer options are *Quit when the last window closes* / *Keep (tray app)* /
  *Ask later*.

### 6.8 Explainability: `taema why`

`taema why TARGET` is the single best debugging tool. It must answer: who is this, who started
it, what survived, what is learned, what would happen in each mode, and why.

```
$ taema why firefox
app-firefox-3f2a1c    state live    pids 12    mem 812M / peak 1.1G    psi 0.0
  identity   firefox 128.0  /usr/lib/firefox/firefox  inode 66305:123456
  provenance
    firefox(4242) ← niri(1200) ← elogind-session(2)
    co-birth 8   cgroup 12   job 0   runtime 2   confidence high
  survivors  sig a1b2c3d4e5f6: node:esbuild ×1, node:vite.js ×1
    closes 7   answered stop   stop_ok 5   respawn 1   last 2h ago
  pair       firefox → node:vite.js: stop (explicit 3.0), confidence 1.00
  memory     current 812M  anon 700M  file 90M  reclaimable 60M  pressure 0.0
  vetoes     none
  mode auto  would stop on close (explicit), graceful 5s, no SIGKILL
  last       2026-10-19 08:04 stop_ok  [decision 1281]
```

`taema why PID`, `taema why NAME`, and `taema why --pair OWNER LEFTOVER` share the renderer.
A `--json` variant returns the same object the dashboard uses.

### 6.9 Fixing the 0.2.x learning bugs

| Bug | 0.2.x | v2 |
|---|---|---|
| Burn-in is global | `decide(p, now, store.created, store.closes)` | `decide(p, now, p.first_seen, p.closes)` |
| Regret keyed by leftover only | `auto_recent[key]` | `auto_recent[(owner, sig)]` |
| Launcher pairs stored | `observe_close(launcher=True)` still creates a pair | launcher closes update a noise counter; no pair |
| Generic owners | `comm` accepted | `identity_ok()` + unit/exe/inode resolution |
| Pair vs exe keys | `exe_key` in stop, `app_key` in pairs | one `app_key`/`AppIdentity` everywhere |
| Own outcomes unused | missing | `stop_ok` + `respawn` on pair/signature |
| GUI never asks | no review | review queue + prompt flag |
| `keep` is exe-only | `user_keep` | `keep` is pair-aware; `do-not-kill` is hard |
| No undo | relaunch is the only undo | `taema undo` + veto |

---

## 7. Feature 2 — resource governor (memory, CPU, IO) and container/VM GC

### 7.1 What the kernel gives us (and what it does not)

| Feature | Interface | Minimum kernel | Fallback |
|---|---|---|---|
| memory accounting | `memory.current`, `memory.stat` | 4.5 | none (scope lifecycle only) |
| peak usage | `memory.peak` | 5.19 | daemon samples max(current) |
| pressure | `memory.pressure`, `/proc/pressure/memory` | 4.20 | `cpu.stat` + edges |
| targeted reclaim | `memory.reclaim` | 5.19 | `memory.high` pulse, or no reclaim |
| soft cap | `memory.high` | 4.5 | no cap |
| hard cap | `memory.max` | 4.5 | no cap |
| swap accounting | `memory.swap.current/max` | 5.0 | no swap reclaim |
| zswap | `memory.zswap.*`, `/sys/module/zswap` | 5.15+ | swap only |
| OOM events | `memory.events(.local)` | 4.5 | log only |
| whole-subtree signal | `cgroup.kill` | 5.14 | SIGTERM/SIGKILL loop |
| freeze | `cgroup.freeze` | 5.2 | no pause |

The live machine (Void, kernel 7.2.11_1) has all of them: `memory.reclaim`, `memory.pressure`,
`memory.peak`, `memory.zswap.*`. Feature detection must be runtime, not assumed.

**Honesty about “reallocating memory”.** The kernel frees a process's memory when it exits; a
userspace GC cannot “move” anonymous pages to another process. What tæma can do:

- reclaim page cache and (with swap) anonymous pages from a live-but-idle scope;
- save a VM/container state, stop it, and remove the cgroup so the kernel frees everything;
- use `memory.high`/`memory.low` as soft shares so an idle scope cannot crowd out an active one;
- report freed bytes and rebalance the advisory budget. That is the honest meaning of
  “reallocate” here, and the plan says so in the docs and dashboard.

### 7.2 Accounting model

New module `src/taema/memory.py` (stdlib only):

```python
@dataclass(frozen=True)
class LeafMemory:
    rel: str
    current: int
    peak: int | None
    swap_current: int
    anon: int
    file: int
    inactive_file: int
    shmem: int
    slab: int
    high: int | None
    max: int | None
    pressure_some10: float
    pressure_full10: float
    oom_kill: int
    high_events: int
    reclaimable: int          # file - inactive_file - shmem, floor 0
    generation: int           # cache invalidation

def read_leaf(path: str) -> LeafMemory | None: ...
def feature_flags() -> Features: ...
def reclaim(path: str, bytes_: int) -> ReclaimResult: ...
def pulse_high(path: str, target: int, ms: int) -> bool: ...
def host_pressure() -> HostPressure: ...   # /proc/meminfo, /proc/pressure/memory, /proc/swaps
```

Cost: ~10 small file reads per scope per memory pass. With 200 scopes and a 30–60 s pass,
this is negligible. The daemon already does one `/proc` snapshot per pass; memory reads are
separate because they are per cgroup leaf and cheap.

### 7.3 Classification: what may be reclaimed, what may be capped

| Class | Detection | Stop authority | Reclaim | Cap |
|---|---|---|---|---|
| `protected` | hard rules | never | never | never |
| `foreground` | focused or visible window (agent, §9.3), tty, edge from a tty/desktop client, CPU > 1%, or `[mem] class = foreground` | pair only | only if idle > 10 min and pressure high | no `memory.high` by default |
| `background` | `app-*` / `leftover/*` with no edges, CPU ≈ 0, no pty | pair/unit | yes | soft `memory.high` |
| `container` | podman/docker/incus unit or `[unit] class = container` | unit + pair | yes (runtime-aware) | soft; `max` opt-in |
| `vm` | libvirt/qemu/virtualbox unit or `[unit] class = vm` | unit + pair | only after save/pause; `memory.reclaim` for file cache | soft; `max` opt-in |
| `infrastructure` | protected comm, session leader, `manager` | never | never | never |

**“No notification/desktop process attached”** is modeled as: no `edges` entry from an outside
process (unix/TCP peer, ptrace, conmon/podman pause), no pty host, no runtime-dir client, and
no QMP/VBoxSVC/incus/docker API socket peer. We do not poll the notification daemon: a pending
notification is not a dependency. If a desktop manager (virt-manager, GNOME Boxes, IDE) is
attached, it holds a socket to QMP/the container API, so `inspect.edges` already sees it. We
extend `edges` with explicit `kind` labels for `qmp`, `podman_api`, `docker_api`, `incus_api`,
and `vboxsvc` so `taema why` can say *which* desktop process is attached.

### 7.4 Budget and allocation

```toml
[mem]
enabled = true
manage = "soft"              # off | observe | soft | hard
budget = "auto"              # min(user/<uid>/memory.max, mem.fraction * MemTotal)
fraction = 0.80
floor = "512M"               # never let MemAvailable go below this
min_headroom = "128M"        # never cap/reclaim below current + this
headroom_percent = 10
reclaim = true
reclaim_interval = 60
reclaim_cooldown = 300
reclaim_max = "2G"
idle_reclaim_grace = 300
pressure_gate = 10           # only reclaim when global some avg10 >= this ...
pressure_ceiling = 60        # ... and never when full avg10 is above this
swap_reclaim = true
zswap = true
oom_policy = "log"           # log | raise | notify
```

Budget algorithm (per memory pass):

1. `total = min(finite memory.max of user/<uid>, fraction * MemTotal)`. On the live machine
   `memory.max` is `max`, so the fraction applies.
2. `reserved = Σ reservation` for active scopes, where `reservation` comes from `[mem]` or a
   class default (`vm: 25%`, `container: 10%`, `app: 5%`, capped by total).
3. `available = total - floor - infrastructure_estimate`.
4. For each **background** scope with `manage = soft`:
   `high = max(current + min_headroom, reservation * pressure_factor)`.
   Write `memory.high` only when it changes by > 5% to avoid churn.
5. For each **foreground/active** scope, set `memory.low` to its reservation (protection) and
   clear `memory.high` if it was set by us.
6. On scope exit (`rmdir` or `populated 0`), decrement `reserved`, remove the scope's limits
   (the kernel does it), and recompute; log `rebalance` with freed/available.
7. `memory.max` is only written when a unit explicitly sets `[mem] max` and
   `mem.manage = "hard"`; validate `max >= current + min_headroom`, else refuse and log.

`memory.high` is a throttle, not a reservation. The docs and dashboard must call it a soft
share. This is deliberate: hard limits cause OOM and latency surprises, and tæma is not the
only thing on the machine.

### 7.5 The reclaim ladder

For a scope classified `background`/`container`/`vm`, with no veto, in a mode that may reclaim:

```
0. Apply the reversible stages of the action ladder first (§5.6): deprioritize, then freeze
   when eligible. Reclaiming a frozen scope cannot cause refault thrash while it stays frozen.
1. If the scope is a VM/container and [mem] save_state exists:
     run the hook only after idle_reclaim_grace and no attachment;
     timeout 30 s; success/failure logged; failure → do not escalate.
2. If global pressure is above pressure_gate and scope pressure is low:
     reclaimable = file - inactive_file - shmem
     if reclaimable >= reclaim_min:
         memory.reclaim = min(reclaimable, reclaim_max, current - min_headroom)
3. If swap is available (or zswap enabled) and memory.swap.max allows:
     reclaim anonymous pages, bounded by reclaim_max and min_headroom.
     Never do this to a VM without a save/pause hook: swapping a guest is worse than waiting.
4. If memory.reclaim is unavailable but memory.high exists:
     pulse memory.high to max(current + min_headroom, target) for pulse_ms,
     restore; abort on pressure_ceiling or OOM events.
5. If the scope has no users and no save hook, and its authority permits a stop:
     stop per §5 (graceful first), then rmdir; log freed bytes.
6. Otherwise: keep, report in taema memory, and let the user decide.
```

**Thrash control.** After a reclaim, sample `memory.stat` and `memory.events` for
`refault`/`pgmajfault`/`high` growth. If the scope refaults within `reclaim_cooldown`, mark it
`warm` for `warm_until = now + 2 * cooldown`, double its effective `idle_reclaim_grace`, and
skip further reclaim until it is cold. This is the memory analogue of `idle_grace_scale`.

**Save-state hooks are explicit.** A unit must opt in with a command; tæma never invents a
save command. Hooks run as the user, in their own process group, with a timeout, and their
output is logged. Template values are substituted by tæma from validated fields (unit name,
domain, container id), never from shell interpolation.

### 7.6 Container and VM support

New/updated units:

| Runtime | Detection | Quit signal | Save/pause |
|---|---|---|---|
| podman rootless | `catatonit -P` pause + `conmon`, `XDG_RUNTIME_DIR`, `podman.sock` | runtime dir or socket gone; no conmon; no API peer | `podman pause`, `podman stop`, `podman checkpoint` (opt-in) |
| docker rootless | `dockerd`, `containerd-shim`, `runc`, `docker.sock` | socket gone; no shim | `docker pause`, `docker stop` |
| libvirt/QEMU | `qemu-system-*`, `virtiofsd`, QMP socket under `/run/user/<uid>/libvirt/qemu/` | QMP socket gone; no client; domain not running | `virsh managedsave`, `virsh save` |
| incus/lxc | `incusd`, `incus-user`, `lxc-start`, `incus.sock` | socket gone; no instance | `incus stop`, `incus pause` |
| VirtualBox | `VBoxSVC`, `VBoxHeadless`, `VBoxSVC` IPC | VBoxSVC gone | `VBoxManage savestate` |
| generic | `[unit] class = container / vm` + `[match]` | no edges/CPU/runtime | `[mem] save_state` |

Example `~/.config/taema/units/libvirt-qemu.toml`:

```toml
[unit]
name = "app-libvirt-qemu"
kind = "app"
class = "vm"
stop_when_unneeded = true
survive_logout = false

[match]
comm = "qemu-system-x86_64"

[[children]]
name = "vm"
ancestor_comm = "qemu-system-x86_64"
binds_to = "root"

[mem]
reservation = "4G"
high = "6G"
# max = "8G"            # opt-in; never set below current + min_headroom
swap_max = "2G"
idle_reclaim = true
min_headroom = "512M"
save_state = ["virsh", "managedsave", "%(domain)s"]
resume = ["virsh", "start", "%(domain)s"]

[gc]
keep_while_children = true
no_attach_grace = 120

[kill]
graceful = 30
```

Example podman extension:

```toml
[mem]
reservation = "1G"
high = "2G"
swap_max = "1G"
idle_reclaim = true
save_state = ["podman", "stop", "--time", "10", "%(container)s"] # opt in explicitly
```

**Quit detection and the GC order.** When a container or VM quits:

1. detect the quit (runtime dir/socket gone, no conmon/shim/domain, no attachment);
2. run the save/pause hook if configured (VM/container state is preserved);
3. reclaim page cache (and swap if allowed);
4. stop the remaining pause/conmon/helper processes per mode authority;
5. `rmdir_tree` the scope; the kernel frees anon/file/kernel memory; record
   `freed_bytes ≈ memory.current` before removal;
6. `budget.release(scope)` and rebalance `memory.high`/`memory.low` for the remaining scopes;
7. log `gc_quit`, `reclaim`, `rebalance` with before/after.

If the user has not authorized a stop, steps 1–3 still run (non-destructive), the scope is
contained in `leftover/`, and a review is queued with the estimated memory. That is the
`adopt` behaviour: “I saved/reclaimed what I safely could; the rest is your call.”

### 7.7 Memory safety and failure modes

- **Never** write `memory.max` below `memory.current + min_headroom`; refuse and log.
- **Never** reclaim a scope with `protected`, a veto, a pty host, or an outside edge.
- **Never** reclaim when `memory.pressure` full avg10 is above `pressure_ceiling` (the machine
  is already thrashing) or when the scope's own pressure is high (it is working).
- **Never** reclaim `manager` or a scope containing the daemon.
- Skip a scope whose `memory.current` is below `reclaim_min`; the churn is not worth it.
- If `memory.events.local: oom_kill > 0`, log `oom` with the scope and memory; do not lower
  limits; raise `memory.high` if tæma set one and the unit is interactive (opt-in).
- If the cgroup files disappear mid-pass (`ENOENT`), treat as “scope exited” and re-read; never
  crash the daemon.
- If `memory.reclaim` returns `EAGAIN`/`EBUSY`, back off for `cooldown`; if `EINVAL`, disable
  the feature for the boot and log.
- If the kernel has no memory controller, memory commands report `unsupported` and the GC
  falls back to process/CPU rules.
- **Hold** and **veto** block reclaim too. `taema memory reclaim --force-veto` is explicit.

### 7.8 Observability for memory

`taema memory` output:

```
$ taema memory
HOST     total 31.4G   available 18.2G   pressure some 0.0 / full 0.0   swap 8.0G (zswap on)
BUDGET   soft 25.1G   reserved 12.4G   managed 8.1G   reclaimed today 2.1G
SCOPE                    CLASS    CURRENT  PEAK   ANON   FILE  RECLAIM  PSI10  HIGH   ACTION
app-herdr                app       664M    1.4G   562M   73M    60M     0.0    -      keep
app-libvirt-qemu-8f2a    vm        3.9G    4.2G   3.6G   0.2G   0.2G    0.4    5.9G   warm
leftover/firefox-42      app       812M    812M   700M   90M    60M     0.0    1.2G   idle 2m
```

`taema memory reclaim NAME`, `taema memory budget`, `taema memory pressure`, `taema memory
watch` are subcommands. The dashboard shows the same table. Log events: `mem_sample` (only on
change), `reclaim`, `reclaim_failed`, `warm`, `oom`, `rebalance`, `gc_quit`, `freed`.

### 7.9 CPU and IO quality of service

The `cpu` and `io` controllers are already enabled in `user/<uid>`, but tæma sets no
weights. v2 uses them for one purpose: background work must not compete with what the user
is looking at. These writes are cheap, instant, and fully reversible.

| Class (§7.3) | `cpu.weight` | `cpu.idle` | `io.weight` | `pids.max` |
|---|---|---|---|---|
| foreground (focused window) | 100, or `qos.focus_cpu_weight` (300) with `focus_boost` | 0 | 100 | unlimited |
| interactive (visible window, tty job) | 100 | 0 | 100 | unlimited |
| background (`app-*`, windowless) | `qos.background_cpu_weight` (50) | 0 | 50 | unlimited |
| leftover / quarantined | — | 1 | `qos.leftover_io_weight` (10) | `qos.leftover_pids_max` (0 = off) |
| container / vm | unit `[qos]`, else 100 | 0 | unit `[qos]`, else 100 | unit |
| shared helpers | 50 | 0 | 50 | unlimited |

- **Hierarchy work.** `leftover/` and `shared/` are parent directories that hold no
  processes, so the daemon enables `+cpu +io +memory +pids` in their `cgroup.subtree_control`
  once. Without that, their children have no control files. This needs no root, because the
  directories sit in the delegated subtree.
- **Feature detection.** `cpu.idle` needs kernel 5.15 or newer. `io.weight` needs an IO
  controller that honours weights (BFQ exposes `io.bfq.weight`; io.cost exposes `io.weight`).
  A missing file is skipped and reported by `doctor`.
- **Writes only on change.** Class changes are debounced by 2 s, so a focus that flips back
  and forth does not churn. A `qos` event is logged only when the class changes.
- **Focus boost** is off by default and on in the `focus` profile. It needs the agent's focus
  events (§9.3).

### 7.10 Pressure guard and OOM coordination

The goal is that the kernel or earlyoom never has to choose a victim, and that if they must,
they choose a leftover rather than the app the user is using.

**Triggers (event-driven, zero idle cost):**

- PSI triggers registered on `user/<uid>/memory.pressure`: `some 150000 2000000` (150 ms of
  stall in a 2 s window) and `full 50000 2000000`. An unprivileged trigger was verified on
  this kernel (§1.6). The trigger fds go into the daemon's selector.
- `MemAvailable` below `guard.available_floor`. `auto` means earlyoom's `-m` plus 4
  percentage points when earlyoom is running, else 12%. On this machine that is 12%,
  comfortably above earlyoom's 8%.

**Guard ladder.** Each step runs per event, has a cooldown of `guard.cooldown` (10 s), and
stops as soon as pressure clears:

1. Reclaim page cache from idle background, frozen, and leftover scopes, largest
   reclaimable first.
2. Freeze eligible leftovers (§5.6), even unlearned ones, because freezing is reversible. In
   `adopt` this step needs `guard.freeze_in_adopt = true`.
3. Reclaim anonymous memory from frozen scopes into swap/zswap, bounded by `reclaim_max`.
4. Stop authorized scopes (answered, learned, or unit rules), largest `memory.current`
   first, one at a time.
5. Never stop an unlearned scope. If memory is still short, the kernel or earlyoom decides,
   and the `oom_score_adj` shaping below has already biased that choice.

**`oom_score_adj` shaping.**

- On contain or freeze, leftover members are raised to `guard.oom_adj_leftover` (+500).
  `shared/` helpers are raised to `guard.oom_adj_shared` (+200).
- Raising needs no privilege; this was verified.
- Lowering needs `CAP_SYS_RESOURCE`. A `standalone` or `keep` answer therefore asks the root
  helper to restore the original value. The new verb is `taema-attach oom-restore PID VALUE`,
  and the helper validates: same uid, a value recorded by the daemon at contain time, and a
  value that is not lower than the original.
- `memory.oom.group = 1` on leftover scopes (`guard.oom_group_leftover`), so a kernel OOM
  kill takes the whole leftover tree instead of one helper and leaving its siblings orphaned.

**earlyoom coordination.**

- Detect earlyoom (process name and `/proc/PID/cmdline`) and parse `-m`, `-s`, `--prefer`,
  and `--avoid`. `taema doctor` shows them.
- earlyoom picks its victim by `oom_score`, which includes `oom_score_adj`, except where
  `--prefer`/`--avoid` match. Because tæma raises leftovers' scores, earlyoom's choice among
  non-matching processes already favours leftovers.
- `doctor` warns when a `--prefer` pattern matches a current foreground or interactive scope.
  On this machine, `node` matches the dev server in use. The suggestion is to narrow
  `--prefer` and rely on tæma's shaping. tæma never edits earlyoom's config, which is
  root-owned.
- nohang and systemd-oomd are detected the same way; neither is present here.

**Logging.** `guard` events carry the trigger, the steps taken, bytes freed, and the
duration. The widget shows a pressure indicator while the guard is active.

### 7.11 Swap, zswap, and zram advisor

Freezing and then reclaiming moves idle leftovers to swap. On this machine swap is a 24 GiB
file with zswap disabled, so every swap-in is a disk read. tæma does not change system swap
settings, because that needs root, but it advises:

- `taema doctor` reports swap devices, zswap state (`/sys/module/zswap/parameters/enabled`),
  and zram devices. With swap present and zswap off, it recommends enabling zswap and prints
  the root commands: the sysfs toggle for the current boot and the kernel command-line
  parameter for persistence.
- The reclaim ladder reads `memory.zswap.current` and `memory.swap.current` to report what
  went where. `taema memory` shows `swap` and `zswap` columns.
- VM scopes default to `memory.swap.max = 0` unless the unit sets `swap_max` or a save hook
  ran, because swapping a running guest's memory is worse than waiting.
- Per-scope `memory.zswap.writeback` is respected and never changed.

---

## 8. Feature 3 — commands and dashboard

### 8.1 Command surface

Keep every 0.2.x command working. Add verbs and aliases; do not require users to relearn.

| 0.2.x | v2 | Notes |
|---|---|---|
| `run` | `run` | `--bind`/`--owner` now work in `adopt`; `--join` unchanged |
| `kill` | `kill` / `stop` | `stop` is the new primary; `kill` is an alias |
| `ls` | `ls` / `ps` | new columns (mem, psi, state, decision); `--tree`, `--apps`, `--leftovers`, `--json`, `--watch` |
| `explain` | `explain` / `why` | human provenance output; `--json` |
| `keep` | `keep` / `allow` | pair-aware with `--pair`; exe-level remains the default |
| `forget` | `forget` | `--veto` removes a veto; `--all` for an app |
| `status` | `status` | `--json` pure; human summary by default |
| `gc` | `gc` | `--dry-run`, `--memory`, `--now`, `--json` |
| `adopt` | `adopt` | `--all` adopts unknown app roots; `--dry-run` |
| `daemon` | `daemon` | hidden; `--verbose`, `--once` for tests |
| — | `memory` | `show / top / reclaim / budget / pressure` |
| — | `learn` | `show / pairs / apps / signatures / export / reset` |
| — | `review` | list/answer pending GUI closes |
| — | `answer` | answer a review/question by id |
| — | `do-not-kill` | hard veto; aliases `dnk`, `never` |
| — | `undo` | undo a stop; `--restore` optional |
| — | `teach` | `OWNER LEFTOVER stop / keep / standalone` |
| — | `hold` / `resume` | runtime kill switch (global or per scope) |
| — | `dash` | curses dashboard; `--once`, `--json`, `--filter` |
| — | `watch` | line-based stream for non-curses terminals |
| — | `doctor` | feature/permission/service checks |
| — | `events` | `decisions.log` tail with `--follow`, `--since`, `--json` |
| — | `config` | `show / get / set / unset / edit / diff`; effective config with sources (§10.1) |
| — | `completions` | bash/zsh/fish |
| — | `setup` | first-run wizard (§10.1) |
| — | `mode` / `profile` | switch the mode or profile without restarting the service (§10.1–§10.2) |
| — | `reload` | re-read config and units (also automatic on change) |
| — | `snooze` | hold with an expiry (`taema snooze 2h`) |
| — | `freeze` / `thaw` | manual quarantine control (§5.6) |
| — | `launch` | start an app inside a fresh scope (§9.4) |
| — | `desktop` | `wrap / unwrap / list` desktop entries (§9.4) |
| — | `agent` | session companion; started by the compositor (§9.1) |
| — | `bar` | status-bar feed: `--format waybar / i3bar / json / plain --follow` (§9.5) |
| — | `prompt` | prompt segment from `$XDG_RUNTIME_DIR/taema/summary`, no socket (§10.3) |
| — | `top` / `tree` | live resource table and ownership tree (§10.5) |
| — | `history` / `report` / `suggest` | timelines, digests, suggestions (§10.6) |
| — | `recent` / `restore` | recent automatic actions and relaunch (§10.7) |
| — | `unit` | `new / test / lint / list / enable / disable / install` (§10.4) |
| — | `mute` | silence notifications for one app |
| — | `backup` / `learn export` / `learn import` / `reset` | portability and reset (§10.8) |
| — | `bug-report` | sanitized diagnostics bundle (§10.9) |
| — | `help` | topics with examples (§10.9) |

Global flags: `--json`, `--jsonl`, `--plain`, `--wide`, `--no-color`, `--yes`, `--quiet`,
`--socket PATH`, `--config PATH`, `--verbose`, `--do-not-kill [TARGET]`, `--version`.

Exit codes: `0` success, `1` user error, `2` target not found, `3` daemon unavailable
(read-only output still printed where possible), `4` refused by veto/protection (with reason).

### 8.2 Output examples

`taema ls` / `taema ps`:

```
SCOPE                     STATE   PIDS  CPU%   MEM    PEAK   PSI10  DECISION        OWNER
app-firefox-3f2a1c        live      12   1.2   812M   1.1G    0.0   stop (answered) firefox
app-herdr                 live      69   0.3   664M   1.4G    0.0   keep (seed)     herdr
app-libvirt-qemu-8f2a     live       4   0.2   3.9G   4.2G    0.4   stop (learned)  libvirt
leftover/firefox-42       idle       3   0.0   812M   812M    0.0   ask             firefox
```

`taema status` human summary:

```
mode auto · daemon up 3h12m · 8 scopes · 42 learned apps · 18 pairs · 2 reviews
memory 8.1G managed of 25.1G · reclaimed 2.1G today · host pressure 0.0
last auto stop: leftover/firefox-42 stop_ok 2h ago
next gc 42s · next memory pass 18s · hold off
```

`taema review --json` and every other read command return a stable object with a `schema`
field. This is what the dashboard consumes.

### 8.3 `taema dash` (curses TUI, stdlib)

```
┌ tæma 0.5 · mode auto · daemon up 3h · host 31% (9.8/31.4G) · PSI 0.0 · hold off ─────────┐
│ SCOPES (8)                    pids  cpu%    mem    peak  psi  decision        owner      │
│ ▸ app-firefox-3f2a1c            12   1.2    812M   1.1G  0.0  stop (answered) firefox    │
│   app-herdr                     69   0.3    664M   1.4G  0.0  keep (seed)     herdr      │
│   app-libvirt-qemu-8f2a          4   0.2    3.9G   4.2G  0.4  stop (learned)  libvirt    │
│   leftover/firefox-42            3   0.0    812M   812M  0.0  ask             firefox    │
├ LEARNED (apps 42 · pairs 18 · signatures 9) ──────────────────────────────────────────────┤
│ firefox → node:vite.js     stop  1.00   7 closes   5 stop_ok   1 respawn   2h ago        │
│ claude  → node:esbuild     ask   0.00   3 closes   0 stop_ok   0 respawn   1d ago        │
├ MEMORY / BUDGET ────────────────────────────────────────────────────────────────────────────┤
│ pool 25.1G  reserved 12.4G  managed 8.1G  reclaimed 2.1G today  zswap on                 │
├ EVENTS (tail) ──────────────────────────────────────────────────────────────────────────────┤
│ 12:04:11  auto_stop   leftover/firefox-42   stop_ok   freed 812M                          │
│ 12:05:02  review      r-9c1  firefox        node:esbuild,node:vite.js  (2h)              │
└ [j/k] move  [enter] why  [s] stop  [n] never  [u] undo  [a] answer  [r] reclaim  [?] help ┘
```

Keys: `j/k` navigate, `enter` details (`why`), `s` stop (confirmation), `n` do-not-kill,
`u` undo, `a` answer review, `r` reclaim, `z` freeze/thaw, `p` profile, `g` GC dry-run,
`m` memory, `f` filter, `/` search,
`?` help, `q` quit. Refresh 2 s; if `curses` is unavailable, `dash` falls back to
`watch --plain`. `dash --once` renders to stdout (golden tests). `dash --json` prints the
snapshot object.

Actions go through the same socket API as the CLI, so the dashboard cannot bypass vetoes or
mode gates. Destructive actions require a confirmation line showing the veto/edge/memory
facts. Read-only by default for the web variant.

Revision 2 additions to the dashboard:

- a **Windows** column (app_id and count from the agent);
- a **❄** marker for frozen scopes and a **↓** marker for deprioritized ones;
- per-scope memory **sparklines** drawn from `mem_samples` (§13.2);
- a **Guard** line that shows pressure, the last guard action, and bytes freed;
- a **Profile** indicator with the switch reason.

The dashboard renders a view model (`ui/viewmodel.py`) that `dash --json`, `bar`, and the
DMS widget also use, so all surfaces show the same numbers.

### 8.4 Optional web dashboard (read-only, M7 or later)

`taema dash --web 127.0.0.1:8787` uses `http.server` from the standard library, binds
localhost, prints a random token URL, and serves `/api/status`, `/api/learn`, `/api/memory`,
`/api/events` read-only. No mutations in v1 of the web view; a single static HTML page renders
the same tables. This is optional and not a milestone gate.

### 8.5 Shell integration

- Keep the existing `done`/`kill` hooks and `TAEMA_JOB` tagging.
- Add a cheap review flag check (one `[[ -e ]]`) and a once-per-session line:
  `tæma: 2 closes waiting — taema review`.
- Add `taema` completions for bash/zsh/fish; install them in `Makefile`.
- `TAEMA_NO_PROMPT=1` still disables all prompt output.
- `taema do-not-kill` works from any shell; no hook needed.
- `taema prompt` prints a short segment (`⟲2 ❄1`) from `$XDG_RUNTIME_DIR/taema/summary`, for
  starship or custom prompts (§10.3).

### 8.6 `doctor`, `events`, `config`

`taema doctor` checks: cgroup v2 mount, delegation and controllers, `memory.reclaim`/PSI/
swap/zswap, `sudo -n` helper, group membership, runit service state, unit parse errors,
store integrity and schema version, file permissions, socket path, daemon mode, hold and
profile, kernel version, agent and window-backend state, notification capabilities, earlyoom
settings, zram, `cpu.idle`/`io.weight`/`cgroup.freeze` availability, and Rust component
versions. Output is `ok|warn|fail` per line with a fix hint. `--json` is for automation, and
`--fix` applies safe user-level fixes (§10.9).

`taema events` tails `decisions.log` with a stable event schema, `--since 2h`, `--event
stop,veto`, `--json`, `--follow`. The dashboard uses the same reader.

`taema config` prints the merged system+user config with source paths and which keys are
overridable. `taema config --json` is used by tests.

### 8.7 Log hygiene

- Deduplicate `would_*`, `gc_would_*`, `mem_sample` with `store.changed(key, sig)`.
- Rotate at 1 MiB to `.1`, `.2` (max 3 files). Decisions for undo live in the `decisions`
  table (§13.2), not in memory.
- Every action gets a `decision_id`; events reference it (`corr`), so `taema undo` and
  `taema events` can reconstruct a chain.
- `decisions.log` stays JSON-lines, 0600, state dir 0700.

---

## 9. Feature 4 — desktop and session integration

The daemon runs outside the user session by design: runit starts it with a clean
environment, which is good for safety. Everything the desktop can tell us (windows, focus,
notifications, launches) therefore has to come from a small companion that lives inside the
session. This section specifies that companion and what it enables.

### 9.1 The session agent (`taema agent`)

**Why it exists.** The daemon has no `DBUS_SESSION_BUS_ADDRESS`, `WAYLAND_DISPLAY`, or
`NIRI_SOCKET`. The session bus lives at a random `/tmp/dbus-…` path created by
`dbus-run-session`, and `/run/user/<uid>/bus` does not exist (§1.6). Only a process started by
the session can reach the bus and the compositor.

**How it starts**, in order of preference; `taema setup` offers each:

1. niri: `spawn-at-startup "taema" "agent"` in `~/.config/niri/config.kdl`. `setup` prints
   the line, or appends it after confirmation.
2. XDG autostart: `~/.config/autostart/taema-agent.desktop`, for sessions that honour it.
3. The DMS plugin (§9.5) can start it if it is not running.
4. By hand: `taema agent --foreground` for debugging.

**What it does:**

| Duty | Detail |
|---|---|
| Register | connects to the daemon socket with `register_agent` and sends a session id, the capabilities (`notify-actions`, `window-backend=niri`, `focus`), and the env facts it can share (desktop name, never secrets) |
| Notify | renders reviews, toasts, countdowns, and guard events, and returns the answers (§9.2) |
| Window feed | streams window open/close/focus events with pids from the window backend (§9.3) |
| Launch | runs `taema launch` requests from its own leaf, so launched apps never need sudo (§9.4) |
| Presence | tells the daemon the session is alive; the daemon logs `agent_up`/`agent_down` and falls back to process-only behaviour |

**What it does not do.** It decides nothing (invariant 11), stores nothing durable, and
never signals a process.

**Placement and protection.** The agent moves itself into `user/<uid>/agent` at start. This
is a move inside the delegated subtree, so it needs no root when the agent is already in
`user/<uid>`; otherwise it asks the daemon to attach it. The `agent` leaf is implicitly
protected: never adopted, frozen, deprioritized, or stopped.

**Lifecycle.**

- Single instance per session, enforced by a lock on `$XDG_RUNTIME_DIR/taema/agent.lock`.
- Reconnects to the daemon with exponential backoff, capped at 30 s.
- Exits when the Wayland or niri socket goes away; that is session end.
- Target footprint: < 15 MB RSS in Python. The Rust option is in §11.5.

### 9.2 Actionable notifications

**Backends.** The agent picks one at start (`notify.backend = auto`):

| Backend | How | When |
|---|---|---|
| `notify-send` (default) | spawns `notify-send -a tæma -i <icon> -A stop=… -A keep=… -A never=… -A details=… -p -w`; the action name is read from stdout; the child has a timeout (`notify.ttl`, 10 min) | libnotify ≥ 0.7.10 (0.8.8 here) and a server with the `actions` capability |
| `jeepney` (optional) | pure-Python D-Bus (`python3-jeepney` 0.9 in Void): `Notify`, `CloseNotification`, and the `ActionInvoked`/`NotificationClosed` signals with the sender checked | when installed; allows updating or closing a notification resolved elsewhere, with no child process per notification |
| `gdbus` (fallback) | `gdbus call --session … Notify` for one-way toasts only | no libnotify |
| none | nothing; reviews wait for `taema review` | no server, `notify.enabled = false`, `quiet` profile |

**Kinds:**

| Kind | Example | Actions |
|---|---|---|
| Review (GUI or windowless close) | "VS Code left 2 processes (812 MB): node:vite.js, esbuild" | Stop when it closes · Keep · Never · Details |
| Windowless app | "Claude Desktop is still running with no windows (1.2 GB)" | Quit now · Always quit on close · Keep (tray app) |
| Countdown (learned, not explicit) | "Stopping vite in 30 s (learned from 6 closes)" | Keep · Stop now |
| Toast after an automatic action | "Froze 2 leftovers of code · freed 640 MB" | Undo |
| Guard | "Memory pressure: froze 3 leftovers, freed 2.1 GB" | Undo · Details |
| Digest (optional, daily) | "Today: 4.3 GB freed, 9 stops, 0 undos, 2 reviews" | Open report |
| Error (at most once per day per kind) | "tæma could not move processes: sudo rule missing" | Run doctor |

**Policy.**

- Coalesce closes over `notify.batch_seconds` (60 s).
- Cap at `notify.max_per_hour` (6).
- Skip scopes under `notify.min_mem` (200 MB) unless the same signature repeats 3 times.
- Honour quiet hours (`22:00–08:00` by default) and the `game` and `quiet` profiles.
- Mute per app with `taema mute APP`.
- Use body markup only when the server advertises `body-markup`. Text is plain and short
  enough to read aloud for screen readers.

**Answer path.** Every actionable notification carries the nonce of its review or question.
The agent sends `notify_result {nonce, action}` to the daemon. Answers from notifications,
the shell prompt, the dashboard, and the CLI therefore share one rate limit, one audit
trail, and one expiry rule. A click after expiry gets a toast saying the question expired,
with *Details*.

### 9.3 Window-aware lifecycle (niri first)

**Signal.** `niri msg --json event-stream` (the same JSON over `$NIRI_SOCKET`) emits window
opened/changed events (`id`, `app_id`, `pid`, `title`, `workspace_id`), closed events, and
focus changes. All of these were verified in §1.6. The agent forwards them as
`window_event {kind, window_id, app_id, pid, focused, ts}`. Titles are dropped unless
`store_titles = true`.

**Mapping.** window pid → `/proc/PID/cgroup` → scope → app instance. The window's `app_id`
becomes the instance's `desktop_id` (§6.2 item 8) and is used to look up `.desktop` names and
icons.

**Instance states:** `windowed` → `windowless` → `exited`. In 0.2.x, only `exited` counted
as a close.

- **Last window closed while the root is still alive** starts `windowless_grace` (30 s;
  learned per app, longer for apps that often reopen a window).
- After the grace, the app's `on_last_window` policy applies:
  - `ask` (default): a windowless review (§9.2).
  - `quit`: stop the app's whole scope with authority, as if the root had exited. The
    answer "Always quit on close" sets this.
  - `keep`: a tray app. Never treat it as closed. Its idle children can still be leftover
    candidates by the normal rules.
- A window reopening during the grace or later cancels any pending action and counts as
  `keep` evidence.

**Foreground classification.**

- The focused window's scope is `foreground`: QoS boost when enabled, never frozen, never
  reclaimed beyond page cache.
- A scope with visible windows is `interactive`.
- A windowless scope is `background`.

**Thaw on focus.** If a frozen scope opens or focuses a window, it is thawed at once.

**Backends**, all behind `WindowBackend` (`snapshot()`, `events()`):

| Backend | Source | Has pid | Plan |
|---|---|---|---|
| niri | `$NIRI_SOCKET` JSON | yes | M5 |
| sway / i3 | i3 IPC `get_tree`, `subscribe window` | yes | M7 or community |
| Hyprland | `hyprctl -j clients`, socket2 events | yes | M7 or community |
| generic Wayland | `wlr-foreign-toplevel` | no | not supported: process-only mode |
| X11 | `_NET_WM_PID` | yes | not planned |

### 9.4 Launch-time scoping (`taema launch`)

Adoption by polling always lags behind the launch. Launching inside a scope removes the lag
and gives exact provenance: the scope exists before the first instruction of the app runs.

- `taema launch [--app NAME] [--unit UNIT] [--bind] -- CMD…` creates
  `app-<name>-<hash>`, moves itself in, registers the instance with the daemon
  (`launch_prepare`), and `exec`s the command. This is the `taema run` path with an
  app-scope name and launcher metadata.
- **No sudo when started from the agent.** The agent sits in `user/<uid>/agent`, so a child
  it forks can move into a new leaf without privilege. From a login-cgroup shell, the helper
  path (`sudo -n taema-attach`) is used, exactly as `taema run` does today.
- **Desktop entries.** `taema desktop wrap firefox.desktop` writes an override to
  `~/.local/share/applications/firefox.desktop` with
  `Exec=taema launch --app firefox -- <original Exec>`. It records the original entry's hash
  and supports `unwrap` and `list`. `doctor` warns when a wrapped entry drifts after a
  package update. DMS and most launchers read these entries, so wrapping covers them.
- **Compositor binds.** `taema setup` can print niri `spawn` binds that use `taema launch`.
  It never edits compositor config without confirmation.
- **Suggestions.** `taema suggest` proposes wrapping the most-launched GUI apps once
  history shows them (§10.6).
- **Latency.** The overhead must stay under 30 ms. The Python CLI costs about 95 ms today,
  so the launch fast path is one of the Rust candidates (§11.5). Until then, lazy imports
  bring the Python path under 50 ms.

### 9.5 Status widget and bar feed

- `taema bar [--format waybar|i3bar|json|plain] [--follow]` emits one line per state change
  over a `subscribe` stream (§14.3), with no polling.
- Text: `tæma ⟲2 ❄1 ↓3 9.3G`. The tooltip lists the top scopes by memory and the pending
  reviews. The CSS class is one of `ok`, `review`, `pressure`, `hold`, or `error`.
- **DMS / quickshell plugin** (`contrib/dms/`, QML):
  - the widget shows mode, profile, review count, frozen count, memory freed today, and the
    pressure state;
  - clicking opens a popup with pending reviews and Stop / Keep / Never buttons, the hold
    and snooze toggles, the profile switcher, and "Open dashboard" (runs `taema dash` in the
    user's terminal);
  - it consumes `taema bar --follow --format json` through a quickshell `Process`, so it
    needs no new protocol.
- The waybar and i3bar formats cover other setups. `plain` is for scripts.

### 9.6 Desktop integration safety

- The agent, widget, and bar are clients. Every mutation goes through the daemon socket with
  the uid check (`SO_PEERCRED`) and, for answers, a nonce.
- Window events are rate-limited (`agent.max_events_per_s`, 50) and validated: the pid must
  belong to the uid, and its start time is checked when the daemon has seen it.
- The agent never forwards environment variables, window titles (unless opted in), or
  clipboard contents.
- A missing or crashed agent degrades features; it never blocks the daemon.

---

## 10. Feature 5 — quality of life

**The QoL rule:** every common task takes one short command or one click. Nothing requires
editing TOML or restarting the service. Every output answers "what next?".

### 10.1 Setup, onboarding, and live configuration

**`taema setup`** is an interactive wizard. It is idempotent, and `--yes` takes the
defaults. In order, it:

1. runs `doctor` and shows only the failures, with fixes;
2. explains `auto` and `adopt` in two plain sentences each, and lets the user choose;
3. detects runtimes (podman and virsh on this machine) and offers their units;
4. detects the desktop (niri + DMS) and offers agent autostart, the widget, and wrapping the
   most-used apps;
5. checks the shell hooks;
6. sends a test notification with actions and confirms the reply arrived;
7. shows RAM, swap, and zswap with advice;
8. explains earlyoom coordination;
9. writes only `~/.config/taema/taema.d/10-setup.toml`, user units, and autostart entries.
   It prints the root commands it cannot run itself.

**`taema` with no arguments** prints a one-screen summary: the status line, the top 3
pending reviews, the last automatic action, one suggestion, and a hint such as
`try: taema review`.

**Live configuration.**

- The daemon reloads on `taema reload`, on SIGHUP, and when the mtime of any config or unit
  file changes. It checks about 20 files per tick, which costs nothing measurable.
- An invalid config keeps the old one running. The daemon logs `config_invalid`, and
  `taema status` shows the error with `file:line:col` from `tomllib`.

**Drop-ins.** `~/.config/taema/taema.d/*.toml` is merged after `taema.toml`, in lexical
order. CLI-managed settings go to `taema.d/50-cli.toml`, a generated file with a "managed by
taema" header. Hand-written files are never rewritten. Python's stdlib cannot write TOML, so
a small writer handles the scalar, array, and table keys that `config set` supports.

**Commands:**

| Command | Effect |
|---|---|
| `taema mode auto` | writes the drop-in and reloads, without sudo. It prints what changes as a diff of the capability matrix (§5.1). |
| `taema config show [--sources]` | merged config, with the file that set each key |
| `taema config get KEY` / `set KEY VALUE` / `unset KEY` | edits `50-cli.toml`, validates, reloads |
| `taema config edit` | opens `$EDITOR` on the user file, validates on save, and restores the previous version on error |
| `taema config diff` | user and drop-ins against the system defaults |
| `taema snooze 2h` / `snooze until 18:00` | a global hold with an expiry; the widget shows a countdown |

### 10.2 Profiles

A profile is a named overlay of config keys, using the same keys as `taema.toml`.

| Profile | Intent | Main overrides |
|---|---|---|
| `default` | the configured behaviour | none |
| `focus` | the focused app gets the machine | `qos.focus_boost = true`; notifications as a digest only |
| `battery` | fewer wakeups, earlier freezing | `freeze.after = 60`; GC and adopt intervals ×2; reclaim earlier |
| `game` | protect the game | freeze idle leftovers and idle VMs at once; aggressive guard; no notifications; never touch `steam`, `gamescope`, `wine` scopes |
| `quiet` | do not disturb, do not act | no notifications; no stops; reviews wait |
| `server` | headless | agent features off; process-only |

- **Auto-switch** (`[profile.auto]`):
  - on battery, from `/sys/class/power_supply/*/online`, checked each tick;
  - when a named process is running (`gamescope`, a Steam game child);
  - by time window.
- Manual `taema profile game` sticks until `taema profile auto`.
- Every switch is logged with its reason and shown in `status`, `dash`, and the widget.
- Users define their own with `[profile.NAME]` tables.

### 10.3 Commands that are pleasant to use

- **Fuzzy targets.** Any TARGET accepts a scope, app key, pid, desktop id, or a unique
  substring.
  - When ambiguous and interactive, a numbered pick list appears. When ambiguous and not
    interactive, the command exits 2 and lists the candidates.
  - `--pick` (or `TAEMA_PICKER=fzf`) uses `fzf` when it is installed. It is installed here.
- **Human inputs.** Sizes (`512M`, `1.5G`), durations (`90s`, `2h30m`, `7d`), and times
  (`--since yesterday`, `--since 09:00`, `--until 18:00`) are accepted everywhere.
- **Smart defaults.**
  - `taema stop` with no target in a terminal opens a picker of leftovers.
  - `taema why` with no target explains the last decision.
  - `taema review` with one pending item shows it directly.
- **Safe bulk actions.** `taema stop --leftovers --idle 1h`, `taema freeze --leftovers`, and
  `taema thaw --all` print a plan and ask, unless `--yes` is given. `--dry-run` is accepted
  everywhere.
- **Output.**
  - Tables fit the terminal width and truncate with `…`; `--wide` turns that off.
  - `--plain` drops box drawing and colour, for screen readers and logs.
  - `NO_COLOR` and `CLICOLOR_FORCE` are honoured.
  - Long output goes to `$PAGER` on a tty.
  - `--json` and `--jsonl` are available on every read command.
- **Errors.** One line says what happened, one line says how to fix it, and a "did you mean"
  uses `difflib.get_close_matches`. Exit codes are as in §8.1.
- **Grammar.** `taema <verb> [target] [flags]`, with noun groups for subsystems (`unit`,
  `memory`, `learn`, `config`, `desktop`). Every `--help` ends with 2–3 real examples, and
  `taema help TOPIC` explains concepts.
- **Completions.** Dynamic: scope names, app keys, review ids, profiles, and units, served by
  a hidden `taema __complete` command. Available for bash, zsh, and fish.
- **Prompt segment.** `taema prompt` prints `⟲2 ❄1` (or nothing) from
  `$XDG_RUNTIME_DIR/taema/summary`, a one-line file the daemon rewrites on change. It makes no
  socket call. The target is < 5 ms with the Rust fast client and < 40 ms in Python.

### 10.4 Unit authoring without TOML archaeology

- **`taema unit new --from PID|SCOPE|APP [--name N]`.** Inspects the live process: exe,
  comm, cmdline, children, listening sockets, runtime dir, window `app_id`, and memory
  history. It writes a commented draft with suggested `[match]`, `[[children]]`, `[gc]`,
  `[mem]`, `[qos]`, and `[kill]` sections, opens it in `$EDITOR` when interactive, and
  validates it on save.
- **`taema unit test FILE|NAME`.** Shows which live processes match, which scope they would
  go to, and what GC, memory, and QoS rules would do right now. This is a dry run.
- **`taema unit lint`** checks:
  - the schema and unknown keys;
  - over-broad matches (for example `comm = "node"` alone);
  - `max` below the observed peak;
  - hooks that are not executable;
  - `never_stop` together with `stop_when_unneeded`.
- **`taema unit list`** shows each unit's source (system, user, or learned) and whether it
  is active. `enable`/`disable` mask a system unit with a user file (`mask = true`).
- **Learned unit suggestions.** After an app has 5 or more instances with consistent
  children (a VM child, a session child), `taema suggest` proposes a unit, and accepting it
  writes the file.
- **Unit packs.** `contrib/units/` holds curated units: vscode, jetbrains, android-emulator,
  podman, libvirt-qemu, docker-rootless, incus, virtualbox, steam, discord, and generic
  Electron. Install one with `taema unit install vscode`.

### 10.5 Live views

- **`taema top`.** A refreshing table over `subscribe`: scope, state (live, windowless,
  frozen, deprioritized), CPU%, MEM, Δmem/min, PSI, windows, decision. It can sort by any
  column, and `--once` prints a snapshot.
- **`taema tree [TARGET]`.** The cgroup tree with processes, windows, provenance arrows
  (`firefox ← niri`), and edges (`adb ⇠ studio: tcp 5037`).
- **Dashboard additions** are in §8.3.

### 10.6 History, reports, and suggestions

- **`taema history APP|SCOPE [--since]`.** A timeline of launches, window closes, survivors,
  reviews and answers, freezes and thaws, reclaims, stops, and regrets, with decision ids.
- **`taema report [--day|--week|--month] [--json]`** covers:
  - memory freed, split by reclaim and by stop;
  - automatic stops and answered stops;
  - undos and regrets;
  - the top leftover makers;
  - time spent frozen and thaws by connect;
  - guard events;
  - reviews answered and expired.

  It ends with at most 3 suggestions.
- **`taema suggest`.** A ranked, actionable list. Each item has an id, applied with
  `taema suggest apply S3`. Examples:
  - answer stale reviews;
  - create a unit for an app with stable children;
  - wrap frequently launched apps;
  - remove expired or unused vetoes;
  - enable zswap;
  - narrow earlyoom's `--prefer`;
  - raise `windowless_grace` for an app with regrets.

### 10.7 Safety nets the user can feel

- **Undo toast** after every automatic freeze, guard action, or stop (§9.2). `taema undo`
  (§6.5) covers every ladder stage.
- **Countdown** before a learned, non-explicit stop: "Stopping vite in 30 s · Keep". *Keep*
  records keep evidence and a 7-day suspension.
- **`taema recent`** lists the last 50 automatic actions with decision ids, freed memory,
  and whether a restore is possible.
- **`taema restore ID`** relaunches a stopped root in a fresh scope from its original cwd.
  This needs `remember_argv`. The environment is rebuilt from an allowlist (`PATH`, `HOME`,
  `LANG`, `LC_*`, `XDG_*`, plus `WAYLAND_DISPLAY`/`DBUS_SESSION_BUS_ADDRESS` when restored
  through the agent). It never reuses the original environment.
- **`taema --do-not-kill` with no target** acts on the most recent automatic action of any
  kind, including freezes and pending countdowns.

### 10.8 Data portability and reset

- **`taema backup [--to FILE]`.** A tarball of an SQLite online backup (`Connection.backup`),
  the user config, drop-ins, and user units. `taema restore-backup FILE` restores it after
  confirmation.
- **`taema learn export|import [--merge|--replace] [--redact]`.** A versioned, schema'd JSON
  file for moving to a new machine or sharing rules. Import shows a diff and needs
  confirmation. Imported answers are marked `source=import` and start in probation.
- **`taema reset --learning|--vetoes|--history|--all`.** Always takes a backup first.

### 10.9 Help, documentation, and support

- **Man pages** are written in scdoc (in the Void repos) and installed by the Makefile:
  `taema(1)`, `taema-agent(1)`, `taema.toml(5)`, `taema.unit(5)`, and `taema-learning(7)`.
- **`taema help TOPIC`** covers modes, learning, veto, ladder, memory, units, agent,
  profiles, and privacy.
- **`taema doctor --fix`** performs safe user-level fixes:
  - create directories and fix permissions;
  - enable controllers in `leftover/` and `shared/`;
  - install agent autostart;
  - migrate the store;
  - remove stale flag files.

  It prints the root-level fixes (`sudo …`) and runs them only with `--sudo`.
- **`taema bug-report`** writes a tarball with:
  - versions;
  - `doctor --json`;
  - the redacted config;
  - unit names;
  - daemon self-metrics;
  - the last 500 events with argv, cwd, and titles removed.

  It never includes environment values.
- **Daemon self-metrics** in `status --verbose`: RSS, CPU seconds, pass durations (p50 and
  p95), `ss` calls per minute, SQLite write time, event lag, and agent state.

### 10.10 Performance targets for everyday use

| Path | Today (measured, §1.6) | Target | How |
|---|---|---|---|
| `taema status` | 0.092 s | < 50 ms p50 | lazy imports; Rust client later |
| `taema --version` / `--help` | 0.093–0.102 s | < 30 ms | lazy imports |
| shell prompt, no pending question | builtin `[[ -e ]]`, 0 processes | unchanged | — |
| `taema prompt` segment | n/a | < 5 ms (Rust) / < 40 ms (Python) | summary file only |
| `taema launch` overhead | n/a (`run` ≈ 0.1 s) | < 30 ms | Rust fast path; agent-side launch |
| close → notification | n/a (no GUI path) | < 3 s with the agent | window events + batching |
| close detected | ≤ 15 s + 5 s `MIN_AGE` | < 1 s with agent/eventd; ≤ one adopt interval without | §11.4 |
| daemon RSS idle | 25.1 MB | ≤ 30 MB (Python core) | caps, SQLite instead of in-memory history |

---

## 11. Technology stack and architecture evolution

Revision 1 assumed the stack could not change: Python standard library only, a JSON store,
and polling. Revision 2 treats the stack as a design variable. Each decision below is
recorded as an ADR, with the options considered, the choice, and the reason.

### 11.1 Current stack (0.2.1)

| Layer | Today |
|---|---|
| Language | Python ≥ 3.11, standard library only (`tomllib`, `selectors`, `socket`, `json`) |
| Storage | `knowledge.json` (whole-file rewrite), `decisions.log` (JSON lines), `feedback.jsonl` |
| Config | TOML, read-only (`tomllib`); system file plus user file |
| IPC | JSON lines over `AF_UNIX`, `SO_PEERCRED` uid check, one request per connection |
| Events | `/proc` polling every 15 s with a fork gate; pidfd for owners; epoll on `cgroup.events` |
| Privileged code | `taema-attach`: Python `-I`, run through `sudo -n` |
| External tools | `ss` (iproute2), `setpriv`, `sudo`, runit |
| UI | plain-text CLI; shell hooks in bash, zsh, and fish; Python prompt client `taema-hook` |
| Packaging | Makefile + xbps-src `gnu-makefile`; signed XBPS repo from GitHub releases |
| CI | GitHub Actions in `void-glibc`; `unittest` (331 tests) |

### 11.2 Forces that drive change

- **Queries and history** (`why`, `history`, `report`, dashboard sparklines) need indexed
  storage with retention. Rewriting a whole JSON file does not scale to that.
- **Concurrent readers.** The CLI, dashboard, widget, and agent read while the daemon writes.
- **Event-driven reaction** to pressure, windows, and process births and exits.
- **Session access** for notifications and windows (§9).
- **Low-latency clients**: prompt segment, bar, launch wrapper, shell hook.
- **Safety of privileged code.** An interpreter running under sudo is a large attack surface
  for a tiny job.
- **Maintainability.** The surface roughly doubles (governor, agent, store, protocol), and
  typed contracts keep it correct.
- **Portability** across glibc and musl Void, and simple packaging on Void.

### 11.3 ADR-1 — Storage: SQLite (accepted)

| Option | Verdict |
|---|---|
| JSON v3 (revision 1) | rejected: no queries or retention, a whole-file rewrite, reader/writer races |
| **SQLite via stdlib `sqlite3`** | **accepted** |
| LMDB, RocksDB, or other non-stdlib stores | rejected: new runtime dependency, no SQL for reports |

**Decision.**

- The store is `~/.local/state/taema/state.db` in WAL mode, with `synchronous=NORMAL`,
  `busy_timeout=2000`, and `foreign_keys=ON`. The schema is in §13.2.
- There is one writer, the daemon, with one transaction per pass.
- Readers (CLI, dashboard, agent, bar) open `file:…?mode=ro` URIs.

**Why.**

- Queries and retention come with it.
- Concurrent readers without locks.
- Atomic commits for crash safety.
- It ships in the stdlib (`sqlite3` 3.53.4 here).
- JSON export stays easy, and the Rust components can read the same file later.

**Costs and mitigations.**

| Cost | Mitigation |
|---|---|
| Schema migrations | `PRAGMA user_version` with forward-only migration scripts |
| Corruption | `quick_check` on start; on failure rename the file and rebuild from the daily export (§13.9) |
| WAL growth | a passive checkpoint at idle |

**Audit.** `decisions.log` stays: append-only, greppable, and rotated. It is the audit trail.
The `events` table is a queryable index with retention.

### 11.4 ADR-2 — Event-driven collectors (accepted, staged)

| Source | Privilege | Latency | Status |
|---|---|---|---|
| pidfd (owner watch) | none | instant | exists |
| `cgroup.events` epoll (`populated`, `frozen`) | none | instant | exists; extended to `frozen` |
| PSI triggers (`memory.pressure` poll) | none (verified, §1.6) | ≤ 2 s window | new in M3 |
| niri `event-stream` through the agent | session | instant | new in M5 |
| `/proc` snapshot with fork gate | none | adopt interval | stays as the **reconciliation pass**; correctness never depends on an event arriving |
| netlink proc connector (`PROC_EVENT_FORK/EXEC/EXIT`) via `taema-eventd` | `CAP_NET_ADMIN`, so root | instant | new in M6, **optional** |
| eBPF (execsnoop-style) | root + BPF toolchain | instant | rejected: heavy build and runtime requirements, more than this job needs |
| fanotify | root for useful marks | — | rejected: not a process-lifecycle API |

**Design.** Collectors push typed events (`ProcBorn`, `ProcExited`, `WindowClosed`,
`PressureHigh`, `LeafEmpty`, `LeafFrozen`, …) into one in-process queue, and the selector
loop drains it. Handlers are idempotent, because a reconciliation pass may report the same
fact again.

**`taema-eventd`** is root and optional:

- one instance per system, under the existing runit service;
- subscribes to the proc connector and filters events by uid;
- forwards compact records `(event, pid, tgid, ppid, uid, ts)` to
  `/run/taema/events/<uid>.sock`, created by root with mode 0600 and owned by the user;
- keeps a bounded ring of 4096 events per consumer and drops for a slow consumer, with a
  counter;
- accepts no commands and makes no decisions.

With eventd, `MIN_AGE` stops being a polling artefact. Births are seen instantly, and the
5 s rule becomes a classification rule only.

### 11.5 ADR-3 — Language strategy: hybrid now, with a gate for a full port (accepted)

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| A. Python only (typed, modernized) | fastest iteration on heuristics that are still moving; reuses 331 tests; no new toolchain | ~25 MB RSS daemon; ~95 ms client start; an interpreter under sudo; weak guarantees for privileged code | the **core** stays here in v2 |
| **B. Hybrid: Python core + Rust edges** | memory-safe privileged code; < 5 ms clients; a tiny eventd; iteration speed kept where logic changes most | two toolchains; slower CI; boundaries must be process + protocol only (no FFI) | **chosen for v2** |
| C. Full Rust rewrite now | 3–8 MB footprint, one static binary, strong types, native D-Bus (`zbus`), `ratatui` | months before user value; re-porting 331 tests; learner heuristics not yet stable | **deferred** to gate G-Core |
| D. Go | static binaries, simple concurrency | GC'd daemon at 10–20 MB; no toolchain here; a weaker fit for tiny privileged binaries | rejected |
| E. Python + C extension | faster `/proc` scans | packaging pain, memory-unsafe | rejected |

**Rust components in v2** live in a `rust/` cargo workspace and produce binaries only:

1. **`taema-attach`**, the root helper, rewritten with an identical CLI and identical
   validation, plus the new `oom-restore` verb (§7.10).
   - Differential tests run the Python and Rust helpers against the same request corpus.
   - A fuzz target covers the argument parser.
   - The Python helper ships as a fallback for one release.
2. **`taema-fast`**, a multi-call binary for latency-critical paths:
   - `taema-hook` (done, kill, ask);
   - `taema prompt`;
   - `taema launch` (attach, register, exec);
   - `taema bar --follow`.

   The `taema` shell wrapper dispatches these subcommands to `taema-fast` when it is
   installed, and falls back to Python otherwise.
3. **`taema-eventd`**, the optional proc-connector forwarder (§11.4).
4. **Later, if needed:** `taema-agent` in Rust, if the Python agent misses its footprint.

**Contracts.** The only contracts between languages are the socket protocol (JSON Schema,
§14), the SQLite schema (§13.2), and command-line interfaces. That is what makes option C
possible later without a big-bang rewrite.

**Dependency policy for Rust:**

- no async runtime;
- crates limited to `libc`/`rustix`, `serde`, and `serde_json`, plus `toml` where config is
  read;
- vendored for offline xbps builds;
- `cargo audit` and `cargo deny` run in CI.

**Gate G-Core**, reviewed at the end of M7. The daemon core is ported to Rust if any of
these hold:

- idle RSS > 30 MB, or CPU > 0.2%, after the M7 optimizations;
- pass p95 > 100 ms with 300 scopes;
- 2 or more production defects per quarter that a type system would have caught;
- a need for a single static binary, for example musl-only or minimal installs.

The port uses the protocol contract tests and the decision replay corpus (§18) as the
executable spec. It follows a strangler order: collectors, then actuators, then policy and
the learner.

### 11.6 ADR-4 — Python modernization (accepted)

- **Version floor.** Stays at 3.11, as the README promises, because `tomllib` needs it. CI
  tests 3.11 and the current Void Python (3.14).
- **`pyproject.toml`** holds metadata and tool config only. The Makefile install layout and
  the xbps template do not change.
- **Tools:** `ruff` for lint and format; `mypy` strict for new modules and gradually for old
  ones, with per-module overrides.
- **Code style:** `dataclasses(slots=True, frozen=True)` for records, and `typing.Protocol`
  for pluggable parts (`WindowBackend`, `Notifier`, `Store`, `Collector`, `Actuator`).
- **Package layout.** The import root stays `taema`. Compatibility shims keep old imports
  working during the move.

```
taema/
  core/       cgroup.py proc.py edges.py runtime.py              kernel and /proc facts, no policy
  model/      identity.py provenance.py signature.py decide.py    pure logic, no I/O
  store/      db.py schema.sql migrate.py export.py feedback.py
  governor/   memory.py qos.py freeze.py guard.py budget.py       actuators with safety checks
  daemon/     loop.py collectors.py passes.py authorize.py api.py
  agent/      main.py notify.py launch.py windows/{niri,sway,hyprland}.py
  cli/        main.py targets.py render.py complete.py commands/*.py
  ui/         viewmodel.py dash.py bar.py report.py
  config/     load.py dropins.py write.py validate.py profiles.py
```

- **CLI startup.** The entry point imports only argparse and the command module it needs.
  This is how §10.10's latency target is met.

### 11.7 ADR-5 — IPC protocol v2 (accepted)

- JSON over `AF_UNIX` with `SO_PEERCRED` stays.
- Requests use an envelope: `{"v":2,"id":N,"cmd":…,"args":{…}}`.
- Replies: `{"v":2,"id":N,"ok":true,"result":…}` or
  `{"v":2,"id":N,"ok":false,"error":{"code":…,"message":…,"hint":…}}`.
- **Streaming.** `subscribe` keeps the connection open and pushes
  `{"v":2,"id":N,"seq":S,"event":…,"data":…}` lines. Clients resume from `seq` (§14.3).
- **Schemas** live in `schema/ipc/*.json`. They are validated in tests and mirrored by the
  serde types in the Rust clients.
- **Compatibility.** v1 one-shot messages (without `v`) are accepted for one release, so
  shells with old hooks keep working.
- **Rejected:** varlink (no Void library, small ecosystem); a D-Bus service (the daemon is
  outside the session; that is the agent's job); gRPC (heavy).

### 11.8 ADR-6 — Desktop stack (accepted)

- **Notifications.** `notify-send -A` by default; `python3-jeepney` as an optional richer
  backend; `gdbus` as a fallback (§9.2). No new mandatory dependency.
- **Windows.** niri IPC over the stdlib socket first; sway, i3, and Hyprland behind the same
  Protocol (§9.3).
- **Widget.** A QML plugin for DMS and quickshell in `contrib/dms/`. It is an
  example/contrib artifact, not a runtime dependency. waybar and i3bar JSON come from
  `taema bar`.
- **TUI.**
  - stdlib `curses` is the baseline.
  - **Textual** (`python3-textual` 8.2.7, in Void) was considered as an optional front-end
    over the same view model. It is deferred: it adds about 0.3 s of startup and more RSS,
    and it would mean two UIs to maintain.
  - **ratatui** comes in if G-Core ports the clients.

### 11.9 ADR-7 — Build, packaging, and CI (accepted)

**xbps template.**

- Keeps `build_style=gnu-makefile`.
- Adds `hostmakedepends="cargo scdoc"`. The Makefile builds `rust/` with
  `cargo build --release --offline` from vendored crates, which are shipped as a second
  distfile.
- `depends` is unchanged. `libnotify` is documented as optional, because Void has no
  "recommends" and the agent degrades without it.

**Subpackages:**

| Subpackage | Contents |
|---|---|
| `taema` | core, CLI, agent, `taema-fast`, Rust helper |
| `taema-eventd` | optional root forwarder plus its runit integration |
| `taema-contrib` (optional) | DMS widget and unit packs |

**CI matrix** (`void-glibc` and `void-musl` containers):

- `ruff check` and `ruff format --check`;
- `mypy`;
- `unittest`/`pytest` with coverage, at least 85% for new modules;
- `hypothesis` property tests;
- `cargo fmt --check`, `clippy -D warnings`, `cargo test`, and `cargo audit`;
- JSON Schema contract tests;
- the existing packaging tests;
- an `xbps-src pkg` build;
- an optional live-cgroup job (cgroup delegation inside CI containers varies).

**Release.** The existing tag workflow and signed repository stay. Release notes are
generated from the changelog plus a "behaviour changes" section, which is required whenever
mode semantics change.

### 11.10 Target architecture

```
                         ┌───────────────────────── root ─────────────────────────┐
 runit: taema service ──▶│ sv/taema/run: delegate user/<uid>, controllers          │
                         │ taema-eventd (Rust, optional): proc connector → per-uid │──┐ /run/taema/events/<uid>.sock
                         │ taema-attach (Rust): validated moves, oom-restore       │◀─┼── sudo -n (daemon, CLI)
                         └─────────────────────────────────────────────────────────┘  │
 per user (uid) ───────────────────────────────────────────────────────────────────────────────────┼──────────────
  taema daemon (Python)                                                                 │
   collectors: /proc reconcile · pidfd · cgroup.events · PSI triggers · eventd ◀────────┘ · agent windows
        │ typed events
        ▼
   provenance (instances, parents, signatures) ──▶ learner (decide, outcomes, reviews)
        │                                                   │
        ▼                                                   ▼
   authorize: hard rules → veto → hold → mode/profile → pair/unit authority → ladder stage
        │
        ▼
   actuators: contain · QoS · freeze/thaw · reclaim · budget · stop      (all veto/hold-aware)
        │
   store: state.db (SQLite WAL) + decisions.log (audit)      API: taema.sock (JSON v2 + subscribe)
                                                                  ▲        ▲         ▲        ▲
  clients: taema CLI (Python) · taema-fast (Rust: hook, prompt, launch, bar) · dash (curses)
           taema agent (session: notifications, niri windows, launches) · DMS widget (QML)
```

### 11.11 Stack migration path

| Milestone | Stack change |
|---|---|
| M0 | none (hotfix on the 0.2 code) |
| M1 | package restructure with shims; `pyproject.toml`, ruff, mypy; SQLite store and importer; protocol v2 envelope; CI matrix with musl |
| M2 | pure `model/` modules with property tests |
| M3 | PSI-trigger collector; `governor/` actuators; typed event queue |
| M4 | `subscribe` streaming; config drop-ins, reload, minimal TOML writer; curses view model |
| M5 | `agent/` package; niri backend; notifier backends (notify-send, jeepney) |
| M6 | `rust/` workspace: `taema-attach`, `taema-fast`, `taema-eventd`; template, vendoring, cargo CI |
| M7 | performance work; G-Core gate review; scdoc man pages |

---

## 12. Configuration and unit schema

### 12.1 `taema.toml` additions (all optional; old files keep working)

```toml
mode = "auto"

[learn]
enabled = true
authority = "learned"        # answered | learned | aggressive
silent_kills = 5
silent_days = 3
silent_ratio = 0.9
burn_in_days = 7
burn_in_closes = 20
probation_stops = 3
allow_self_authority = false
respawn_window = 60
revive_window = 1800
regret_window = 1800
regret_suspend_days = 7
ask_per_day = 3
ask_pair_gap_days = 7
ask_gui = true
review_ttl_days = 14
identity_denylist = ["MainThread", "Thread-*", "pool-*", "GC", "Finalizer", "sleep", "cat", "head", "sort", "grep", "true"]

[mem]
enabled = true
manage = "soft"
budget = "auto"
fraction = 0.80
floor = "512M"
min_headroom = "128M"
headroom_percent = 10
reclaim = true
reclaim_interval = 60
reclaim_cooldown = 300
reclaim_max = "2G"
idle_reclaim_grace = 300
pressure_gate = 10
pressure_ceiling = 60
swap_reclaim = true
zswap = true
oom_policy = "log"
probe = false                # D9: ask podman/virsh/incus for friendly names (extra processes)

[veto]
enabled = true
default_expiry = "0"
block_reclaim = true

[ui]
color = "auto"
dashboard_refresh = 2
events_tail = 200
# notifications: see [notify] (§12.5)

[review]
queue = true
prompt = true
prompt_interval = 86400
```

`[protected]` is unchanged and still union-only. `[seeds]` gains nothing required; `share`
and `persist` remain. A user file cannot remove a protected entry.

### 12.2 Unit schema additions

```toml
[unit]
name = "app-example"
kind = "app"              # app | scope
class = "vm"             # app | container | vm | service (new, optional)
stop_when_unneeded = true
survive_logout = false

[match]                   # unchanged
exe = "/usr/bin/example"

[[children]]              # unchanged
name = "session"
ancestor_comm = "example"
binds_to = "root"

[gc]
keep_while_children = true
env_dir_missing = "XDG_RUNTIME_DIR"
no_attach_grace = 120

[mem]                     # new, all optional
reservation = "2G"
high = "4G"
max = "6G"                # opt-in; validated against current + min_headroom
low = "1G"
swap_max = "2G"
idle_reclaim = true
min_headroom = "256M"
save_state = ["virsh", "managedsave", "%(domain)s"]
resume = ["virsh", "start", "%(domain)s"]
pause = ["podman", "pause", "%(container)s"]
resume_container = ["podman", "unpause", "%(container)s"]
oom_group = false

[kill]
graceful = 10
keep = ["adb"]
never_stop = false        # new: unit-level veto
```

Unknown keys are ignored with a warning in `taema doctor`; a malformed unit is skipped, never
fatal. Hooks are executed directly (no shell) with a timeout; values are substituted from
validated fields only.

### 12.3 Example units shipped

- `podman.toml` (extend with `[mem]`)
- `libvirt-qemu.toml`
- `docker-rootless.toml`
- `incus.toml`
- `virtualbox.toml`
- examples: `claude-desktop.toml`, `herdr.toml`, `android-emulator.toml` (updated with `[mem]`)

### 12.4 Undo/relaunch data

For `undo --restore` only, record `cwd` and `argv` (no env, no stdin) in the decision ring for
a stopped root. It is off by default (`[learn] remember_argv = false`); when off, `undo` adds
the veto/keep but does not relaunch. This is a privacy/behaviour trade-off, documented.

### 12.5 New configuration sections (revision 2)

```toml
[agent]
enabled = true
window_backend = "auto"      # auto | niri | sway | hyprland | none
windowless_grace = 30        # seconds after the last window closes (learned per app)
max_events_per_s = 50
store_titles = false         # window titles are never stored unless true

[notify]
enabled = true
backend = "auto"             # auto | notify-send | jeepney | gdbus | none
batch_seconds = 60
max_per_hour = 6
min_mem = "200M"
quiet_hours = "22:00-08:00"
ttl = 600
undo_toast_seconds = 30
countdown_seconds = 30       # warning before a learned (non-explicit) stop; 0 = off
digest = "off"               # off | daily

[freeze]
enabled = true
adopt = false                # freeze leftovers in adopt mode
after = 120                  # idle seconds before a contained leftover is frozen
wake_on_connect = true
max_frozen = 32
cpu_idle_max = 0.5           # percent over 60 s

[qos]
enabled = true
leftover_cpu_idle = true
leftover_io_weight = 10
background_cpu_weight = 50
focus_boost = false
focus_cpu_weight = 300
leftover_pids_max = 0        # 0 = unlimited

[guard]
enabled = true
available_floor = "auto"     # auto = earlyoom -m + 4 points, else 12%
psi_some = "150ms/2s"
psi_full = "50ms/2s"
cooldown = 10
freeze_in_adopt = false
oom_adj_leftover = 500
oom_adj_shared = 200
oom_group_leftover = true

[store]
path = "~/.local/state/taema/state.db"
retention_days = 90
sample_interval = 60         # seconds; samples written only on >5% change or every 10 min
max_events = 200000
daily_export = true          # state-export.json, 3 rotations, used for recovery

[learn]
remember_argv = false        # needed for `taema restore`

[experimental]
freeze = true
guard = true
window_close = true
launch_wrap = true
eventd = false

[profile]
active = "auto"              # auto | default | focus | battery | game | quiet | server | NAME

[profile.auto]
on_battery = "battery"
when_running = { gamescope = "game" }

[profile.game.notify]
enabled = false

[profile.game.freeze]
after = 0
```

All keys are optional, and the defaults are the values shown. `taema config show --sources`
prints the effective value and the file that set it.

### 12.6 Configuration layering and drop-ins

Files are merged in this order, later winning, except `[protected]`, which is always the
union:

1. built-in defaults;
2. `/etc/taema/taema.toml`, the system file; the root helper reads only this one;
3. `/etc/taema/taema.d/*.toml`, packaged or admin drop-ins, in lexical order;
4. `~/.config/taema/taema.toml`, hand-written and never rewritten by tæma;
5. `~/.config/taema/taema.d/*.toml`, where `10-setup.toml` comes from `taema setup` and
   `50-cli.toml` from `config set`, `mode`, and `profile`;
6. the active profile overlay;
7. runtime overrides: `hold`, `snooze`, and a manual profile, which live in memory and in
   `state.db`, never in TOML.

`TAEMA_CONFIG` still replaces all of these with one file, for tests.

### 12.7 Unit schema additions (revision 2)

```toml
[desktop]
app_id = "code"                  # window app_id(s) that belong to this unit
desktop_file = "code.desktop"    # used by `taema desktop wrap`
on_last_window = "ask"           # ask | quit | keep

[qos]
cpu_weight = 100
io_weight = 100
pids_max = 0

[freeze]
never = false                    # never freeze this unit (for example an audio daemon)
wake_on_connect = true

[mem]
swap_max = "0"                   # VMs default to 0 unless a save hook ran
```

---

## 13. Data model, storage, and migrations

### 13.1 Files

| Path | Writer | Purpose |
|---|---|---|
| `~/.local/state/taema/state.db` (+ `-wal`, `-shm`) | daemon | all learned state, history, and decisions (SQLite, WAL) |
| `~/.local/state/taema/decisions.log` (`.1`, `.2`) | daemon | append-only audit (JSON lines), rotated at 1 MiB, 3 files |
| `~/.local/state/taema/feedback.jsonl` | CLI | offline mutations, replayed by the daemon |
| `~/.local/state/taema/state-export.json` (`.1`, `.2`) | daemon | daily logical export, used for recovery and support |
| `~/.local/state/taema/knowledge.json.v2-backup` | migration | the 0.2.x store, kept 30 days after migration |
| `$XDG_RUNTIME_DIR/taema/q.<shellpid>` | daemon | a pending shell question (unchanged) |
| `$XDG_RUNTIME_DIR/taema/summary` | daemon | a one-line status for `taema prompt` and quick reads (`reviews=2 frozen=1 hold=0`) |
| `$XDG_RUNTIME_DIR/taema/HOLD` | daemon/CLI | hold flag readable while the daemon is down |
| `$XDG_RUNTIME_DIR/taema/agent.lock` | agent | single-instance lock |

Directory modes are 0700 and file modes 0600. Nothing is world-readable.

### 13.2 Schema (`PRAGMA user_version = 5`)

```sql
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);   -- created, closes, last_decay

CREATE TABLE apps (
  key TEXT PRIMARY KEY, kind TEXT NOT NULL,            -- unit | exe | interp | container | vm | desktop | legacy
  display TEXT, exe TEXT, dev INTEGER, ino INTEGER, desktop_id TEXT, unit TEXT,
  first_seen REAL, last_seen REAL, instances INTEGER NOT NULL DEFAULT 0,
  on_last_window TEXT NOT NULL DEFAULT 'ask', windowless_grace REAL,
  confidence TEXT NOT NULL DEFAULT 'high');            -- low for imported legacy keys

CREATE TABLE instances (
  id TEXT PRIMARY KEY,                                 -- "pid.start"
  app TEXT NOT NULL REFERENCES apps(key), pid INTEGER, start INTEGER,
  born REAL, windowless REAL, exited REAL, parent_app TEXT, scope TEXT,
  terminal INTEGER, class TEXT, runtime TEXT,
  launched_by TEXT,                                    -- launch | adopt | unit | run
  parent_evidence TEXT NOT NULL DEFAULT '[]',           -- per-instance evidence set (JSON)
  last_seen REAL,                                       -- most recent pass that saw the pid/start
  survivors TEXT);                                     -- signature id
CREATE INDEX instances_app_born ON instances(app, born);

CREATE TABLE parents (
  app TEXT, parent TEXT, co_birth INTEGER, cgroup INTEGER, job INTEGER, runtime INTEGER,
  window INTEGER, launch INTEGER, last REAL, PRIMARY KEY (app, parent));
CREATE INDEX parents_last ON parents(last);

CREATE TABLE signatures (
  id TEXT PRIMARY KEY, owner TEXT NOT NULL, members TEXT NOT NULL,  -- JSON [[key,count],...]
  runtime TEXT, runtime_hash TEXT, tty INTEGER,
  kind TEXT NOT NULL DEFAULT 'exit',                             -- exit | windowless
  veto INTEGER NOT NULL DEFAULT 0,                                  -- signature veto outcomes
  closes INTEGER DEFAULT 0, stop_ok INTEGER DEFAULT 0, respawn INTEGER DEFAULT 0,
  ex_stop REAL DEFAULT 0, ex_keep REAL DEFAULT 0, ex_last TEXT, first_seen REAL, last_seen REAL);
CREATE INDEX signatures_owner ON signatures(owner);

CREATE TABLE pairs (
  owner TEXT, leftover TEXT, sig TEXT,
  stop REAL DEFAULT 0, keep REAL DEFAULT 0, ex_stop REAL DEFAULT 0, ex_keep REAL DEFAULT 0,
  ex_last TEXT, ex_ts REAL, closes INTEGER DEFAULT 0, kills INTEGER DEFAULT 0,
  launches INTEGER DEFAULT 0, stop_ok INTEGER DEFAULT 0, respawn INTEGER DEFAULT 0,
  days TEXT, probation INTEGER DEFAULT 0, first_seen REAL, last_seen REAL,
  last_asked REAL DEFAULT 0, last_auto_stop REAL DEFAULT 0, last_keep REAL DEFAULT 0,
  suspended_until REAL DEFAULT 0,
  source TEXT DEFAULT 'observed',                      -- observed | answer | import | legacy | legacy-invalid
  PRIMARY KEY (owner, leftover));

CREATE TABLE exes (key TEXT PRIMARY KEY, counters TEXT, term_exit_ms TEXT,
                   idle_grace_scale REAL DEFAULT 1.0, stops INTEGER DEFAULT 0, last_seen REAL);
CREATE TABLE standalone (key TEXT PRIMARY KEY, n INTEGER, ts REAL);
CREATE TABLE vetoes (id TEXT PRIMARY KEY, kind TEXT NOT NULL, match TEXT NOT NULL,
                     created REAL, expires REAL, reason TEXT, source TEXT);
CREATE TABLE reviews (id TEXT PRIMARY KEY, kind TEXT, owner TEXT, sig TEXT, scope TEXT,
                      pids TEXT, mem INTEGER, created REAL, expires REAL, shown REAL,
                      state TEXT NOT NULL DEFAULT 'open');   -- open | answered | expired
CREATE TABLE decisions (
  id INTEGER PRIMARY KEY, ts REAL,
  kind TEXT,                                           -- contain | qos | freeze | thaw | reclaim | stop | guard | veto | undo
  scope TEXT, owner TEXT, sig TEXT, stage INTEGER, authority TEXT, why TEXT,
  freed INTEGER, undo TEXT, argv TEXT, cwd TEXT, undone REAL);  -- argv/cwd only with remember_argv
CREATE TABLE events (seq INTEGER PRIMARY KEY, ts REAL, event TEXT, decision_id INTEGER, data TEXT);
CREATE INDEX events_ts ON events(ts);
CREATE TABLE mem_samples (scope_key TEXT, ts REAL, current INTEGER, anon INTEGER, file INTEGER,
                          swap INTEGER, zswap INTEGER, psi10 REAL, PRIMARY KEY (scope_key, ts));
CREATE TABLE mem_rollup (app TEXT, day INTEGER, current_p50 INTEGER, peak INTEGER,
                         reclaimed INTEGER, freed INTEGER, frozen_s INTEGER, PRIMARY KEY (app, day));
CREATE TABLE asked (day INTEGER PRIMARY KEY, n INTEGER);
CREATE TABLE frozen (scope TEXT PRIMARY KEY, since REAL, listeners TEXT, decision_id INTEGER);  -- crash recovery
CREATE TABLE oom_adj (pid INTEGER, start INTEGER, original INTEGER, applied INTEGER, PRIMARY KEY (pid, start));
```

`model/decide.py` stays a pure function over plain records, as `knowledge.decide()` is
today. The store maps rows to records and back. Tests of the decision logic never need a
database.

### 13.3 Write path and cost

- One transaction per pass (adopt, GC, memory, guard), plus one immediately after an
  explicit answer, veto, or undo. This keeps the 0.2.x rule that answers are saved at once.
- Prepared statements and `executemany` for batches.
- Memory samples are written only when a value changes by more than 5%, or every 10 minutes.
- Rollups are computed on the first pass after midnight, and retention pruning runs hourly.
- `PRAGMA wal_checkpoint(PASSIVE)` runs when the daemon has been idle for 60 s.
- Expected idle load: under 200 row writes per hour and under 5 ms of SQLite time per pass.
  `status --verbose` reports the measured numbers.

### 13.4 Retention and caps

| Table | Cap | Retention |
|---|---|---|
| `instances` | 50,000 rows | 90 days since exit or last observation; answer/veto-referenced rows are protected |
| `events` | 200,000 rows | 90 days |
| `decisions` | 10,000 rows | 180 days, longer when referenced by a veto or an undo |
| `mem_samples` | — | 7 days raw |
| `mem_rollup` | — | 365 days |
| `apps` | 2,000 rows | LRU by `last_seen`; apps with answers or vetoes are never evicted |
| `pairs` | 1,000 rows | weight-0 pairs pruned after 30 days |
| `signatures` | 256 per owner | LRU by `last_seen` |
| `vetoes` | 512 | until expiry |
| `reviews` | 128 open | answered and expired rows: 30 days |

### 13.5 Migration from 0.2.x

The migration runs once, on the first start of a v2 daemon with no `state.db`:

1. Copy `knowledge.json` to `knowledge.json.v2-backup`.
2. Import `exes`, `pairs`, `standalone`, `asked`, `created`, and `closes` into the matching
   tables, with `source='legacy'`. Apps are created with `kind='legacy'` and
   `confidence='low'`.
3. Pairs whose owner fails `identity_ok()` (§6.2) are not used for decisions. On this
   machine those are `MainThread > sh/sort/head` and the `sleep > …` pairs. They are kept
   with `source='legacy-invalid'` and listed by `taema learn show --legacy`. The one
   explicit answer among them becomes a review, so the user can re-confirm it against a real
   app.
4. Import the last 10,000 lines of `decisions.log` into `events`, best effort.
5. Stop writing `knowledge.json`. It is left in place, and the release notes say so.

The import is idempotent. A crash mid-way rolls back the single transaction, and the next
start retries.

### 13.6 `feedback.jsonl` v2 ops

`{"v":2,"op":…,"id":…,…}` with `op` one of `keep`, `forget`, `kill`, `veto`, `unveto`,
`undo`, `answer`, `teach`, `mute`, `hold`, `snooze`.

- Only these offline-safe ops are queued. Mode and profile changes go to TOML drop-ins
  instead.
- The daemon replays the file with the existing rename-and-replay pattern. Ops are
  idempotent by `id`, and invalid lines are skipped and counted.
- The CLI enforces queued vetoes and holds locally (§6.4).

### 13.7 Decision log v2 schema

Every event carries `ts`, `event`, `mode`, `profile`, `decision_id` (when relevant), `corr`,
and `why`, plus a payload. These events are new in revision 2:

- reviews: `review_queued`, `review_answered`, `review_expired`;
- vetoes and undo: `veto`, `vetoed`, `undo`;
- stops: `stop_planned`, `stop_outcome`;
- the action ladder: `contain`, `qos`, `freeze`, `thaw` (with `reason`);
- memory: `reclaim`, `reclaim_failed`, `warm`, `oom`, `rebalance`, `gc_quit`, `freed`,
  `guard`;
- desktop: `window_close`, `windowless`, `agent_up`, `agent_down`, `notify_sent`,
  `notify_result`, `launch`;
- control: `hold`, `resume`, `profile`, `reload`, `config_invalid`, `doctor`;
- store: `store_migrated`, `store_recovered`.

Old events stay readable.

### 13.8 Downgrade

A 0.2.x binary ignores `state.db` and falls back to `knowledge.json.v2-backup` once it is
renamed back, which means stale state. The documented path is:

```sh
taema learn export --format v2 > ~/.local/state/taema/knowledge.json
```

That writes a 0.2-compatible file (exes, pairs, standalone) before the package is
downgraded.

### 13.9 Corruption and recovery

- `PRAGMA quick_check` runs at start.
- On failure, the daemon:
  1. renames the database to `state.db.corrupt-<ts>`;
  2. creates a fresh schema;
  3. imports the newest `state-export.json`, falling back to the v2 backup;
  4. logs `store_recovered`;
  5. raises a one-time notification.
- If the database is locked for more than `busy_timeout`, that pass is skipped, logged, and
  retried. The daemon never blocks the selector loop on SQLite for more than 2 s.

---

## 14. Daemon and socket protocol

### 14.1 New commands

All requests are one JSON line; replies are one JSON object; peer uid must be the user. Add a
`protocol: 2` field to every reply. New commands (idempotent where noted):

| Command | Payload | Reply |
|---|---|---|
| `status` | `{json:bool}` | mode, hold, counts, memory summary, review count, version |
| `why` | `{target}` | provenance/decision object |
| `learn` | `{view, limit}` | apps/pairs/signatures |
| `memory` | `{view}` | host/leaf stats, budget |
| `review` | `{}` | pending entries |
| `answer` | `{id, choice}` | applied |
| `veto` | `{match, expires, reason}` | id |
| `unveto` | `{id}` | ok |
| `undo` | `{decision_id?, last:bool}` | ok |
| `hold` / `resume` | `{scope?}` | ok |
| `stop` | `{scope, dry_run, force_veto}` | report (veto-aware) |
| `gc` | `{dry_run, memory}` | candidates |
| `events` | `{since, limit, event[]}` | rows |
| `doctor` | `{}` | checks |
| `config` | `{}` | merged config + sources |
| `subscribe` | `{topics[], since_seq?}` | stream of `{seq, event, data}` lines (§14.3) |
| `reload` | `{}` | `{ok, sources, errors[]}` |
| `mode` / `profile` | `{set?}` | effective value, reason, capability diff |
| `freeze` / `thaw` | `{target, dry_run}` | ladder report |
| `launch_prepare` | `{app, unit?, scope?}` | leaf path, instance id |
| `register_agent` | `{session, caps[], backend}` | agent id, heartbeat interval |
| `window_event` | `{kind, window_id, app_id, pid, focused, ts}` | ack (rate-limited) |
| `notify_result` | `{nonce, action}` | applied / expired |
| `history` / `report` / `suggest` | `{target?, since?, period?}` | rows / report / suggestions |
| `unit_test` | `{path or name}` | matches and would-actions |
| `recent` / `restore` | `{limit}` / `{decision_id}` | rows / launch result |

Revision 2 adds streaming subscriptions (§14.3), so the dashboard, bar, widget, and agent
react to changes instead of polling.

### 14.2 Safety

- Keep the 0.5 s request read and 64 KiB cap.
- Validate every field; reject unknown keys with `error` (do not crash).
- `veto`, `answer`, `undo`, `hold` require the caller's uid; no remote socket.
- Dry-run flags never write knowledge (except the audit line).
- Every mutating reply includes the `decision_id` and the effective mode/authority.

### 14.3 Subscriptions

- `subscribe {topics: ["status","scopes","reviews","decisions","memory","guard","profile"], since_seq}`
  keeps the connection open. The daemon writes one JSON line per event, with a monotonically
  increasing `seq` taken from the `events` table.
- On reconnect, a client sends `since_seq` and receives what it missed, up to 1,000 events.
  Beyond that it gets a `resync` event and should fetch a snapshot.
- At most 16 subscribers. Each has a bounded queue of 4,096 events, and a slow subscriber is
  disconnected with `error: slow_consumer`.
- Snapshots (`status`, `scopes`) are computed from the same view model as `dash --json`
  (§8.3), so every surface agrees.

### 14.4 Agent messages

- The agent registers once per connection. `window_event` and `notify_result` are accepted
  only on a registered agent connection, from the same uid.
- Heartbeats run every 30 s. After 3 missed beats, the agent is marked down, window-based
  classification falls back to process-only, and nothing pending is decided on stale window
  data.
- `launch_prepare` returns a leaf the agent (or `taema launch`) moves into before `exec`. The
  daemon records `launched_by=launch` and the requested app name, and expects the pid to
  arrive within 5 s, after which the empty leaf is removed.

---

## 15. Security, privacy, and threat model

### 15.1 Assets

- **Availability of the user's processes.** A wrong stop can lose unsaved work.
- **The privilege boundary**: the root helper, `taema-eventd`, and the runit service.
- **Privacy of history**: app usage times, command lines (opt-in), and window titles
  (opt-in).
- **Integrity of learned rules**, so a poisoned store cannot cause mass stops.

### 15.2 Trust boundaries

```
root:         runsv/sv run · taema-eventd · taema-attach  ── validated requests only ──▶ kernel
uid:          daemon ◀── AF_UNIX + SO_PEERCRED (same uid) ──▶ CLI · dash · bar · taema-fast · agent
session:      agent ◀──▶ session D-Bus (notification server) · niri socket
user-defined: units, hooks, profiles (user-owned files; hooks run as the user)
```

### 15.3 Threats and mitigations

| Threat | Mitigation |
|---|---|
| Another same-uid process drives the daemon socket | That process can already signal your processes, so tæma adds no new power. The helper still moves only same-uid processes. The socket is 0600 and peer-checked. Documented. |
| Another user or a remote party reaches the socket | `SO_PEERCRED` uid check; no TCP listener; the web view (§8.4) binds localhost with a random token, is read-only, and sets CSP with no CORS |
| Spoofed notification actions | answers are bound to a per-review nonce with an expiry. The jeepney backend checks that `ActionInvoked` comes from the unique bus name that owns `org.freedesktop.Notifications`. notify-send reads its own child's stdout. |
| Malicious or broken unit or hook | units in `/etc` are root-owned, user units are user-owned; hooks are exec'd directly with an argv list (no shell), templated only from validated fields, run in their own process group with a timeout, and `unit lint` flags risks |
| Root helper exploitation | Rust rewrite; strict parsing; no environment use; absolute paths; uid, pid-owner, cgroup-prefix, and protected checks as today; `oom-restore` limited to values recorded at contain time; fuzzing and differential tests (§18) |
| `taema-eventd` abuse | read-only stream; per-uid sockets created by root at mode 0600; events filtered to that uid; bounded memory; no request parsing beyond connect |
| Freeze as denial of service | never freeze with edges, windows, audio, or protected members; wake-on-connect; `max_frozen`; thaw on hold, veto, focus, and exit; crash recovery thaws |
| `oom_score_adj` misuse | only raised, only on contained leftovers and shared helpers; restoring goes through the validated helper |
| Store poisoning (crafted import) | imports are schema-validated, start in probation, need confirmation, and are marked `source=import`; probation never allows SIGKILL |
| Privacy leaks | titles and argv off by default; retention limits; `export --redact` and `bug-report` strip argv, cwd, titles, and env; 0600/0700 modes; no network |
| Supply chain | no third-party Python runtime dependencies by default; Rust crates minimal, vendored, and checked with `cargo audit`/`deny`; signed XBPS repository (existing) |

### 15.4 Process

- A security review of `taema-attach` (Rust) and `taema-eventd` before the M6 release.
- `SECURITY.md` with a disclosure contact. CVE-style notes in the release notes when a fix
  touches the privilege boundary.
- Every new socket command gets a fuzz case in the protocol fuzz suite.

---

## 16. File-by-file implementation map

| Path | Work |
|---|---|
| `src/taema/core/{cgroup,proc,edges,runtime}.py` | split from `cgroup.py`/`inspect.py`; memory, QoS, and freeze file helpers; `subtree_control`; new edge kinds (QMP, podman/docker/incus API sockets, PipeWire client, ESTAB TCP) |
| `src/taema/model/{identity,provenance,signature,decide}.py` | `identity_ok`, `AppIdentity`, instances, parents, signatures, matching; pure `decide()` v3 with per-pair burn-in, probation, and outcomes |
| `src/taema/store/{db,schema.sql,migrate,export,feedback}.py` | SQLite store, migrations, 0.2 importer, export/import, backup, feedback v2 |
| `src/taema/governor/{memory,budget,qos,freeze,guard}.py` | leaf stats, feature flags, reclaim ladder, budget, QoS writes, freeze/thaw with wake-on-connect, PSI guard, `oom_score_adj` shaping |
| `src/taema/daemon/{loop,collectors,passes,authorize,api}.py` | selector loop, typed event queue, adopt/GC/memory passes, the one authorization ladder, protocol v2 with subscribe and agent messages |
| `src/taema/agent/{main,notify,launch}.py`, `agent/windows/{niri,sway,hyprland}.py` | session agent, notifier backends, window backends, agent-side launch |
| `src/taema/cli/{main,targets,render,complete}.py`, `cli/commands/*.py` | command registry, fuzzy targets, renderers, errors, exit codes, completions, all commands in §8.1 |
| `src/taema/ui/{viewmodel,dash,bar,report}.py` | shared view model, curses dashboard, bar feed, reports |
| `src/taema/config/{load,dropins,write,validate,profiles}.py` | layering, drop-ins, minimal TOML writer, validation with `file:line`, profiles and auto-switch |
| `src/taema/{engine,daemon,knowledge,lineage,policy,inspect,cgroup,cli}.py` | compatibility shims that re-export from the new modules for one release |
| `rust/Cargo.toml`, `rust/attach/`, `rust/fast/`, `rust/eventd/`, `rust/fuzz/` | Rust workspace (§11.5) |
| `libexec/taema-attach` | Rust binary; the Python version stays as `taema-attach.py` for one release |
| `libexec/taema-hook` | becomes a symlink to `taema-fast` (Python fallback kept) |
| `libexec/taemad-user` | unchanged, except that it exports `TAEMA_EVENTS_SOCKET` when eventd is enabled |
| `sv/taema/run` | optional eventd start (`TAEMA_EVENTD=1` in `conf`); creates `/run/taema/events/` |
| `shell/taema.{bash,zsh,fish}` | review hint, `taema prompt` support, completions sourcing |
| `completions/{taema.bash,_taema,taema.fish}` | new |
| `contrib/dms/` | DMS/quickshell widget (QML) and README |
| `contrib/units/*.toml` | unit packs (§10.4) |
| `contrib/autostart/taema-agent.desktop`, `contrib/niri/taema.kdl` | agent autostart examples |
| `etc/taema.toml`, `etc/taema.d/` | new sections with safe defaults; a packaged drop-in directory |
| `etc/units/*.toml` | podman `[mem]`/`[qos]`; libvirt-qemu; docker-rootless, incus, virtualbox as examples |
| `schema/ipc/*.json`, `schema/export.json` | JSON Schemas for protocol v2 and the export format |
| `docs/man/*.scd` | scdoc man pages (§10.9) |
| `docs/design.md`, `taema/README.md`, `README.md` | rewritten for v2: modes, ladder, memory, agent, profiles, migration |
| `docs/adr/0001-…md` … `0007-…md` | the ADRs from §11 as individual files |
| `pyproject.toml` | tool config (ruff, mypy, coverage); no runtime dependencies |
| `Makefile` | install the new layout, Rust binaries, man pages, completions, contrib; `make check` runs everything in §18.4 |
| `srcpkgs/taema/template` | `hostmakedepends`, vendored crates distfile, subpackages, `conf_files` for new units and drop-ins |
| `.github/workflows/{ci,release}.yml` | glibc + musl matrix, Python and Rust jobs, xbps build |
| `tests/…` | see §18 |

**Size estimate:** about 6,000–8,000 new or changed lines of Python, 2,000–3,000 lines of
Rust, 4,000–5,000 lines of tests, and 2,000 lines of docs and man pages.

---

## 17. Milestones, sequencing, and acceptance criteria

### 17.1 Overview

| Milestone | Theme | Days (one developer) | Release |
|---|---|---|---|
| M0 | Honest `adopt` and safety hotfix | 3–5 | 0.3.0 |
| M1 | Foundations: SQLite, restructure, tooling, protocol v2 envelope | 6–9 | 0.4.0 (with M2) |
| M2 | Provenance learner, signatures, veto, undo, review, `why` | 8–12 | 0.4.0 |
| M3 | Resource governor: memory, QoS, freeze, guard, containers and VMs | 12–18 | 0.5.0 |
| M4 | Commands, dashboard, live config, subscriptions | 8–12 | 0.6.0 |
| M5 | Desktop and session: agent, notifications, windows, launch, widget | 8–12 | 0.7.0 |
| M6 | Native components in Rust: helper, fast client, eventd | 8–12 | 0.8.0 |
| M7 | QoL completion, hardening, dogfood, G-Core gate | 8–12 | 1.0.0 |
| **Total** | | **61–92** | |

**Dependencies:**

```
M0 ──▶ M1 ──▶ M2 ──┬──▶ M4 ──▶ M5 ──┐
                   └──▶ M3 ─────────┼──▶ M7
       M1 ──▶ M6 (needs protocol v2) ┘
```

**Two-developer plan (about 2–3 months).**

- Track A (core): M0 → M1 → M2 → M3 → M7 (learning and governor items).
- Track B (surface): starts after M1, then M4 → M5 → M6 → M7 (QoL and docs items).
- The tracks meet at M7.

**Feature flags.** Risky behaviour ships behind `[experimental]` keys for one release, and
then moves to the normal config. The flags are `freeze`, `guard`, `window_close`,
`launch_wrap`, and `eventd`. `taema doctor` lists the flags that are on.

### 17.2 M0 — Honest `adopt` and safety hotfix (3–5 days, 0.3.0)

**Changes**

1. Adopt-all app roots in `adopt`, `auto`, and `enforce`. Keep the 64-per-pass cap and the
   5 s, session-leader, pty, and unit filters.
2. In `adopt`, contain survivors in `leftover/`, queue a review (stored in the 0.2 JSON store
   until M1), and never stop on an unlearned pair. Owner-bound scopes (`--bind`/`--owner`)
   stop gracefully in `adopt`.
3. Remove the unlearned idle stop from `auto`; such leftovers are reviewed instead.
   `leftover_expire_days = 0` (off) remains available as an option.
4. Make `auto` stop idle `shared/*` and unit `stop_when_unneeded` scopes, with veto, hold,
   edge, CPU, and pty checks. Deduplicate `gc_would_stop`/`would_stop` with `store.changed`.
5. Add the identity denylist (`MainThread`, thread names, version strings, shells, trivial
   commands). Launcher closes no longer create pairs.
6. Add a minimal `taema do-not-kill` and `taema undo`, enforced offline. `status` shows
   reviews.
7. `ls` gains MEM and PSI columns.

**Acceptance**

- In a live `adopt` session, a GUI close with a leftover appears under `leftover/` within one
  adopt interval. `taema review` lists it, `taema do-not-kill` blocks a later `taema kill`,
  and a relaunch is not stopped.
- `taema run --bind` stops its scope on owner exit in `adopt`.
- An unlearned leftover in `auto` is kept and reviewed after `idle_grace`. The test that
  asserted the old idle kill now asserts "kept + review".
- In `auto`, an idle podman pause scope whose runtime dir is gone is stopped within one GC
  pass, or kept if vetoed. In `adopt` the same scope is reviewed.
- 24 h in `adopt` produce zero repeated `gc_would_stop` lines for an unchanged leaf.
- All 331 existing tests pass, plus the new M0 tests. `observe` still writes nothing.

**Exit artifacts:** a release note titled "adopt now contains and asks"; an updated README
mode table.

### 17.3 M1 — Foundations (6–9 days)

**Changes**

- Package restructure (§11.6) with shims; `pyproject.toml`; ruff and mypy, strict on new
  modules.
- SQLite store (§13.2) behind the existing `Store` API, so callers do not change yet.
- The 0.2 importer (§13.5); daily export; recovery path (§13.9).
- Protocol v2 envelope with v1 compatibility, and JSON Schemas for existing commands.
- CI on the glibc + musl matrix, with coverage.

**Acceptance**

- The migration on a copy of the live store gives identical `pair_decision` results for
  every valid legacy pair. Invalid-owner pairs are marked, and their answer becomes a review.
- Killing the daemon mid-pass (SIGKILL) loses at most the current pass and never corrupts the
  store; this is checked 100 times in a loop test.
- The CLI reads `state.db` while the daemon writes, with no `database is locked` errors in
  a 10-minute stress test.
- Daemon RSS stays ≤ 30 MB with a 50k-row database.

**Exit artifacts:** ADR files 0001–0007; a schema document; migration notes.

### 17.4 M2 — Provenance learner (8–12 days)

**Changes**

- `model/identity`, `provenance`, and `signature`; parent evidence; instance ledger.
- Review queue for GUI closes; `review`, `answer`, and `teach`; the shell prompt hint.
- Outcome loop (`stop_ok`, `respawn`), per-pair burn-in, probation, corrected regret.
- `why` renderer, `learn` views, decision ids.
- Full veto grammar with precedence and expiry; `undo`; `restore` behind `remember_argv`.

**Acceptance**

- `taema why` explains a close with the app identity, parent chain, signature, evidence,
  last outcome, vetoes, and what each mode would do.
- One explicit "stop" on a signature applies to a renamed survivor set with the same
  signature, and never to a different one.
- A pair created today cannot become silent-stop because the store is old.
- Regret only triggers for the same pair or signature.
- `taema do-not-kill` works with the daemon down, and the refusal exits with code 4.
- `taema undo` after an automatic stop restores `keep` and blocks the next stop.
- After migration plus one week, there are zero generic owners in active pairs.

**Exit artifacts:** a decision replay corpus built from the live log; the man page draft
`taema-learning(7)`.

### 17.5 M3 — Resource governor (12–18 days)

**Changes**

- `governor/memory`: accounting, feature flags, `taema memory`, budget, reclaim ladder,
  warm/thrash control, safety guards.
- `governor/qos`: classes, weights, `cpu.idle`, enabling controllers in `leftover/` and
  `shared/`.
- `governor/freeze`: eligibility, freeze/thaw, wake-on-connect, crash recovery; `freeze` and
  `thaw` commands.
- `governor/guard`: PSI triggers, available floor, guard ladder, `oom_score_adj` shaping,
  `memory.oom.group`, earlyoom detection, `doctor` advice; the helper `oom-restore` verb
  (Python first).
- Container and VM units (podman, libvirt-qemu, plus examples), quit detection, save and
  pause hooks, rebalance on exit, `gc --memory`.
- The swap/zswap advisor in `doctor`.

**Acceptance**

- `taema memory` reports current, peak, anon, file, swap, zswap, reclaimable, and PSI per
  scope, plus the budget.
- Freeze: a frozen `python3 -m http.server` is thawed by an incoming connection in ≤ 3 s, and
  the client request succeeds.
- Freeze is never applied to a scope with a window, an audio client, or an edge (test
  matrix).
- Guard: under a synthetic memory hog in a test scope, the guard reclaims and freezes before
  `MemAvailable` drops below the floor. Leftovers carry `oom_score_adj` 500. earlyoom (if it
  fires) picks the leftover.
- A fake libvirt domain with `save_state` saves and stops only when no client holds the QMP
  socket.
- No code path writes `memory.max` below `current + min_headroom`. A veto blocks freeze,
  reclaim, and stop.
- Idle daemon ≤ 30 MB RSS and ≤ 0.2% CPU with sampling and triggers enabled.

**Exit artifacts:** a memory section in the README; `doctor` checks for every kernel feature
in §7.1.

### 17.6 M4 — Commands, dashboard, live config (8–12 days)

**Changes**

- CLI framework: registry, fuzzy targets, renderers, errors, exit codes, `--json`/`--jsonl`,
  and the pager.
- Every command in §8.1 except the M5/M6 ones; completions; `doctor`, `events`, `config`.
- Hot reload, drop-ins, the minimal TOML writer, `mode`, `profile` (manual), `snooze`,
  `hold`.
- `subscribe` streaming; the view model; the curses `dash`; `top`; `tree`.
- Lazy imports to meet §10.10.

**Acceptance**

- `taema mode adopt` switches the running daemon without sudo, in under 1 s, and
  `status` shows the change.
- An invalid edit keeps the old config and shows `file:line`.
- `dash --once` output is deterministic (golden test), and `dash` actions go through the
  socket and respect vetoes.
- Every read command has `--json`, validated against its schema.
- `taema status` p50 < 50 ms over 100 runs on this machine.

**Exit artifacts:** draft man pages `taema(1)` and `taema.toml(5)`; a completions install.

### 17.7 M5 — Desktop and session integration (8–12 days)

**Changes**

- `taema agent` with lifecycle, registration, heartbeats, and its leaf.
- Notifier backends (notify-send, jeepney, gdbus); notification kinds and policy.
- The niri window backend; windowless lifecycle in the learner; focus classification; thaw
  on focus.
- `taema launch`, `launch_prepare`, agent-side launch, `taema desktop wrap/unwrap/list`.
- `taema bar` and the DMS widget in `contrib/dms/`; profile auto-switch (battery, process).

**Acceptance**

- With the agent running under niri, closing the last window of a test app that leaves a
  child produces a review notification within 3 s. Clicking *Stop* applies the answer.
- An app with `on_last_window = quit` is stopped after `windowless_grace`. Reopening a
  window during the grace cancels the stop.
- A launch through a wrapped desktop entry is born in its scope. `taema why` shows
  `launched_by=launch` and the right `desktop_id`.
- Killing the agent degrades to process-only mode without errors. Restarting it re-registers
  within 30 s.
- Notification volume stays within `max_per_hour` under a scripted storm of 50 closes.

**Exit artifacts:** `taema-agent(1)`; a widget screenshot; an autostart snippet for niri.

### 17.8 M6 — Native components (8–12 days)

**Changes**

- The `rust/` workspace and CI jobs; vendored crates; template changes.
- `taema-attach` in Rust with a differential test corpus, a fuzz target, and `oom-restore`.
- `taema-fast`: hook, prompt, launch, bar follow; dispatch from the `taema` wrapper.
- `taema-eventd`, optional: proc connector, per-uid sockets, runit integration, and a
  collector in the daemon.

**Acceptance**

- 100% parity between the Python and Rust helpers on the request corpus, including every
  refusal case. 24 h of fuzzing finds no crash.
- `taema prompt` < 5 ms, and the `taema launch` overhead < 30 ms (p50 over 100 runs).
- With eventd enabled, a process born and exited within 1 s is still recorded in the
  instance ledger. With eventd disabled, behaviour is unchanged.
- The xbps build passes on glibc and musl.

**Exit artifacts:** security review notes for the helper and eventd; `SECURITY.md`.

### 17.9 M7 — QoL completion, hardening, and gate review (8–12 days)

**Changes**

- `setup` wizard; `doctor --fix`.
- `unit new/test/lint/list/enable/disable/install` and unit packs.
- `history`, `report`, `suggest`, `recent`, `restore`, `backup`, export/import, `reset`.
- Man pages, `help` topics, `bug-report`.
- Performance work; a 30-day dogfood; threshold tuning from real data.
- The G-Core gate review (§11.5); release notes and the upgrade guide.

**Acceptance**

- A fresh user account reaches a working setup (agent, widget, notifications, mode) in under
  2 minutes with `taema setup`.
- 30 days of `auto` on this machine meet every §19 target. There is no wrong stop that was
  not caught by review, countdown, or undo. The undo rate is < 2%, there are no daemon
  crashes, and the log stays under 3 MiB.
- An upgrade from 0.2.1 preserves pairs, adds reviews for invalid legacy answers, and stops
  nothing during migration.
- `make check` passes on both libcs, and the install, upgrade, and remove cycle passes in a
  disposable Void VM.

**Exit artifacts:** the 1.0.0 release; the G-Core decision record; the dogfood report.

---

## 18. Testing and quality engineering

### 18.1 Existing harness

`tests/test_phase0.py` has `FakeCg` (a temp cgroup tree patched over `cgroup.CG`) and
`make_cfg`; `tests/test_phase2.py` has `FakeProc` (a temp `/proc` with stat/comm/exe/cmdline/
environ/fd). 331 tests pass. v2 extends these, not replaces them.

### 18.2 New tests

| File | Coverage |
|---|---|
| `tests/test_phase5_learning.py` | identity denylist, signatures, per-pair burn-in, outcome loop, review queue, veto precedence, undo, launcher suppression, adopt containment, owner-bound adopt |
| `tests/test_phase6_memory.py` | fake `memory.*` files, feature flags, reclaim ladder, budget rebalance, PSI gates, warm/thrash, save hook, quit detection, OOM, safety guards |
| `tests/test_phase7_ui.py` | CLI parsers/aliases/exit codes, JSON schemas, `dash --once`, completions, `doctor`, `events` |
| `tests/test_migration.py` | v1/v2→v3, unknown keys, corrupt store, feedback replay, concurrent CLI/daemon |
| `tests/test_safety.py` | veto wins in every layer, protected/self-guard, no memory writes outside owned leaves, no `memory.max` below headroom, observe mutates nothing |
| `tests/test_live_sandbox.py` | opt-in (`TAEMA_LIVE=1`): a disposable `scope-taematest-<pid>` with `sleep`, real `memory.current`/`reclaim`/rmdir; never touches other scopes |
| `tests/test_budget.py` | extend: memory pass cost, state caps, no log growth on repeated passes |

### 18.3 Special checks

- **Decision purity:** `knowledge.decide()` is a pure function; property tests for monotonicity
  (adding `ex_stop` cannot make it less likely to stop; adding `keep` cannot make it more
  likely, except the documented override rule).
- **Replay:** feed an anonymized `decisions.log` + `knowledge.json` through the new decider and
  assert every `stop` is still authorized; use the live snapshot as a fixture.
- **Fake cgroup memory files:** extend `FakeCg.leaf(..., memory=...)` to write
  `memory.current/stat/events/pressure/high/max/reclaim`; a fake `memory.reclaim` records the
  written value.
- **Safety fuzz:** mutate socket JSON (types, huge strings, unknown keys) and assert an error
  reply, no crash, no mutation.
- **Performance:** 200 fake leaves, memory pass < 100 ms, GC pass < 50 ms, daemon RSS < 30 MB
  (use `resource.getrusage` in a subprocess or `ps`), idle sleep > 1 s.
- **No root in tests.** Live tests only use the delegated user subtree and unique names.

### 18.4 Tooling and CI gates

| Gate | Tool | Threshold |
|---|---|---|
| Lint and format | `ruff check`, `ruff format --check` | zero findings |
| Types | `mypy` (strict for `model/`, `store/`, `governor/`, `daemon/authorize.py`) | zero errors |
| Unit and integration tests | `unittest` via `pytest` | all pass on glibc and musl, Python 3.11 and 3.14 |
| Coverage | `pytest-cov` | ≥ 85% for new modules; no drop for old ones |
| Properties | `hypothesis` | `decide()` monotonicity, signature stability, veto precedence, budget invariants |
| Contracts | JSON Schema | every socket reply and export validated |
| Rust | `cargo fmt`, `clippy -D warnings`, `cargo test`, `cargo audit`, `cargo deny` | zero findings |
| Fuzz | `cargo fuzz` (helper parser), Python socket fuzz | no crash in the CI time budget; 24 h before the M6 release |
| Packaging | existing packaging tests, `xbps-src pkg` | pass |

### 18.5 New test areas in revision 2

| Area | How |
|---|---|
| SQLite store | migration from fixture stores (including a copy of the live 0.2.1 store); crash loops; reader/writer concurrency; retention; recovery from a corrupted file |
| Action ladder | fake `cgroup.freeze`/`cgroup.events`; eligibility matrix; thaw triggers; crash-recovery thaw; wake-on-connect against a captured `ss` Recv-Q, plus a live sandbox test with `python3 -m http.server` |
| Guard | fake PSI trigger fd (a pipe made readable on demand); available-floor math with and without earlyoom; `oom_score_adj` writes against a fake `/proc` |
| QoS | class transitions, debounce, missing-file feature detection, `subtree_control` enabling |
| Agent | fake niri socket server replaying recorded `event-stream` JSON; a stub `notify-send` printing scripted actions; heartbeat loss; rate limits |
| Launch | `launch_prepare` timeout and empty-leaf cleanup; desktop wrap/unwrap round trip; drift detection |
| Config | drop-in order, protected union, invalid edits kept out, TOML writer round trip, profile overlays and auto-switch |
| CLI UX | fuzzy targets, ambiguity exits, size/duration/time parsing, did-you-mean, `--plain` output, golden outputs |
| Rust helper | a differential corpus run against the Python helper; refusal cases; fuzzing |
| eventd | recorded netlink frames; uid filtering; slow-consumer drop |
| Performance | 300 fake scopes: pass p95 < 100 ms; CLI latency benchmark; RSS budget with a 50k-row database |

### 18.6 Dogfood protocol

- Run `auto` on the maintainer's machine for 30 days, starting after M5. M6 and M7 are
  dogfooded on top.
- Keep a weekly `taema report --week --json` snapshot in `notes/dogfood/`.
- Write every undo, veto, or surprise into a template with the decision id, expected and
  actual behaviour, and a root cause. Each one becomes a test case in the replay corpus.
- Exit criteria are the §19 targets.

---

## 19. Success metrics

| Area | Metric | Target |
|---|---|---|
| Adopt | App roots > 5 s in a scope after one interval | 100% of eligible roots |
| Adopt | GUI closes with survivors that get a review | 100% |
| Learning | Pairs with generic/invalid owners after 7 days | 0 |
| Learning | Pairs older than 7 days with only weight-0 evidence | 0 (answer, teach, or mark noise) |
| Learning | Silent-stop decisions with per-pair burn-in | 100% |
| Safety | Wrong stops (veto/undo/regret) per 100 auto stops | < 2 |
| Safety | Stops without an authorization reason | 0 |
| Memory | Idle background scopes with reclaimable cache left untouched | 0 after `idle_reclaim_grace` |
| Memory | OOM kills caused by tæma-set limits | 0 |
| Memory | Reclaim thrash (refault within cooldown) | < 5% of reclaims |
| Ops | Daemon RSS / CPU at idle | ≤ 30 MB / ≤ 0.2% |
| Ops | `gc_would_*` duplicate lines per unchanged leaf | 0 |
| UX | `taema why` answers who/why/what in one screen | 100% of tested cases |
| Desktop | GUI closes with survivors answered within 24 h (notification, widget, or CLI) | ≥ 60% |
| Desktop | Open review backlog | ≤ 5 items |
| Desktop | Notifications per hour (p95 day) | ≤ `notify.max_per_hour` |
| Detection | Close → decision latency with the agent | < 3 s p95 |
| Ladder | Client hangs caused by freeze | 0 (wake-on-connect p95 thaw ≤ 3 s) |
| Guard | earlyoom or kernel OOM kills of non-leftover processes | 0 during dogfood |
| QoL | First-run setup to a working configuration | < 2 min |
| QoL | `taema status` / `taema prompt` / `taema launch` latency | < 50 ms / < 5 ms / < 30 ms |
| Stack | Rust/Python helper parity on the corpus | 100% |
| Stack | Coverage of new modules | ≥ 85% |

---

## 20. Risks and mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Wrongful kill of a needed process | data loss / broken workflow | no unlearned idle stops; review queue; probation; veto; undo; protected rules; graceful first |
| Learning poisoned by a bad answer | repeated wrong stops | validated identities; no generic owners; answer applies to signature, shown with provenance; undo/veto; decay; per-pair suspension |
| Memory reclaim causes latency/thrash | slow apps | pressure gates, headroom, cooldown, warm/cold, never for foreground, observe mode, per-unit opt-in |
| `memory.max` OOM | killed app | never below current+headroom; opt-in only; OOM logging; no default hard caps |
| Kernel feature gaps | memory commands fail | runtime feature detection; fallbacks; `doctor`; no crash |
| cgroup hierarchy / no-internal-process | child scopes lack memory files | aggregate app-scope accounting first; optional layout v2 later; document |
| Permission errors | half-applied budget | only write owned leaves; wrap `OSError`; log and back off; never retry blindly |
| Performance regression | daemon too heavy | one `/proc` scan per pass; memory reads bounded; skip gates; caps; budget tests |
| Log growth | disk / noise | dedupe, rotation ×3, change-only events |
| Migration data loss | lost learning | backup, keep v2 keys, tests, downgrade note |
| User confusion from mode changes | distrust | docs, `doctor`, `why`, dashboard, release notes, default safe |
| Privacy of argv/cwd | local only | off by default; 0600; no network; redact in export |
| Packaging breakage | install/upgrade failure | update template, conf_files, packaging tests, VM install test |
| Two toolchains (Python + Rust) | slower builds, contributor friction | Rust limited to three small binaries; process and protocol boundaries only; Python fallbacks for one release; vendored crates |
| SQLite locking or corruption | lost passes or lost state | WAL, a single writer, read-only readers, `busy_timeout`, quick_check, daily export, recovery path |
| Agent not running | no notifications, no window signals | graceful degradation to process-only; `doctor` and the widget show agent state; `setup` installs autostart |
| Notification fatigue | user mutes everything | batching, caps, memory threshold, digest, quiet hours, per-app mute, profiles |
| Freeze hangs a client | broken workflows | eligibility rules, wake-on-connect, thaw on focus, `max_frozen`, crash-recovery thaw, off in `adopt` by default |
| Tray app misclassified as closed | killing an app the user keeps in the tray | `on_last_window = ask` by default; grace learned per app; reopening = keep evidence; `keep (tray app)` answer |
| earlyoom and tæma act at once | double actions, confusion | the guard floor sits above earlyoom's `-m`; tæma only frees, shapes, and stops authorized scopes; doctor explains the interplay |
| Desktop entry wrappers drift | apps launch an old Exec line | hash of the original entry; `doctor` drift check; `desktop unwrap`; `suggest` re-wrap |
| Compositor IPC changes | window backend breaks | backend versioning, recorded-stream tests, process-only fallback |
| Scope creep | late delivery | M0 ships alone; milestones release independently; experimental flags; G-Core decided by data, not taste |

**Kill switches:** `taema hold`, `taema snooze`, `TAEMA_HOLD=1`, `taema mode observe`,
`taema profile quiet`, `TAEMA_MEM=0`, `[experimental]` flags off, a global `do-not-kill`,
`--dry-run`, and a `SIGUSR1` toggle. `taema thaw --all` undoes every freeze at once. All are
documented in `doctor` and `taema help safety`.

---

## 21. Compatibility, migration, rollback

- **Config:** old `taema.toml` and unit files keep working. New sections are optional. Unknown
  keys are ignored with a `doctor` warning. `[protected]` remains union-only.
- **Modes:** `adopt` behaviour changes (it now adopts all app roots, contains leftovers, asks,
  and honors owner binding). This is a deliberate breaking change; release notes and
  `taema doctor` call it out. `observe` and `enforce` keep their contracts. `auto` becomes
  safer (no unlearned idle stop).
- **Store:** the JSON store is migrated once to SQLite (§13.5), and `knowledge.json` is kept
  as a 30-day backup. Schema v4 adds `instances.parent_evidence` with an empty default and
  `instances.last_seen`, preserving v3 rows. A downgrade needs `taema learn export --format v2`
  first (§13.8); see
  `docs/identity-resolution.md` for the v4 SQLite rollback steps.
- **Package:** versions follow §17.1 (0.3.0 → 1.0.0). `conf_files` gains the new units and
  `/etc/taema/taema.d/`. Runtime dependencies are unchanged (Python stdlib); `libnotify` is
  optional. Rust adds build-time `cargo` only, and `scdoc` is added for man pages.
  `taema-eventd` is a separate optional subpackage. `INSTALL`/`REMOVE` stay the same, plus
  installing man pages and completions. `sv/taema/run` remains compatible, and `TAEMA_HOLD`
  and `TAEMA_EVENTD` are optional.
- **Desktop:** nothing changes for users who do not run the agent. `taema setup` is the
  opt-in path, and wrapped desktop entries can be removed with `taema desktop unwrap --all`.
- **Protocol:** v1 one-shot socket messages are accepted for one release, so old shell hooks
  keep working during an upgrade.
- **Rollback:** set `mode = "observe"`, `taema hold`, or downgrade the package; the store
  backup is the source of truth. Scopes that exist stay until their processes exit (existing
  behaviour).

---

## 22. Decision record

All recommendations from revision 2 were accepted on 2026-10-19. Each decision has a stable
id, so code reviews, ADR files, and commit messages can cite it (for example "per D10").
Changing a decision means adding a new row that supersedes the old one; rows are never
edited in place.

| Id | Topic | Decision | Where it applies |
|---|---|---|---|
| D1 | Authority in `adopt` | `adopt` = contain + deprioritize + learn + ask + reclaim + owner-bound stop, with `[learn] authority = "answered"`. Learned stops stay an opt-in. | §5.1, §5.2, M0 |
| D2 | Unlearned idle stops in `auto` | Removed. `leftover_expire_days` remains available with default 0 (off); unlearned leftovers are reviewed instead. | §2.3, M0 (T0.4) |
| D3 | Memory management default | `mem.manage = "soft"` in both `adopt` and `auto`, with the conservative headroom of §7.4. `memory.max` stays unit opt-in. | §5.1, §7.4, Appendix A |
| D4 | SIGKILL | Only for pairs the user answered explicitly. Learned and probation stops are SIGTERM-only. | §5.6, §6.7 |
| D5 | `undo --restore` | Opt-in through `[learn] remember_argv`, off by default. Without it, undo adds the veto and keep evidence but cannot relaunch. | §10.7, §12.4 |
| D6 | First dashboard | curses TUI first. The read-only web view comes in M7 or later. Textual is deferred. | §8.3, §8.4, §11.8 |
| D7 | Versioning | 0.3.0 → 1.0.0 as in §17.1. "v2" names the product line, not the version number. | §17.1, §21 |
| D8 | Idle shared/unit GC in `auto` | Yes: `auto` stops idle `shared/*` and `stop_when_unneeded` scopes, with veto, hold, edge, pty, and CPU checks. `adopt` reviews them instead. | §2.3, §5.1, M0 (T0.5) |
| D9 | Container/VM identification | Cgroups and sockets first. Friendly names from `podman`/`virsh`/`incus` only with `[mem] probe = true` (default false). | §6.2, §7.6, §12.1 |
| D10 | Freeze in `adopt` | Off for the first release (`freeze.adopt = false`). Revisit after the dogfood data in M7. | §5.6, §12.5 |
| D11 | Windowless default | `on_last_window = "ask"` for every app. No curated tray-app list; the learner records each answer. | §9.3, §12.7 |
| D12 | Rust in v2 | Root helper, `taema-fast` (hook, prompt, launch, bar), and optional `taema-eventd`. A full core port happens only through gate G-Core. | §11.5, M6 |
| D13 | eventd | Optional subpackage, off by default (`[experimental] eventd = false`). The agent and niri cover GUI latency. | §11.4, §11.9, §12.5 |
| D14 | Privacy defaults | Window titles and argv/cwd are not stored by default. `restore` works only after opting in to argv (D5). | §9.3, §12.5, §15.3 |
| D15 | DMS widget | In-tree under `contrib/dms/`, released in lockstep with the core. | §9.5, §16 |
| D16 | Notifications | On by default when an agent with an action-capable server is running, within the caps of §9.2. `setup` still lets the user turn them off. | §9.2, §12.5 |
| D17 | Python floor | 3.11, as the README promises. CI tests 3.11 and the current Void Python. | §11.6, §18.4 |
| D18 | Focus boost | Only in the `focus` profile (`qos.focus_boost = false` by default). | §7.9, §10.2 |

**Open items.** None block M0. New questions raised during implementation are added here
as D19 and onward, with the milestone that needs the answer.

---

## Appendix A — Mode capability matrix (one page)

This mirrors §5.1 and §5.6. If they ever disagree, §5.1 wins.

| Capability | observe | adopt | auto | enforce |
|---|---|---|---|---|
| Observe lineage and windows | yes | yes | yes | yes |
| Adopt unit-matched apps | log | yes | yes | yes |
| Auto-adopt app roots | log | yes | yes | yes |
| Launch-time scoping (`taema launch`) | yes (explicit) | yes | yes | yes |
| Contain survivors in `leftover/` | log | yes | yes | yes |
| Deprioritize leftovers | log | yes | yes | yes |
| Freeze idle leftovers | log | opt-in | yes | yes |
| Ask terminal questions / queue reviews | yes | yes | yes | yes |
| Stop owner-bound scopes | log | yes | yes | yes |
| Stop by answered pair | no | yes | yes | yes |
| Stop by learned pair | no | opt-in (`authority=learned`) | yes | yes |
| Stop idle `shared/*` / `stop_when_unneeded` | log | no (review) | yes | yes |
| Enforce GC and session rules | no | no | no | yes |
| Reclaim memory | log | page cache; swap opt-in | yes | yes |
| Pressure guard | log | reclaim, deprioritize; freeze opt-in | full ladder | full ladder |
| Soft memory cap (`memory.high`) | log | yes (`mem.manage = soft`) | yes | yes |
| Hard memory cap (`memory.max`) | no | unit opt-in | unit opt-in | unit opt-in |
| Hold, snooze, veto | yes | yes | yes | yes |

## Appendix B — Evidence weights (defaults)

| Evidence | Weight | Decay | Notes |
|---|---|---|---|
| explicit answer (pair/signature) | +3.0 | never | only contrary explicit evidence overturns |
| inferred manual kill | +0.25 stop, kills +1 | 7 days ×0.9 | shell `kill` with vanished pid |
| observed close | 0 (closes +1) | never | burn-in only |
| launcher close | 0 (launches +1) | never | no pair in v2 |
| own stop succeeded (`stop_ok`) | +0.5 | 7 days ×0.9 | confidence only unless self-authority |
| own stop respawned | keep +1, respawn +1 | 7 days ×0.9 | suspend on regret |
| regret | keep +3 | never | 7-day suspension |
| shared hit | exe +1 | 7 days ×0.9 | learned “share” default |
| veto | block | never | hard rule |

## Appendix C — Veto target grammar

```
TARGET := SCOPE | PID | APP | PATH | CGROUP | UNIT | PAIR | SIGNATURE | OWNER
SCOPE  := an existing leaf name (app-x, scope-x, leftover/x) or a prefix that resolves uniquely
PID    := a positive integer with a matching starttime (pid reuse safe)
APP    := app key/identity (firefox, node:vite.js, app-firefox)
PATH   := an absolute executable path
CGROUP := an absolute path under /sys/fs/cgroup/user/<uid>
UNIT   := a unit name from /etc/taema/units or ~/.config/taema/units
PAIR   := --pair OWNER LEFTOVER
SIG    := --signature 12-hex
OWNER  := --owner OWNER (all leftovers of that owner)
```

A target that matches nothing is an error (exit 2); a target that matches multiple scopes
requires `--all` or a more specific form. A veto prints what it matched, so the user can
verify before the next close.

## Appendix D — Unit examples

See §7.6 for libvirt and podman. A generic container unit:

```toml
[unit]
name = "app-container"
kind = "app"
class = "container"
stop_when_unneeded = true

[match]
comm = "conmon"

[mem]
reservation = "512M"
high = "1G"
idle_reclaim = true

[gc]
keep_while_children = true
```

An Android emulator project unit (existing example, extended):

```toml
[unit]
name = "scope-satcyber"
kind = "scope"

[kill]
graceful = 15
keep = ["adb"]

[mem]
reservation = "4G"
high = "6G"
save_state = ["/home/user/bin/satcyber-save"] # optional, explicit
```

## Appendix E — Live evidence snapshot (0.2.1, mode `adopt`)

Collected from the maintainer's machine while writing this plan; commands are read-only.

```text
mode                       adopt (user config; system default auto)
daemon                     running, PID 1438
knowledge                  version 2, created, closes 20
exes                       0 (all counters zero → dropped)
pairs                      18
pairs with any evidence    1 (MainThread > sh/sort/head, ex_stop 3)
pairs with zero evidence   17
decisions.log events       gc_would_stop 1176, adopt 91, owner_watch 47, would_stop 47,
                           would_attribute 20, socket_bound 10, question_ready 2,
                           stop 1, gc_removed_empty 1, answer 1
top gc scopes              app-podman-a60a9cde 406, app-podman-4f0d253a 394,
                           app-podman-2de8215f 376
memory                     user/1000 694,620,160; app-herdr 664,375,296
                           anon 562,335,744; file 73,089,024; kernel 27,594,752
kernel features            memory.reclaim, memory.pressure, memory.peak, memory.zswap.*,
                           /proc/pressure/memory present; cgroup.subtree_control = cpuset cpu io memory pids
```

What this shows:

- Adopt did move unit apps (91 adopt events), so it is not inert; it is just not doing the
  cleanup or the learning that the product promises.
- 1,176 `gc_would_stop` lines for three unchanged podman scopes is the “does nothing” symptom,
  and a log-growth bug.
- The only pair with authority is attached to `MainThread`, an invalid identity. The learner
  is not only starved; it is capable of learning the wrong thing.
- 664 MB in one app scope is the memory opportunity, and it is invisible to the current code.

### E.2 Facts collected for revision 2 (2026-10-19)

```text
python / sqlite            3.14.8 / 3.53.4
would_stop breakdown       47 of 47 are "owner N exited"
daemon footprint           RSS 25,124 kB, CPU 00:00:02 after 40:27
cli latency                taema --version 0.102 / 0.093 / 0.094 s; taema status 0.092 s
memory / swap              MemTotal 15,554,700 kB; MemAvailable 9,359,304 kB; /swapfile 25,165,820 kB; zswap N
earlyoom                   -r 60 -m 8 -s 8 --prefer (^|/)(node|python|java|docker|containerd|codex|cline|opencode)
                           --avoid (^|/)(runit|sshd|greetd|niri|Xwayland|dbus-daemon|elogind|qemu-system|steam|gamescope|wine|claude|claude-desktop)
oom_score_adj              unprivileged raise to 500: ok
psi trigger                write "some 150000 2000000" to app-herdr/memory.pressure: accepted
delegated files            cgroup.freeze rw, memory.high rw, memory.pressure rw, memory.reclaim -w (owner soubarna)
notification server        quickshell 1.2; caps: persistence body body-markup body-hyperlinks body-images
                           actions action-icons icon-static inline-reply
notify-send                0.8.8 (-A/--action, -w, -p, -r)
session bus                unix:path=/tmp/dbus-…; /run/user/1000/bus absent; daemon env: no DBUS/WAYLAND/NIRI
niri                       msg --json windows keys: app_id focus_timestamp id is_floating is_focused is_urgent
                           layout pid title workspace_id; event-stream emits JSON
desktop processes          niri, qs (quickshell), dms-guard, earlyoom; dms CLI at /usr/sbin/dms
tools                      fzf, pytest, virsh, podman, zramctl, rustc/cargo (~/.cargo); no docker/incus/VBox/go
void repos                 rust/cargo 1.99, ruff 0.15.7, python3-mypy 2.1.0, python3-hypothesis 6.156,
                           python3-pytest-cov 7.1, python3-build 1.6.1, python3-jeepney 0.9.0,
                           python3-textual 8.2.7, python3-rich 15.0, python3-dbus 1.3.2, scdoc 1.11.4, earlyoom 1.9.0
ci image                   ghcr.io/void-linux/void-glibc:latest
```

## Appendix F — Glossary

| Term | Meaning |
|---|---|
| scope / leaf | a cgroup directory under `/sys/fs/cgroup/user/<uid>/` |
| member | a process directly or transitively inside a scope |
| root | the process whose lifetime defines an app scope |
| survivor / leftover | a member still running after its root exited |
| pair | `(owner, leftover)` learning record (0.2.x); v2 adds signatures |
| signature | a stable fingerprint of a survivor set |
| provenance | the recorded parent/child/instance history of an app |
| authority | what permits a stop: answer, learned evidence, unit rule, or manual mode |
| veto | a hard user block on stop/reclaim for a matched object |
| reclaim | return page cache (and optionally swap) from a live scope |
| budget | the advisory per-user memory pool and per-scope soft shares |
| hold | a runtime pause of all stops/reclaims |
| review | a pending close that needs an answer outside the shell prompt |
| action ladder | contain → deprioritize → freeze → reclaim → stop; reversible until the last stage |
| deprioritize | set `cpu.idle`/`io.weight` and raise `oom_score_adj` for a contained scope |
| freeze / quarantine | `cgroup.freeze = 1` on an idle leftover scope; undone by thaw |
| wake-on-connect | thawing a frozen scope when its listening socket gets a pending connection |
| windowless | an app whose root is alive but whose last window closed |
| session agent | `taema agent`: the in-session companion for notifications, windows, and launches; no authority |
| window backend | the compositor adapter that maps windows to pids (niri first) |
| launch-time scoping | starting an app inside its scope (`taema launch`) instead of adopting it later |
| profile | a named overlay of config keys (`focus`, `battery`, `game`, …), switched manually or automatically |
| drop-in | a `taema.d/*.toml` file merged after the main config |
| guard | the pressure-triggered memory protection ladder |
| eventd | the optional root forwarder of netlink process events |
| G-Core | the data-driven gate that decides whether to port the daemon core to Rust |

## Appendix G — Work breakdown

Ids are stable, so tickets, commits, and the dogfood log can reference them. Estimates are
in focused developer-days.

| Id | Task | Days | Depends on |
|---|---|---|---|
| **M0** | | | |
| T0.1 | Adopt-all roots in `adopt`/`enforce` (lift the `auto()` gate in `adopt_pass`) | 0.5 | — |
| T0.2 | Contain survivors in `adopt` (`gui_close` gate) and store reviews | 1 | T0.1 |
| T0.3 | Owner-bound stops in `adopt` (`stop_leaf` gate) | 0.25 | — |
| T0.4 | Remove the unlearned idle stop; update `test_idle_for_learned_grace_then_stop` | 0.5 | — |
| T0.5 | Idle `shared/` and unit GC in `auto`; dedupe `would_*` | 0.5 | — |
| T0.6 | Identity denylist; launcher closes create no pairs | 0.5 | — |
| T0.7 | Minimal veto and undo with offline enforcement | 1 | — |
| T0.8 | `ls` MEM/PSI columns; README mode table; release 0.3.0 | 0.5 | T0.1–T0.7 |
| **M1** | | | |
| T1.1 | Package restructure with shims; `pyproject.toml`; ruff; mypy baseline | 1.5 | M0 |
| T1.2 | SQLite schema, `store/db.py` behind the `Store` API | 2 | T1.1 |
| T1.3 | 0.2 importer, invalid-legacy handling, daily export, recovery | 1.5 | T1.2 |
| T1.4 | Protocol v2 envelope, v1 compatibility, schemas for existing commands | 1 | T1.1 |
| T1.5 | CI matrix (glibc, musl, 3.11, 3.14), coverage | 1 | T1.1 |
| **M2** | | | |
| T2.1 | `model/identity` + `identity_ok` + desktop/launch identity hooks | 1.5 | T1.2 |
| T2.2 | Instances, parents, signatures, matching | 2.5 | T2.1 |
| T2.3 | `decide()` v3: per-pair burn-in, probation, outcomes; property tests | 2 | T2.2 |
| T2.4 | Review queue, `review`/`answer`/`teach`, prompt hint | 1.5 | T2.2 |
| T2.5 | Full veto grammar and precedence, `undo`, `restore` | 2 | T2.2 |
| T2.6 | `why` renderer, `learn` views, replay corpus | 1.5 | T2.3 |
| **M3** | | | |
| T3.1 | `governor/memory`: reader, feature flags, `taema memory` | 2 | T1.2 |
| T3.2 | Budget and reclaim ladder, warm/thrash | 2.5 | T3.1 |
| T3.3 | QoS classes and writes; controllers in `leftover/` and `shared/` | 1.5 | T3.1 |
| T3.4 | Freeze/thaw, eligibility, wake-on-connect, crash recovery | 3 | T3.3 |
| T3.5 | PSI-trigger collector, guard ladder, `oom_score_adj`, `oom.group`, earlyoom detection, helper `oom-restore` | 3 | T3.4 |
| T3.6 | Container/VM units, quit detection, hooks, rebalance; swap/zswap advisor | 3 | T3.2 |
| **M4** | | | |
| T4.1 | CLI framework: registry, targets, renderers, errors, exit codes, lazy imports | 2 | T1.4 |
| T4.2 | Drop-ins, TOML writer, reload, `mode`/`config`/`snooze`/`hold` | 2 | T4.1 |
| T4.3 | `subscribe` and the view model | 1.5 | T1.4 |
| T4.4 | `dash`, `top`, `tree` | 3 | T4.3 |
| T4.5 | `doctor`, `events`, completions | 1.5 | T4.1 |
| **M5** | | | |
| T5.1 | Agent process, registration, heartbeats, leaf placement | 2 | T4.3 |
| T5.2 | Notifier backends and policy | 2 | T5.1 |
| T5.3 | niri backend; windowless lifecycle; focus classification; thaw on focus | 3 | T5.1, T2.2, T3.4 |
| T5.4 | `launch`, `launch_prepare`, desktop wrap | 2 | T5.1 |
| T5.5 | `bar`, DMS widget, profile auto-switch | 2 | T4.3 |
| **M6** | | | |
| T6.1 | Rust workspace, CI, vendoring, template | 1.5 | T1.5 |
| T6.2 | `taema-attach` in Rust, differential corpus, fuzzing | 3 | T6.1 |
| T6.3 | `taema-fast` (hook, prompt, launch, bar) | 3 | T6.1, T5.4 |
| T6.4 | `taema-eventd` and its daemon collector | 3 | T6.1 |
| **M7** | | | |
| T7.1 | `setup` wizard, `doctor --fix` | 2 | M5 |
| T7.2 | Unit tooling and packs | 2 | T4.1 |
| T7.3 | `history`, `report`, `suggest`, `recent`, `backup`, export/import, `reset` | 3 | T2.6 |
| T7.4 | Man pages, `help` topics, `bug-report`, README/design rewrite | 2 | all |
| T7.5 | Performance pass, 30-day dogfood, G-Core review, 1.0.0 release | 3 | all |

---

*End of plan (revision 2.1, decisions D1–D18 accepted). No code was changed. The first executable step is still M0: it
ships alone and makes `adopt` contain, ask, and honour explicit binds. The first safety
step is still removing the unlearned idle stop and adding the veto. Everything after that is
sequenced in §17, and the stack decisions in §11 are recorded so that each one can be
revisited with data.*
