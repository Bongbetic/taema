# tæma design

## Goals

1. When a program stops, everything it started stops too, including detached children.
2. A helper that something outside the program still uses is not killed with it.
3. Running apps are put into scopes without changing how they are launched.
4. Decisions improve with use and can always be explained.
5. Nothing outside the user's own processes is ever touched.

## systemd concepts mirrored

| systemd | tæma |
|---|---|
| `app-*.scope` under `user.slice` | `app-*` leaves under `/sys/fs/cgroup/user/<uid>/` |
| `BindsTo=` | owner watch: `taema run --owner PID` / `--bind`, child scopes bound to their root |
| `StopWhenUnneeded=` | GC of `shared/*` and `stop_when_unneeded` units after `idle_grace` without users |
| `KillMode=mixed` | SIGTERM members, wait the graceful timeout, then SIGKILL what is left |
| logind `KillUserProcesses=` | session-end stop, except `survive_logout` units |

## Cgroup layout

```
/sys/fs/cgroup/
  <session-id>/              elogind login session: compositor, audio, D-Bus, portals
  user/<uid>/                delegated to the user by the taema service
    manager/                 the user's taema daemon
    app-<name>/              adopted apps, with child scopes such as session-<pid>
                             and job-<id> (survivors of one terminal job)
    app-podman-<hash>/       one per rootless podman runtime dir: pause + conmon-<pid>/
    scope-<name>/            explicit project scopes (taema run NAME)
    shared/<comm>-<pid>/     members kept alive because something outside uses them
    leftover/<owner>-<id>/   survivors of a closed app, until GC or an answer decides
```

`sv/taema/run` enables the controllers `cpuset cpu io memory pids` in
`user/<uid>/cgroup.subtree_control` (and in each member's cgroup, re-scanned every 60 s),
so each scope is a CPU and IO weight peer of its siblings. tæma sets no limits. With controllers enabled, a cgroup that has children
cannot hold processes itself (no-internal-process rule): put processes in leaves.
`cgroup.kill` on a parent kills the whole subtree.

Moving a task needs write access to `cgroup.procs` of the lowest common ancestor of the
source and destination. From a session cgroup into `user/<uid>`, that ancestor is the
root cgroup, so the move needs root: `taema-attach` does it. Moves between leaves inside
`user/<uid>` need no privilege, and the daemon does them itself.

## Processes and privileges

```
runsv taema (root)
  run: delegate user/<uid> for each member of group taema; a background loop repeats
       it every 60 s for new members and ends with the service (pid in /run/taema/rescan.pid)
  runsvdir /run/taema/sv
    runsv <user>
      taemad-user <user> (root)  moves itself to user/<uid>/manager, then setpriv
        taemad (uid)             starts taema.daemon_entrypoint; all decisions, all signals
          sudo -n taema-attach   the one privileged step, validated on its own
```

`taema-attach` is a small wrapper preferring the Rust helper with the Python
helper as fallback (standard library only, `python3 -I`). It reads only
`/etc/taema/taema.toml`, which must be root owned. It refuses:

- callers that are not using sudo, and uid 0
- pids not owned by the caller, and pid 1
- protected comms, protected cgroup prefixes and protected environment prefixes
- pids outside a numeric session cgroup and outside the caller's own subtree
- destination paths with `..`, empty segments or uppercase, and leaves not owned by the caller

## Dependency edges

An edge means that an outside process depends on a member, with the member as the
server. A member with an edge is shared.

| Edge | Detection |
|---|---|
| `unix_server` | member holds a bound unix socket, an outside pid holds the peer (`ss -xpn`) |
| `unix_server_unresolved` | member's bound socket has a peer that `ss` cannot attribute (another user's process); counted, conservatively |
| `tcp_server` | member LISTENs on a port and an outside pid holds an established connection to it (`ss -tnp`) |
| `podman_pause` | an outside `conmon` uses the pause process of the member's `XDG_RUNTIME_DIR` |
| `ptrace` | an outside process traces a member (`TracerPid`) |

Pipes, ptys and inherited stdio are never edges. Every process started from a shell
shares those with the shell, so counting them would make everything look shared. A
member that is only a client of something outside (Xwayland, D-Bus, an outside adb
server) has no edge.

Per member, stopping a scope decides one of:

- `skip`: a hard rule protects it. This is logged as an error, because such a process
  should never have been put in a scope.
- `share`: it has an edge, is listed in the unit's `keep` or `--keep`, or the learner
  says `share`. Its subtree moves to `shared/<comm>-<pid>`, and GC decides later.
- `kill`: none of the above.

Descendants of a shared process move with it.

## Daemon loops

- **Owner watch:** `os.pidfd_open(owner)` registered with a selector. When the pidfd
  becomes readable, the bound scope is stopped.
- **Adopt** (every `adopt_interval`): match processes in session cgroups against app
  units (`exe`, `comm`, `cmdline_contains`), group them (for example by
  `XDG_RUNTIME_DIR`), and move whole subtrees through the helper. Then carve child scopes
  inside adopted scopes without privilege.
- **GC** (every `gc_interval`): for `shared/*` and `stop_when_unneeded` units, recompute
  the edges. A leaf with no edges, and no children when `keep_while_children` is set,
  starts an idle timer. It is stopped after `idle_grace`. A podman scope whose
  `XDG_RUNTIME_DIR` is gone is a candidate at once.
- **Empty leaves:** GC removes `app-*`, `scope-*` and `shared/*` leaves that hold no
  process, never `manager`. Each leaf's `cgroup.events` is watched with `epoll`
  (`EPOLLPRI`, at most 256 fds): `populated 0` removes the leaf at once. A leaf that
  cannot be watched is removed by the GC pass when two passes in a row find it empty.
  Only in `adopt` and `enforce` modes.
- **Session end:** once at least one session of the user has been seen and none is left,
  every scope except `manager` and `survive_logout` units is stopped. This fires once
  per login.

Mode gates every action. `observe` only logs. `adopt` also moves. `enforce` also stops.
`auto` moves and learns always, and stops only what "Auto mode" below allows.

## Lineage

Which app owns a process? Cgroup inheritance answers it: once a root is adopted, its
children are born inside its scope. To keep the window before adoption short, the daemon
diffs the session `cgroup.procs` every 2 s and looks only at new pids.

- **Co-birth:** a newcomer with parent 1 within 2 s of a new root joins that root.
- **Never adopted:** session leaders (`sid == pid`), processes whose parent is not the
  user's (login shells from tty or ssh), and anything younger than 5 s.
- **Re-rooting:** a root that exits within 5 s hands the scope to its oldest live member
  (wrappers, AppImage, `code`). A leftover with the same key as the exiting root is a
  self-update relaunch: re-root, never stop.
- **Terminal jobs:** a job is identified by `pgrp`, `sid` and the shell tag
  `TAEMA_JOB=<shellpid>.<n>` found in `/proc/PID/environ` (searched as bytes, only for pids
  born in the job window, always checked with the start time). Nested shells keep a
  `TAEMA_PARENT_JOB` link. Jobs stay in their host's scope. Only the survivors of a job
  are carved into `<host>/job-<id>`, so typing commands creates no scopes.

## Pairs and thresholds

The learner keeps `pairs[(owner_key, leftover_key)] = {stop, keep, last_asked,
last_auto_stop}` next to the per-exe counters, plus `standalone[key]`, at most 32 members
per owner. Keys name interpreter programs by script (`node:vite`), not by interpreter.

| Signal | Weight |
|---|---|
| explicit answer in the prompt | 3, no decay; only contrary evidence overturns it |
| inferred user kill (pid vanished, `kill` args matched) | at most 0.25 |
| leftover observed | 0 |
| respawn | only under a different owner or when self-started; re-running a command is not one |

Thresholds for a silent stop (all must hold): at least 5 shell-observed stops on at least
3 distinct days, no keep in 30 days, ratio 0.9 or more, pair first seen more than 24 h ago,
and a burn-in of 7 days or 20 closes passed. An answered pair needs none of these.
Grace before SIGKILL is max(5 s, p95 x 1.5) capped at 30 s, and SIGKILL is only for
answered pairs. Regret: a relaunch of the key within 30 minutes of an automatic stop adds
keep +3, suspends the pair for 7 days and asks again.

## Auto mode

`mode = "auto"` is the default. Gate order per action:

1. Adopt and learn always run.
2. Hard rules: protected comm or cgroup, members with edges, ptmx hosts, persist seeds,
   more than 1 % CPU over 60 s, unknown origin. These are never stopped.
3. The pair is answered "stop with X", or its evidence thresholds pass: stop.
4. Anything else: keep, and ask at most once per pair per week (3 per day).

`observe`, `adopt` and `enforce` remain manual overrides. Auto-created scopes survive
logout unless their pair is confidently "stop on close". Unknown is never "no": unreadable
`/proc`, a failed `ss` or a zombie means keep and learn.

## Leftover scopes

When a GUI app closes, its non-standalone survivors move to `leftover/<owner>-<id>` and a
review is queued. Pending reviews hold their scope; expiry records a keep answer and never
authorizes a stop. `taema review` lists each open review's owner, survivor keys, and age.
Standalone survivors get their own app scope. Terminal-job roots do not create leftover scopes.
Persist seeds and share seeds are never drained. The scope is removed when empty
(`cgroup.events` shows `populated 0`).

In active modes, the daemon applies reversible resource priorities after a scope's class stays
stable for two seconds. Leftovers use `cpu.idle=1` (CPU weight 10 when unsupported) and IO weight
10 where available. Shared helpers and idle background app scopes use CPU and IO weight 50.
Original control values are retained for undo and restored when a user answers keep or standalone.
Observe mode logs planned changes without enabling controllers or writing controls. Missing
controls are reported by `doctor`; leftover PID limits remain disabled.

## Resource budget

Memory shares are computed from the lower of the configured RAM fraction and a finite delegated
`memory.max`, with the availability floor and infrastructure use reserved before distributing
class shares. Active VM, container, and app scopes receive bounded `memory.low` reservations;
idle background scopes receive `memory.high` at no less than current use plus headroom. The
daemon records original controls, restores only values it still owns, and recalculates shares when
a scope exits. `memory.max` remains opt-in through hard management and a unit's explicit `mem.max`.
The `taema memory budget` view reports the ceiling, reservations, shares, live controls, and
ownership state.

Targets for an idle daemon (no app starting or stopping): RSS at most 25 MB, CPU at most
0.1 % of one core. How the loops stay inside them:

- The daemon sleeps until the next timer (adopt, GC, at most 60 s), not at 1 Hz. A signal
  wakes it at once through `signal.set_wakeup_fd`.
- One `/proc/*/stat` snapshot (`inspect.ProcTable`) per adopt, GC or stop pass.
- Fork gate: an adopt pass is skipped when the last pid in `/proc/loadavg` and the pid
  sets of the session cgroups are unchanged. At least every fifth pass runs anyway.
- `ss` runs only when a decision needs edges, as two calls (`-xapn`, `-tanp`) shared by
  all passes of a stop.
- Session end is checked at the adopt interval, from `/run/systemd/users/<uid>`
  (`STATE=`, `SESSIONS=`) when readable, else by scanning session cgroups.
- State is bounded: 512 exes, 256 owner watches, 256 leaf watches, `idle_since` pruned to
  existing leaves, `knowledge.json` written compact and at most every 300 s (at once after
  an explicit answer and on exit), `decisions.log` logs state changes only and rotates at
  1 MiB to `decisions.log.1`.

`tests/test_budget.py` checks that repeated passes on a fake tree do not grow these
structures and that the idle loop sleeps more than 1 s. RSS and CPU are measured on a
live machine with `ps -o rss,time -p $(pgrep -f taema)`.

## Learning

Store: `~/.local/state/taema/knowledge.json`, keyed by executable basename (falling back
to `comm`). Counters decay by a factor of 0.9 every 7 days.

| Learned | Rule |
|---|---|
| default action | `share` when seed prior (3.0 for seeded `share` names) + `user_keep` + `shared_hits` + 0.5 × `respawned` > `user_kill` + 2 |
| graceful timeout | p95 of the last 20 SIGTERM-to-exit times × 1.5, clamped to 2–60 s; skip SIGTERM when SIGKILL was needed in more than 80% of at least 5 stops |
| idle grace | doubles (cap 2 h) when something GC stopped comes back; shrinks 10% after a clean GC |

`respawned` counts half because supervisors restart processes that were not needed.
`taema keep` and `taema forget` give direct feedback. Every decision, with its inputs,
goes to `decisions.log` as JSON lines.

The learner is never consulted for the protected list, the uid rules or the configured
exclusions.

## Stop ladder

Every stop climbs the same ladder, weakest first: skip hard-protected members
(logged as errors, since they should never be scoped), share members with
outside edges (subtree moves to `shared/<comm>-<pid>`, GC decides later),
freeze idle leftovers reversibly, SIGTERM then wait the learned grace
(max(5 s, p95 x 1.5), cap 30 s), SIGKILL what remains, GC empty leaves.
Descendants of a shared process move with it. `kill --dry-run`, `gc --dry-run`
and `unit test` walk the ladder without changing anything.

## Session agent

One agent runs per graphical session (`taema agent`, see `taema-agent(1)`):
it joins the protected `agent` leaf, registers capabilities, streams window
open/change/close/focus facts, launch requests and notification actions, and
beats every 30 s. The daemon accepts facts only from the same uid, marks
agents down after 3 missed beats (`agent_up`/`agent_down` audit events), and
refuses stale facts so it decides on process data only. Without an agent the
daemon degrades to process-only mode; reviews wait for the shell hint and
`taema review`.

## Profiles

`[profile]` selects a named configuration overlay (`default`, `focus`,
`battery`, `game`, `quiet`, `server`) or `auto` selection. `taema profile NAME`
applies an overlay; `taema profile auto` returns to automatic selection.
`status` reports the active profile and its reason. `profile.runtime_mode`
overrides the base mode; unsetting it returns to the profile mode. The
`server` profile disables the agent, notifications and window-close handling.

## Migration

State moves forward only. The first 0.4.0 start imports valid 0.3.0 JSON
learning transactionally into SQLite (`state.db`), quarantines invalid-owner
answers as reviews, and keeps a mode-0600 `knowledge.json.backup-*` for 30
days. Migration never stops processes. A 0.2 downgrade needs a prior
`taema learn export --format v2`. See `docs/legacy-state-migration.md` and
`docs/state-schema.md` for the sequence and the schema.

## Testing

`make test` runs the unit tests. They use fake `/proc` worlds and captured `ss` output,
and test the root helper's validation directly. They need no root and no cgroups.
