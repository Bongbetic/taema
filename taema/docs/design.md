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
    app-podman-<hash>/       one per rootless podman runtime dir: pause + conmon-<pid>/
    scope-<name>/            explicit project scopes (taema run NAME)
    shared/<comm>-<pid>/     members kept alive because something outside uses them
```

No controllers are enabled below `user/<uid>`, so processes may sit in a parent and in its
children at the same time. `cgroup.kill` on a parent kills the whole subtree.

Moving a task needs write access to `cgroup.procs` of the lowest common ancestor of the
source and destination. From a session cgroup into `user/<uid>`, that ancestor is the
root cgroup, so the move needs root: `taema-attach` does it. Moves between leaves inside
`user/<uid>` need no privilege, and the daemon does them itself.

## Processes and privileges

```
runsv taema (root)
  run: delegate user/<uid> for each member of group taema
  runsvdir /run/taema/sv
    runsv <user>
      taemad-user <user> (root)  moves itself to user/<uid>/manager, then setpriv
        taema daemon (uid)       all decisions, all signals
          sudo -n taema-attach   the one privileged step, validated on its own
```

`taema-attach` is self-contained (standard library only, `python3 -I`) and reads only
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
- **Session end:** once at least one session of the user has been seen and none is left,
  every scope except `manager` and `survive_logout` units is stopped. This fires once
  per login.

Mode gates every action. `observe` only logs. `adopt` also moves. `enforce` also stops.

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

## Testing

`make test` runs the unit tests. They use fake `/proc` worlds and captured `ss` output,
and test the root helper's validation directly. They need no root and no cgroups.
