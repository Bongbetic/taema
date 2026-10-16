<p align="center">
  <img src="https://bongbetic.com/branding/bongbetic-logo-lockup.png" width="360" alt="Bongbetic">
</p>

<h1 align="center">tæma</h1>

<p align="center">
  <strong>Dependency-aware, self-managing process scopes for Void Linux</strong><br>
  systemd-style app scopes, <code>BindsTo</code> and <code>StopWhenUnneeded</code> for runit systems, built on cgroup v2
</p>

<p align="center">
  <img src="https://img.shields.io/badge/platform-Void%20Linux-478061" alt="Void Linux">
  <img src="https://img.shields.io/badge/init-runit-black" alt="runit">
  <img src="https://img.shields.io/badge/python-3.11%2B-black" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/license-MIT-e8333a" alt="MIT">
</p>

---

*tæma* is Icelandic for "to empty". When you stop something, tæma empties it: the program
and everything it left running in the background. A helper that another program still
uses is kept alive.

## The problem

On systemd distributions every app runs in its own cgroup scope. When the app stops,
systemd can stop everything the app started. On Void Linux with runit and elogind, user
processes share one login-session cgroup. A process that detaches (`setsid`, double fork,
`nohup`) is re-parented to init and keeps running after the program that started it has
gone.

Typical leftovers:

- an Android emulator `qemu-system-x86_64` that keeps running after the IDE or project
  script that launched it has stopped
- rootless podman pause processes (`catatonit -P`) whose runtime directory no longer exists
- dev servers, language servers and build daemons from a finished session

Killing a process group or session is not enough, because detached children leave both.
Killing everything blindly is wrong too: an `adb` server, a podman pause process or a
terminal multiplexer server may be shared with programs that are still running.

## What tæma does

- **Scopes.** Every managed program gets its own cgroup v2 leaf under
  `/sys/fs/cgroup/user/<uid>/`. A process cannot leave its cgroup by forking or
  detaching, so the scope always holds the complete process tree.
- **Dependency-aware stop.** Before a scope is stopped, tæma looks for outside processes
  that still use one of its members: unix socket and TCP clients, conmon processes that
  share a podman pause process, and ptrace. A member that is still used is moved to
  `shared/` and stays alive. Everything else gets SIGTERM, then SIGKILL.
- **Automatic management** (the `taema` daemon, one per user):
  - *Adopt:* known apps (podman, plus any unit you add) are moved out of the login
    session into their own `app-*` scopes, with child scopes for sessions or VMs.
  - *BindsTo:* a scope started with `--owner PID` or `--bind` stops when its owner exits.
  - *StopWhenUnneeded:* shared helpers and app scopes are stopped once they have had no
    users for an idle grace period.
  - *Session end:* when your last login session ends, scopes are stopped, except units
    marked `survive_logout`.
- **Learning.** tæma keeps per-executable counters: how often a program turned out to be
  shared, how long it takes to exit after SIGTERM, and whether it came back after a stop.
  It uses them to choose default actions, graceful timeouts and idle grace periods. The
  data is plain JSON. Every decision is written to an audit log, and `taema explain` shows
  the reasoning.
- **Safe by construction.** The daemon runs as your user. The only privileged step,
  moving your own processes out of the login-session cgroup, is a small root helper that
  validates every request. Session infrastructure (compositor, audio, D-Bus, portals,
  keyrings, agents) is protected and never adopted or signalled.

## Requirements

- Void Linux (glibc or musl) with runit
- cgroup v2 mounted at `/sys/fs/cgroup` (the Void default)
- elogind, which gives each login session its own numeric cgroup. Other setups can set
  `paths.session_cgroup` to a fixed path.
- `python3` 3.11 or later, `iproute2` (`ss`), `util-linux` (`setpriv`), `sudo`

tæma uses only the Python standard library.

## Install

### From a release

Download `taema-<version>_1.noarch.xbps` from the
[releases page](https://github.com/Bongbetic/void-mods/releases) into an empty
directory, index it, and install it:

```sh
xbps-rindex -a taema-*.noarch.xbps
sudo xbps-install --repository="$PWD" taema
```

The package is unsigned, so this works only from a local directory repository.

### Build a package from source

```sh
git clone https://github.com/Bongbetic/void-mods
cd void-mods/taema
tools/build-xbps.sh                       # runs the tests, writes build/repo/
sudo xbps-install --repository="$PWD/build/repo" taema
```

### With void-packages

Copy `srcpkgs/taema/template` into your `void-packages` checkout and run:

```sh
./xbps-src pkg taema
sudo xbps-install --repository=hostdir/binpkgs taema
```

## Set up

The package creates the `taema` group and installs the service disabled, like every Void
service. Only members of the `taema` group are managed.

```sh
sudo usermod -aG taema "$USER"      # log out and back in for your shell to see the group
sudo ln -s /etc/sv/taema /var/service/
taema status
```

The service delegates `/sys/fs/cgroup/user/<uid>` to each group member and runs one
daemon per member. After you change group membership, run `sudo sv restart taema`.

### Choose a mode

tæma starts in `observe` mode, where it changes nothing. Move up one mode at a time:

| Mode | Behaviour |
|---|---|
| `observe` | Log every move and stop the daemon would make. Change nothing. |
| `adopt` | Move matching processes into scopes. Never kill. |
| `enforce` | Move, and stop scopes (GC, owner watch, session end). |

Set the mode for yourself in `~/.config/taema/taema.toml`:

```toml
mode = "adopt"
```

Restart your daemon with `sudo sv restart taema`. Watch
`~/.local/state/taema/decisions.log` for a few days. Check `taema gc --dry-run`, then
switch to `enforce` once the candidates it lists are only real leftovers.

## Usage

### Run a project in a scope

```sh
taema run emulator emulator -avd Pixel_8 -no-window   # scope-emulator
taema ls                                              # scopes, process counts, names
taema kill emulator                                   # stop the scope and everything in it
```

`taema kill` prints one line per process: `kill`, `share` (moved to `shared/` because
something outside still uses it) or `skip` (protected).

```
kill    41210 qemu-system-x86    no outside users
kill    41188 emulator           no outside users
share   41302 adb                outside users: tcp_server 127.0.0.1:5037 <- 127.0.0.1:51734
scope scope-emulator stopped
```

Useful options:

```sh
taema run --bind NAME CMD...      # stop the scope when CMD itself exits
taema run --owner PID NAME CMD... # stop the scope when PID exits
taema run --join NAME CMD...      # add a process to an existing scope
taema kill --dry-run NAME         # show the decisions, change nothing
taema kill -t 3 NAME              # 3 s between SIGTERM and SIGKILL
taema kill --keep adb NAME        # move adb aside instead of killing it
taema kill --hard NAME            # ignore detected outside users
```

`scoperun`, `scopekill` and `scopels` are aliases for `taema run`, `taema kill` and
`taema ls`.

### Inspect and teach

```sh
taema status               # daemon mode, owner watches, idle scopes, last GC
taema explain NAME|PID     # decision per member, edges found, learned stats
taema gc --dry-run         # what GC would stop now, and why
taema adopt --dry-run      # what adopt would move now
taema keep adb             # prefer keeping adb alive (feedback for the learner)
taema forget adb           # reset everything learned about adb
```

## Units

A unit describes how to recognise an app and how to manage its scope. System units live
in `/etc/taema/units/`. Your own go in `~/.config/taema/units/`, and a file with the same
name replaces the system one. The package enables `podman.toml`. More examples are in
`/usr/share/examples/taema/units/`: Claude Desktop, the herdr terminal server, and an
Android emulator project scope with a stop hook.

```toml
# ~/.config/taema/units/herdr.toml
[unit]
name = "app-herdr"
kind = "app"                  # adopted automatically
stop_when_unneeded = true     # GC stops it after idle_grace with no users

[match]                       # any of: exe, comm, cmdline_contains
comm = "herdr"
cmdline_contains = "server"

[kill]
survive_logout = true         # keep across logout
graceful = 10                 # seconds between SIGTERM and SIGKILL

[gc]
keep_while_children = true    # needed while it has child processes
```

App units can carve child scopes out of an adopted tree. Each child is bound to its own
root process:

```toml
[[children]]
name = "session"              # becomes session-<pid>
ancestor_comm = "disclaimer"
binds_to = "root"
```

Project scopes (`kind = "scope"`) are created with `taema run NAME`. Their unit may list
`keep = ["adb"]` and a stop `hook`. An executable `~/.config/taema/hooks/NAME.stop` runs
before `scope-NAME` is signalled, for example to let an emulator save its state.

## Configuration

`/etc/taema/taema.toml` holds system defaults and the hard rules. `~/.config/taema/taema.toml`
holds your overrides. Your file may change the mode, timers and seeds, and may add
protected entries. It can never remove a protected entry from the system file.

```toml
[timers]
adopt_interval = 15     # seconds between adopt passes
gc_interval = 60        # seconds between GC passes
idle_grace = 600        # seconds a shared scope must be unused before GC stops it
graceful_timeout = 10   # default seconds between SIGTERM and SIGKILL

[protected]
comm = ["my-shell"]                    # globs allowed; added to the system list
cgroup_prefix = ["/sys/fs/cgroup/x"]   # never read, never written

[protected.env_prefix]
XDG_RUNTIME_DIR = ["/run/mytool"]      # e.g. a tool with its own rootless podman
```

The root helper reads only the system file, and refuses it unless it is root owned and
not group or world writable.

## Safety rules

These rules are fixed. Learning and unit files cannot change them:

- Only your own processes. Root processes, other users' processes and kernel threads are
  never touched.
- Protected session infrastructure is never adopted or signalled.
- Configured cgroup prefixes and environment prefixes are never read or written.
- A scope that contains the caller is never stopped. The check is a cgroup path prefix,
  so `taema kill app-x` from inside `app-x/session-1` is refused.
- The root helper moves only processes that you own and that sit in a login-session
  cgroup or in your own subtree, and only into a leaf you own. It logs every move to
  `/var/log/taema/attach.log`.
- Learned data can only delay a kill (move a process to `shared/`). It never overrides a
  detected dependency or a hard rule.

## Files

| Path | Purpose |
|---|---|
| `/usr/bin/taema` | command line and daemon |
| `/usr/lib/taema/` | Python package |
| `/usr/libexec/taema/taema-attach` | root helper, run through sudo |
| `/etc/sudoers.d/taema` | lets `%taema` run the helper without a password |
| `/etc/sv/taema/` | runit service: delegation plus one daemon per member |
| `/etc/taema/` | system configuration and units |
| `~/.config/taema/` | your configuration, units and hooks |
| `~/.local/state/taema/` | `knowledge.json` (learning) and `decisions.log` (audit) |
| `/var/log/taema/` | service, per-user daemon and helper logs |

## Uninstall

```sh
sudo rm /var/service/taema
sudo xbps-remove taema
```

Scopes that still exist stay where they are until their processes exit. Your files in
`~/.config/taema` and `~/.local/state/taema` are not removed.

## Design

Read [docs/design.md](docs/design.md) for the cgroup layout, dependency detection, the
learning rules and the systemd concepts that tæma mirrors.

## License

MIT. See [LICENSE](../LICENSE).
