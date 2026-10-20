<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/taema-logo-dark.svg">
    <img src="docs/assets/taema-logo-light.svg" width="200" alt="tæma logo: a b-shaped glyph with a draining spiral inside a scope ring, one red dot slipping out">
  </picture>
</p>

<h1 align="center">tæma</h1>

<p align="center">
  <strong>Close an app. Actually close it.</strong><br>
  Process scopes for Void Linux that stop what a program left behind and spare what someone still needs.<br>
  <sub>systemd-style app scopes, <code>BindsTo</code> and <code>StopWhenUnneeded</code> for runit, built on cgroup v2</sub>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/platform-Void%20Linux-478061" alt="Void Linux">
  <img src="https://img.shields.io/badge/init-runit-black" alt="runit">
  <img src="https://img.shields.io/badge/python-3.11%2B-black" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/license-PolyForm%20Noncommercial-e8333a" alt="PolyForm Noncommercial 1.0.0">
</p>

<p align="center">
  <em>Made by</em><br>
  <a href="https://bongbetic.com"><img src="https://bongbetic.com/branding/bongbetic-logo-lockup.png" width="200" alt="Bongbetic"></a>
</p>

---

## Why "tæma"?

*tæma* (say "TY-ma") is Icelandic for **"to empty"**: to pour a vessel out until nothing
is left. That is the whole job. You stop a program, and tæma empties its scope: the
program, its children, and the children that double-forked and hoped you would not
notice.

The logo says the same thing. The **b** is a bowl with a spiral draining out of it. The
ring around it is the **scope**, a cgroup that nothing can sneak out of. The one **red
dot** is the helper that is still in use by someone else. tæma sees it, leaves it alive,
and moves it out of the way. A good emptying never pours out what a neighbour is still
drinking.

## In one minute

You close your IDE. The Android emulator it started keeps eating 3 GB of RAM. Your dev
server is still there, and so is a rootless podman pause process whose runtime directory
is long gone. On systemd every app lives in its own scope and the system cleans up. On
Void with runit, everything shares one login-session cgroup, and a process that detaches
(`setsid`, double fork, `nohup`) outlives its parent.

tæma gives every app its own scope and cleans up properly:

```sh
taema run emulator emulator -avd Pixel_8 -no-window   # start it inside a scope
taema ls                                              # see what lives where
taema kill emulator                                   # empty the scope
```

```
kill    41210 qemu-system-x86    no outside users
kill    41188 emulator           no outside users
share   41302 adb                outside users: tcp_server 127.0.0.1:5037 <- 127.0.0.1:51734
scope scope-emulator stopped
```

Everything is gone except `adb`, because another program is still talking to it. tæma
checked first (sockets, shared podman state, ptrace), kept `adb`, and told you why.

Or skip the typing. Run the daemon and it adopts running apps into scopes, stops a scope
when its owner exits, and garbage-collects helpers nobody uses. It needs no setup: in
`auto` mode it learns first and stops only what you told it to (see "Set up").

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

### From the GitHub repository

The packages are the assets of the latest release.

```sh
echo 'repository=https://github.com/Bongbetic/taema/releases/latest/download' | sudo tee /etc/xbps.d/20-taema.conf
sudo xbps-install -S taema
```

The first sync asks whether to import the repository key. The fingerprint is
`fa:d1:00:32:ce:b1:b9:fd:73:05:05:76:75:54:37:25`. Later updates come with `sudo xbps-install -Su`.

### From a release file

Download `taema-<version>_1.noarch.xbps` from the
[releases page](https://github.com/Bongbetic/taema/releases) into an empty
directory, index it, and install it:

```sh
xbps-rindex -a taema-*.noarch.xbps
sudo xbps-install --repository="$PWD" taema
```

A file you download this way is unsigned, so it works only from a local directory repository.

### Build a package from source

```sh
git clone https://github.com/Bongbetic/taema
cd taema/taema
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

Nothing to do. On first install the package adds every human user (uid 1000 to 59999
with a real login shell) to the `taema` group, links `/etc/sv/taema` into `/var/service`,
and, if zsh is installed, appends one guarded `# taema` line to `/etc/zsh/zshrc`. The
service re-scans the group every minute, so you need no `usermod`, no `ln -s`, and no
logout. Upgrades do none of this. Check with:

```sh
taema status
```

The service delegates `/sys/fs/cgroup/user/<uid>` to each group member and runs one
daemon per member. A user you add later with `usermod -aG taema USER` is picked up within
a minute.

### Auto mode: how it decides

Closing an app is not always clean. `npm run dev` exits and `esbuild` keeps running. You
close your editor and its language server stays behind. tæma watches for this. When a
program leaves something behind, tæma remembers "this leftover came from that program".
That match is called a **pair**. Later, it can clean up the leftover for you.

It never guesses about stopping. Each pair moves through three steps:

1. **Watch.** From the first minute, every app you run gets its own scope. tæma notes
   what survives when it closes. It stops nothing yet.
2. **Ask.** If you close a terminal job and something survives, your shell asks one
   question (see "The prompt" below). Answer `1` and tæma stops that leftover every time that
   program closes. Answer `3` and it never touches it.
3. **Learn from habit.** If you keep killing the same leftover yourself, tæma notices. It
   takes over after all of these are true: you did it at least 5 times on at least 3
   different days, you never kept it in the last 30 days, and tæma has been watching for 7
   days (or 20 closes). It then stops it politely (SIGTERM only, never a hard kill).

When tæma stops something because you answered `1`, it sends SIGTERM first, waits as long
as that program usually needs to exit (5 to 30 seconds, learned from past exits), and only
then sends SIGKILL.

What happens in other situations:

| You do this | tæma does this |
|---|---|
| Close a GUI app | In `adopt`, `auto`, and `enforce`, moves survivors into a `leftover/` scope and queues a review; `taema review` lists pending reviews. Reviews expire to keep after 14 days. In `observe`, it logs the would-contain action without moving anything. |
| Log out | Leaves scopes running, so tmux and `nohup` jobs survive. A scope stops only if every process in it is one tæma is sure about. |
| Close an app with `kill`, `pkill` or `killall` | Matches the vanished processes to your command and asks whether that app belonged to its usual parent. |

**It never stops these**, even if you said yes to something nearby:

- Your desktop's own infrastructure (compositor, audio, D-Bus).
- A process that something else still uses, such as a database a second program talks to.
- Terminals, tmux, screen and zellij, and editors that run terminals.
- Long-lived helpers: tmux, screen, zellij, abduco, dtach, mosh-server, ssh-agent,
  gpg-agent, keyboxd, dirmngr.
- Anything busy (above 1 % CPU over the last minute).
- Anything tæma cannot identify, or cannot read. When in doubt, it keeps the process and
  keeps learning.

**If tæma gets it wrong,** just start the program again. If you relaunch something within
30 minutes of an automatic stop, tæma treats the stop as a mistake. It pauses that pair
for 7 days and asks you again. You never need a command to undo it.

### Dial it down

`auto` is the default. To make tæma quieter, set a different mode:

| Mode | What happens |
|---|---|
| `auto` | Learns from app closes, reviews unlearned idle leftovers, and stops eligible idle shared or `stop_when_unneeded` scopes after safety and veto checks. |
| `adopt` | Adopts eligible apps, contains GUI survivors under `leftover/` for review, and honors `taema run --bind` by stopping that scope when its command exits; idle shared and unit scopes are reviewed, not stopped. |
| `observe` | Logs what it *would* do and leaves scopes and processes in place. |
| `enforce` | Applies unit and lifecycle rules, including GC for `stop_when_unneeded` scopes, with safety and veto checks. |

Leftover expiry is opt-in. `leftover_expire_days = 0` (the default) keeps unlearned
leftovers indefinitely. A positive value allows an aged, idle leftover to expire after that many
days, subject to the usual safety checks; an explicit keep or veto still wins. Review timeouts
resolve to keep and do not enable expiry.

```toml
[timers]
leftover_expire_days = 30 # optional; default 0 disables expiry
```

```sh
taema config set mode '"adopt"'
```

Configuration changes reload the daemon automatically. To switch the shell question off, put
`TAEMA_NO_PROMPT=1` in your shell environment. `taema forget NAME` makes tæma unlearn one
program.

Watch `~/.local/state/taema/decisions.log` and run `taema gc --dry-run` any time to see
what tæma would do.

## Usage

### Run a project in a scope

```sh
taema run emulator emulator -avd Pixel_8 -no-window   # scope-emulator
taema ls                                              # scopes, counts, memory, pressure
taema kill emulator                                   # stop the scope and everything in it
```

`taema ls` prints one row per scope with `procs` (process count), `MEM` (current memory,
human-readable, from `memory.current`) and `PSI` (recent memory pressure, `some avg10`,
from `memory.pressure`). A scope whose memory files are missing or unreadable shows `-`:

```
name                         procs       MEM    PSI  comms
scope-emulator                 12      1.5G   0.42  emulator,qemu-system-x86
  qemu-9                        1      1.4G   0.42  qemu-system-x86
scope-web                       3     24.7M   1.20  firefox,WebExtensions
scope-fresh                     1         -      -  sleep
shared                          0         -      -
  adb-1                         1    768.0K   0.00  adb
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
taema review               # pending GUI-close reviews
taema explain NAME|PID     # decision per member, edges found, learned stats
taema gc --dry-run         # what GC would stop now, and why
taema adopt --dry-run      # what adopt would move now
taema keep adb             # prefer keeping adb alive (feedback for the learner)
taema forget adb           # reset everything learned about adb
```

### The prompt

After a command that ran for 2 s or more, tæma looks for processes it left running. If
it cannot tell whose they are, it asks once, at your next prompt:

```
tæma: `npm run dev` left 2 processes running (node:esbuild, node:vite).
  [1] part of npm run dev: stop them when it closes
  [2] part of another app: code (seen 3x)
  [3] standalone app: give them their own scope, never stop with a parent
  [Enter] ask me later
```

Press one key. Your answer is remembered and applies to that pair (owner, leftover) from
the next close on, also for GUI closes. It asks at most 3 times a day, and each pair only
once a week. It stays silent when you have typed ahead and gives up after 15 s. It also asks
after `kill`, `pkill` and `killall` when the app you closed belonged to another app.

The hook is `shell/taema.bash` (installed to `/etc/bash/bashrc.d/taema.sh`), `taema.fish`
(fish picks it up by itself) or `taema.zsh` (the package hooks it into `/etc/zsh/zshrc`
when zsh is installed). A normal prompt runs no process and uses no `DEBUG` trap. Under bash the
hook sees `kill` only when ble.sh is loaded. Set `TAEMA_NO_PROMPT=1` to turn it off.

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

Configuration layers apply in this order: built-in defaults, `/etc/taema/taema.toml`,
`/etc/taema/taema.d/*.toml`, `~/.config/taema/taema.toml`, then
`~/.config/taema/taema.d/*.toml`, with drop-ins sorted by filename. Later values override
earlier ones. `[protected]` entries always union, so a user file cannot remove a protected
entry from the system configuration. `TAEMA_CONFIG=/path/to/file.toml` replaces the file
layers and is useful for isolated runs.

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

Use `taema config show --sources` to inspect effective values and their source files.
`taema config get KEY`, `set KEY VALUE`, and `unset KEY` read or edit only the CLI-managed
`~/.config/taema/taema.d/50-cli.toml`; hand-written configuration files are left alone. Values
for `set` use TOML syntax, for example `taema config set timers.idle_grace 300` or
`taema config set mode '"adopt"'`. `taema config edit` opens the managed drop-in in `$EDITOR`,
validates it on save, and restores the previous file if validation fails. `taema config diff`
compares the effective config with system defaults. Successful edits ask the daemon to reload;
`taema reload` requests the same reload directly, and SIGHUP or config/unit file changes also
reload automatically. An invalid change leaves the last good config active; `taema status` and
`taema doctor` show the file and TOML line/column to fix.

Switch lifecycle policy with `taema mode observe|adopt|enforce|auto`. It writes the managed
drop-in, reloads the daemon, and lists the authorization capabilities that changed. Select
`taema profile default|focus|battery|game|quiet|server` to apply a named overlay; a profile
selection persists until `taema profile auto`. User overlays use `[profile.NAME]` tables and
the same dotted configuration keys as the base files. `status` shows the active profile and
the reason for its selection. The mode command stores `profile.runtime_mode`, which overrides
the base mode and any profile mode; `taema config unset profile.runtime_mode` returns to the
configured mode. `TAEMA_CONFIG` continues to take precedence over managed changes.

The built-in `focus` profile enables the focus QoS flag. `battery` lengthens adopt and GC
intervals and shortens the configured freeze delay. `game` protects `gamescope` and Steam,
disables notifications, and shortens adopt/GC intervals. `quiet` suppresses automatic stops
and notifications. `server` disables the agent, notifications, window-close handling, and
desktop launch wrapping. Configuration keys for features that are not available yet remain
valid so profile files can describe the intended policy ahead of those features.

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
| `/usr/libexec/taema/taema-hook` | prompt client, called by the shell hooks |
| `/usr/share/taema/shell/` | shell hooks for bash, zsh and fish |
| `/etc/sudoers.d/taema` | lets `%taema` run the helper without a password |
| `/etc/sv/taema/` | runit service: delegation plus one daemon per member, re-scanned every minute |
| `/var/service/taema` | link to the service, made and removed by the package scripts |
| `/etc/taema/` | system configuration and units |
| `~/.config/taema/` | your configuration, units and hooks |
| `~/.local/state/taema/` | `state.db` (current state), `knowledge.json` (preserved legacy/export), and `decisions.log` (audit) |
| `/var/log/taema/` | service, per-user daemon and helper logs |

## Upgrade and downgrade state

The first daemon startup imports legacy 0.2 learning into SQLite and keeps a private
30-day backup. To export state before a downgrade, use `taema learn export --format v2`.
See the [state migration guide](../docs/legacy-state-migration.md) for the full sequence.

## Uninstall

```sh
sudo xbps-remove taema
```

The remove script stops the service, deletes the `/var/service/taema` link and removes the
`# taema` line from `/etc/zsh/zshrc`. An upgrade does none of this. Scopes that still exist
stay until their processes exit. Left on purpose: `~/.config/taema`, `~/.local/state/taema`,
`/var/log/taema` and the `taema` group. Delete them for a clean slate:

```sh
rm -rf ~/.config/taema ~/.local/state/taema
sudo gpasswd -d "$USER" taema      # repeat per user
sudo groupdel taema
sudo rm -rf /var/log/taema
```

## Design

Read [docs/design.md](docs/design.md) for the cgroup layout, dependency detection, the
learning rules and the systemd concepts that tæma mirrors.

## License

[PolyForm Noncommercial 1.0.0](../LICENSE). Use, modify and share it for any noncommercial
purpose. Commercial use and commercial distribution are not allowed. Whenever you share it,
keep the license text and the `Required Notice:` line (credit to Bongbetic) with it.

This license covers every version of tæma, including the earlier releases.
