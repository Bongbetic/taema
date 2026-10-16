<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="taema/docs/assets/taema-logo-dark.svg">
    <img src="taema/docs/assets/taema-logo-light.svg" width="160" alt="tæma logo">
  </picture>
</p>

<h1 align="center">taema</h1>

<p align="center">
  <strong>Close an app. Actually close it.</strong><br>
  Dependency-aware, self-managing process scopes for Void Linux, packaged as an XBPS package
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
ring is the **scope**, a cgroup nothing can sneak out of. The red dot is a helper that
someone else still uses: tæma leaves it alive and moves it aside. A good emptying never
pours out what a neighbour is still drinking.

## What it does

Void Linux keeps things small: runit instead of systemd, and no hidden machinery. But
systemd-style app scopes are missing. On Void every app shares one login-session cgroup,
so a process that detaches (`setsid`, double fork, `nohup`) outlives the program that
started it. Close your IDE and the Android emulator, dev server and podman pause process
it started keep running.

tæma fixes that:

- **Scopes.** Each managed program gets its own cgroup v2 scope that holds its whole
  process tree. Forking and detaching cannot escape it.
- **Dependency-aware stop.** Before it empties a scope, tæma checks who outside still uses
  each member (sockets, shared podman state, ptrace). Used helpers are kept, the rest
  stop.
- **Self-managing.** A daemon adopts running apps into scopes, stops a scope when its
  owner exits (`BindsTo`), garbage-collects unused helpers (`StopWhenUnneeded`) and
  cleans up at logout.
- **Learns on its own.** It works out which program started which (owner and leftover),
  which helpers are shared, and how long each takes to exit. When you close a terminal
  job that leaves processes behind, it asks one short question in your shell. GUI apps
  are learned silently. `taema explain` shows why it decided what it did.
- **Zero setup.** Install the package and carry on. No commands to learn or run.
- **Safe.** It touches only your own processes and never session infrastructure
  (compositor, audio, D-Bus). It adopts and learns from the first minute, but it stops a
  leftover only after you answered a question about it, or after strong evidence.

## Install

Requirements: Void Linux (glibc or musl) with runit, cgroup v2 at `/sys/fs/cgroup`,
elogind, `python3` 3.11+, `iproute2`, `util-linux`, `sudo`. tæma uses only the Python
standard library.

Pick one way.

**1. From a release** (quickest). Download `taema-0.2.0_1.noarch.xbps` from the
[releases page](https://github.com/Bongbetic/taema/releases) into an empty directory:

```sh
xbps-rindex -a taema-*.noarch.xbps
sudo xbps-install --repository="$PWD" taema
```

**2. Build from source.**

```sh
git clone https://github.com/Bongbetic/taema
cd taema/taema
tools/build-xbps.sh                       # runs the tests, writes build/repo/
sudo xbps-install --repository="$PWD/build/repo" taema
```

**3. With void-packages.** Copy `taema/srcpkgs/taema` into your `void-packages` checkout:

```sh
./xbps-src pkg taema
sudo xbps-install --repository=hostdir/binpkgs taema
```

The package is unsigned, so it installs only from a local directory repository.

## Set up

Nothing. The package does it when it is first installed: it adds every human user (uid
1000 and up, with a real login shell) to the `taema` group, enables the service, and hooks
the prompt into bash, fish and (if installed) zsh. No `usermod`, no `ln -s`, and no
logout: `taema` finds your group through the service, which checks for new members every
minute.

```sh
taema status
```

Upgrades change none of this. Only a first install does it.

Run the commands you always run. When you close a terminal job and something is left
behind, tæma asks once in your shell (bash, zsh or fish):

```
tæma: `npm run dev` left 2 processes running (node:esbuild, node:vite).
  [1] part of npm run dev: stop them when it closes
  [2] part of another app: code (seen 3x)
  [3] standalone app: give them their own scope, never stop with a parent
  [Enter] ask me later
```

### How auto mode decides

Closing an app is not always clean. `npm run dev` exits and `esbuild` keeps running. You
close your editor and its language server stays behind. tæma watches for this. When a
program leaves something behind, tæma remembers "this leftover came from that program".
That match is called a **pair**. Later, it can clean up the leftover for you.

It never guesses about stopping. Each pair moves through three steps:

1. **Watch.** From the first minute, every app you run gets its own scope. tæma notes
   what survives when it closes. It stops nothing yet.
2. **Ask.** If you close a terminal job and something survives, your shell asks one
   question (see above). Answer `1` and tæma stops that leftover every time that program
   closes. Answer `3` and it never touches it.
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
| Close a GUI app | Moves what it left behind into a `leftover/` scope and learns from it, silently. No pop-up. It stops them only when the pair is already decided and they are idle. |
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
| `auto` | Adopts, learns and cleans up as described above. |
| `adopt` | Gives apps their own scopes. Never stops anything. |
| `observe` | Only writes what it *would* do to the log. Changes nothing. |

```toml
# ~/.config/taema/taema.toml
mode = "adopt"
```

Then run `sudo sv restart taema`. To switch the shell question off, put
`TAEMA_NO_PROMPT=1` in your shell environment. `taema forget NAME` makes tæma unlearn one
program.

## Use

```sh
taema run emulator emulator -avd Pixel_8 -no-window   # start a program in a scope
taema ls                                              # scopes and process counts
taema kill emulator                                   # empty the scope
```

```
kill    41210 qemu-system-x86    no outside users
kill    41188 emulator           no outside users
share   41302 adb                outside users: tcp_server 127.0.0.1:5037 <- 127.0.0.1:51734
scope scope-emulator stopped
```

`kill` stopped the emulator and kept `adb`, because another program still talks to it.
Each line is `kill`, `share` (kept, moved to `shared/`) or `skip` (protected).

More commands:

```sh
taema run --bind NAME CMD...      # stop the scope when CMD exits
taema run --owner PID NAME CMD... # stop the scope when PID exits
taema kill --dry-run NAME         # show decisions, change nothing
taema kill --keep adb NAME        # move adb aside instead of killing it
taema status                      # daemon mode, owner watches, idle scopes
taema explain NAME|PID            # why tæma decided what it did
taema gc --dry-run                # what GC would stop now
taema keep adb                    # prefer keeping adb alive
taema forget adb                  # reset what was learned about adb
```

`scoperun`, `scopekill` and `scopels` are aliases for `taema run`, `taema kill` and
`taema ls`. Teach tæma new apps with unit files in `~/.config/taema/units/`. Units,
configuration, safety rules and installed files are in
**[taema/README.md](taema/README.md)**.

## Uninstall

```sh
sudo xbps-remove taema
```

The package's remove script stops the service, deletes the `/var/service/taema` link and
removes the `# taema` line from `/etc/zsh/zshrc`. Running scopes stay until their
processes exit. These are left on purpose, so delete them if you want a clean slate:

```sh
rm -rf ~/.config/taema ~/.local/state/taema   # your config, learning data, audit log
sudo gpasswd -d "$USER" taema                 # leave the group (repeat per user)
sudo groupdel taema                           # drop the group
sudo rm -rf /var/log/taema                    # service and helper logs
```

Installed from a local build? Also delete the downloaded `.xbps` or `build/repo/`.

## Layout

```
taema/                  this repository
  taema/                the package
    srcpkgs/taema/      void-packages template
    tools/build-xbps.sh builds a local .xbps without a void-packages checkout
    Makefile            make test, make install DESTDIR=...
    README.md           full reference: units, configuration, safety rules
    docs/               design notes and logo
```

## License

MIT. See [LICENSE](LICENSE).
