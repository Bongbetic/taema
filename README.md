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
- **Learns.** It remembers which programs turned out to be shared and how long they take
  to exit, and `taema explain` shows why it decided what it did.
- **Safe.** It touches only your own processes and never session infrastructure
  (compositor, audio, D-Bus). For its first week it only adopts and learns; it stops a
  leftover only after you answered a question about it, or after strong evidence.

## Install

Requirements: Void Linux (glibc or musl) with runit, cgroup v2 at `/sys/fs/cgroup`,
elogind, `python3` 3.11+, `iproute2`, `util-linux`, `sudo`. tæma uses only the Python
standard library.

Pick one way.

**1. From a release** (quickest). Download `taema-0.1.0_1.noarch.xbps` from the
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

The default mode is `auto`: tæma adopts running apps and learns from day one, and stops
a leftover only after you said so in the prompt (or after a week and strong evidence). Run
the commands you always run. When something is left behind, tæma asks once:

```
tæma: `npm run dev` left 2 processes running (node:esbuild, node:vite).
  [1] part of npm run dev: stop them when it closes
  [2] part of another app: code (seen 3x)
  [3] standalone app: give them their own scope, never stop with a parent
  [Enter] ask me later
```

### What auto mode does

`auto` is the default. From the first minute it **adopts** running apps into scopes and
**learns**. It does not stop anything at first. It stops a leftover only in two cases:

- **You answered.** In the prompt you said "stop them when it closes" for that pair
  (owner, leftover). The next close of that owner stops that leftover: SIGTERM, a grace
  period learned from past exits (5 to 30 s), then SIGKILL.
- **Strong evidence, after a burn-in.** Seen stopped by you at least 5 times on at least 3
  different days, never kept in 30 days, and a 7-day burn-in (or 20 closes) has passed.
  Evidence alone only sends SIGTERM.

Safety rules that auto mode never bends:

- **Regret.** If you relaunch the same program within 30 minutes of an automatic stop,
  tæma counts that as a "keep", pauses the pair for 7 days and asks you again. A wrong
  answer fixes itself with no command.
- **Never stopped:** protected session infrastructure, anything another process still
  uses (an edge), terminal hosts (anything holding `/dev/ptmx`: terminals, tmux, screen,
  zellij, editors), anything above 1 % CPU over 60 s, and anything whose origin tæma
  cannot tell.
- **Persist seeds** (tmux, screen, zellij, abduco, dtach, mosh-server, ssh-agent,
  gpg-agent, keyboxd, dirmngr) are never garbage-collected as idle.
- Unknown is never "no": unreadable `/proc` data, a failed `ss` run or a zombie means
  keep and learn.

### Turn it down

```toml
# ~/.config/taema/taema.toml
mode = "observe"      # log what would happen, change nothing; or "adopt" (move, never kill)
```

Then `sudo sv restart taema`. `TAEMA_NO_PROMPT=1` in your shell environment turns the
question off. `taema forget NAME` resets what was learned about one program.

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
