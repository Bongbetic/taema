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
  (compositor, audio, D-Bus). It starts in `observe` mode, which changes nothing.

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

The package creates the `taema` group and installs the service disabled, like every Void
service. Only members of the `taema` group are managed.

```sh
sudo usermod -aG taema "$USER"      # log out and back in to pick up the group
sudo ln -s /etc/sv/taema /var/service/
taema status
```

tæma starts in `observe` mode: it logs what it would do and changes nothing. Move up one
mode at a time in `~/.config/taema/taema.toml`:

| Mode | Behaviour |
|---|---|
| `observe` | Log every move and stop. Change nothing. |
| `adopt` | Move matching processes into scopes. Never kill. |
| `enforce` | Move, and stop scopes (GC, owner watch, session end). |

```toml
mode = "adopt"
```

Then `sudo sv restart taema`. Watch `~/.local/state/taema/decisions.log` for a few days,
check `taema gc --dry-run`, and switch to `enforce` once it lists only real leftovers.

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
sudo rm /var/service/taema          # stop the service
sudo xbps-remove taema              # remove the package
```

Running scopes stay until their processes exit. These are left on purpose, so delete
them if you want a clean slate:

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
