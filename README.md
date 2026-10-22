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
  <em>Made by</em> <a href="https://bongbetic.com"><strong>Bongbetic</strong></a><br>
  <a href="https://bongbetic.com"><img src="https://bongbetic.com/branding/bongbetic-logo-lockup.png" width="360" alt="Bongbetic logo"></a>
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

**1. From the GitHub repository** (quickest, and the one that updates itself). The
packages are the assets of the latest release. Add that as an XBPS repository once, then
install like any other package:

```sh
echo 'repository=https://github.com/Bongbetic/taema/releases/latest/download' | sudo tee /etc/xbps.d/20-taema.conf
sudo xbps-install -S taema
```

The first sync asks whether to import the repository key. Check that the fingerprint is

```
fa:d1:00:32:ce:b1:b9:fd:73:05:05:76:75:54:37:25
```

and answer `y`. Updates arrive with the rest of your system: `sudo xbps-install -Su`. The
repository serves glibc and musl builds for x86_64, i686, aarch64, armv7l and armv6l.

**2. From a release file.** Download `taema-0.2.1_1.noarch.xbps` from the
[releases page](https://github.com/Bongbetic/taema/releases) into an empty directory:

```sh
xbps-rindex -a taema-*.noarch.xbps
sudo xbps-install --repository="$PWD" taema
```

**3. Build from source.**

```sh
git clone https://github.com/Bongbetic/taema
cd taema/taema
tools/build-xbps.sh                       # runs the tests, writes build/repo/
sudo xbps-install --repository="$PWD/build/repo" taema
```

**4. With void-packages.** Copy `taema/srcpkgs/taema` into your `void-packages` checkout:

```sh
./xbps-src pkg taema
sudo xbps-install --repository=hostdir/binpkgs taema
```

The license is noncommercial, so void-packages' main repository (free software only) would
not accept this template. Use it from your own `void-packages` checkout.

Packages you build or download yourself are unsigned, so they install only from a local
directory repository.

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
taema ls                                              # scopes, counts, memory, pressure
taema kill emulator                                   # empty the scope
```

```
name                         procs       MEM    PSI  comms
scope-emulator                 12      1.5G   0.42  emulator,qemu-system-x86
  qemu-9                        1      1.4G   0.42  qemu-system-x86
scope-web                       3     24.7M   1.20  firefox,WebExtensions
scope-fresh                     1         -      -  sleep
shared                          0         -      -
  adb-1                         1    768.0K   0.00  adb
```

`MEM` is the scope's current memory in human-readable bytes, `PSI` its recent memory
pressure (`some avg10`); a scope without readable memory files shows `-`.

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

## Releases and updates

A release needs no manual work. Bump `__version__` in `taema/src/taema/__init__.py`, commit,
then push a tag named `taema-vX.Y.Z`:

```sh
git tag taema-v0.4.0 && git push origin taema-v0.4.0
```

The `release` workflow runs the tests, builds the `.xbps`, signs an XBPS repository, and
attaches it with the package to the GitHub release. xbps reads it from
`https://github.com/Bongbetic/taema/releases/latest/download`, so the newest release is
always the repository. The workflow then commits a bump of `version` and
`checksum` in the void-packages template. Anyone who added the repository gets the new version with
`sudo xbps-install -Su`. The package's install script changes nothing on an upgrade.

Once the template is merged into void-packages, `srcpkgs/taema/update` lets
`./xbps-src update-check taema` and Void's update bot find each new release by its tag.

Maintainer setup, once: the repository is signed with an RSA key. Store the private key as
the Actions secret `XBPS_PRIVKEY`. Nothing else is needed. If the key ever changes, every
user has to accept the new fingerprint.

## Checks

The `ci` workflow runs on every push and pull request: the unit and packaging test
suites and package build, as an unprivileged user, in the Void glibc and Void musl
containers with the distribution Python. Its Python 3.11 job also runs Ruff lint and
format checks, mypy, and the coverage report and gate. Reproduce that quality job from
the repository root with:

```sh
python3 -m venv /tmp/taema-quality-venv
/tmp/taema-quality-venv/bin/python -m pip install ruff==0.17.1 mypy==2.4.0 coverage==7.16.2
cd taema
/tmp/taema-quality-venv/bin/ruff check src tests tools
/tmp/taema-quality-venv/bin/ruff format --check src tests tools
/tmp/taema-quality-venv/bin/mypy src/taema
PYTHONPATH=src /tmp/taema-quality-venv/bin/coverage run -m unittest discover -s tests -t .
/tmp/taema-quality-venv/bin/coverage report
/tmp/taema-quality-venv/bin/coverage json -o /tmp/taema-coverage.json
/tmp/taema-quality-venv/bin/python tools/check_coverage.py /tmp/taema-coverage.json
cd ..
```

Run the Void test and package build steps locally from the repository root with:

```sh
make -C taema test        # the test suites (unit and packaging)
taema/tools/build-xbps.sh # the package build; runs the suites first, needs xbps-create/xbps-rindex
```

The test suites need only Python 3.11+ and `make`; the package build also needs
`xbps-create` and `xbps-rindex`. A failing step fails the workflow run, which marks the
commit and the pull request as failed. The tag-triggered `release` workflow is separate
and unchanged.

## Layout

```
taema/                  this repository
  taema/                the package
    srcpkgs/taema/      void-packages template and update-check rule
    tools/build-xbps.sh builds a local .xbps without a void-packages checkout
    Makefile            make test, make install DESTDIR=...
    README.md           full reference: units, configuration, safety rules
    docs/               design notes and logo
```

## License

[PolyForm Noncommercial 1.0.0](LICENSE). Use, modify and share it for any noncommercial
purpose. Commercial use and commercial distribution are not allowed. Whenever you share it,
keep the license text and the `Required Notice:` line (credit to Bongbetic) with it.

This license covers every version of tæma, including the earlier releases.
