# Disposable Void VM test harness

`tæma` ships a QEMU-based harness that verifies the package end to end on a
real Void system without touching the maintainer's machine.  One command
builds the package from the working tree, boots fresh Void glibc and musl VMs,
installs the package, enables the runit service, runs scripted scenarios as a
test user with a delegated cgroup session, and saves logs and results as
artifacts.

## The one command

```sh
make -C taema vm-test                      # smoke + M0 acceptance on glibc + musl (default)
make -C taema vm-test VMFLAGS="--libc glibc"          # one libc only
make -C taema vm-test VMFLAGS="--allow-network --scenarios all"
make -C taema vm-test VMFLAGS="--allow-network --scenarios m1,m2,upgrade"  # M1/M2 release gate
make -C taema vm-test VMFLAGS="--allow-network --scenarios m3 --libc glibc --memory-mb 1024"  # M3 pressure gate
```

Equivalent direct invocation: `taema/tools/vm/vmh run [flags]`.

`vmh` subcommands:

| Command | Purpose |
|---|---|
| `vmh doctor` | check host prerequisites (qemu, ssh, xbps, mkfs, …) |
| `vmh fetch --allow-network` | download + sha256-verify the cached base tarballs (and the previous release package when the upgrade scenario is configured) |
| `vmh build` | build `taema-<version>_1.noarch.xbps` from the working tree (`tools/build-xbps.sh`) |
| `vmh run [--dry-run]` | the full pipeline: build → image cache → boot → provision → scenarios → artifacts → teardown |
| `make -C taema vm-dry-run` | print the complete plan (qemu argv, ssh/scp steps) without side effects |

Exit codes: `0` success, `1` scenario/step failure, `2` refusal (missing
prerequisite, missing `--allow-network`, bad configuration).

## Prerequisites

- `qemu-system-x86_64`, `qemu-img` (KVM used automatically when `/dev/kvm` is
  usable; otherwise TCG — `--tcg` forces emulation)
- `ssh`, `scp`, `ssh-keygen`
- `make`, `xbps-create`, `xbps-rindex` (package build; this host is Void)
- `mke2fs`, `tar`, `unshare` (rootless image build; user namespaces required)
- `git` for building the 0.3.0 comparison package from its local tag
- Network **only** for first-time fetches, explicitly opted in with
  `--allow-network`: the official Void rootfs tarballs, the packages the image
  build installs (kernel, sshd, dhcpcd, python3, iproute2, sudo, earlyoom), and the
  previous release package from GitHub.  With a populated cache the whole
  pipeline runs offline.

`vmh run` refuses to start (exit 2) when a tool is missing, when cached
artifacts would require downloads without `--allow-network`, or when a run
directory would be reused.

## How it works

1. **Package**: `tools/build-xbps.sh` stages `make install` and produces
   `build/repo/taema-<version>_1.noarch.xbps` plus repodata.
2. **Base images** (cached under `build/vm/images/<libc>/`): Void publishes no
   qcow2 images, so the harness builds one per libc from the pinned official
   rootfs tarball (sha256 in `tools/vm/config.toml`):
   extract → configure inside `unshare -rmfp --mount-proc=<rootfs>/proc`
   (`tools/vm/mkimage.sh`: kernel plus a generic initramfs, sshd with key-only
   login for the `vmadmin` admin, dhcpcd, runtime dependencies, services
   enabled in the durable `/etc/runit/runsvdir/default` runlevel) → assemble
   the ext4 disk with `mke2fs -d`
   (no root, no loop devices, no host mounts) → `qemu-img convert` to
   `base.qcow2`, keep `vmlinuz`/`initramfs.img` for direct `-kernel` boot.
   Because extraction is unprivileged, every file carries the builder's uid;
   a fixup prepended to `/etc/runit/1` chowns the rootfs once, before any
   service starts (sshd StrictModes and sudo require correct owners) and
   restores the setuid/setgid bits that chown clears, so `sudo -n` provisioning
   works inside the guest.
3. **Every run starts from a clean snapshot**: a fresh run directory
   (`build/vm/runs/<ts>-<pid>-<libc>/`) gets its own qcow2 overlay backed by
   the cached base; the overlay is deleted at teardown (`--keep-run` keeps it
   for debugging).  QEMU serial output, qemu log, per-step ssh/scp logs,
   guest results and daemon logs all land in the run directory.
4. **Provisioning** (root in the guest via `sudo -n`): installs the package
   from the transferred local repository only (`xbps-install -i`), creates the
   test user (`taematest`), adds it to group `taema` (the runit service
   delegates `/sys/fs/cgroup/user/<uid>` to that group), creates
   `/run/user/<uid>`, grants the test user harness-only passwordless sudo for
   privileged scenario steps, and waits for `taema status` to answer.
5. **Scenarios** run as the test user (`tools/vm/scenario.py`) and write a
   JSON result per scenario into the collected artifacts.

## Scenario API

`tools/vm/scenario.py` (imported by the unit tests off-line against temp dirs
via the `TAEMA_CGROOT`/`TAEMA_PROCROOT` seams):

- `spawn_gui_tree(workdir, children)` — a root process that mimics a GUI app
  root and spawns children; the tree survives a login-less session end
- `close_root(pid)` — terminate only the root; children must survive
- `wait_for_event(decisions.log, pattern)` — wait for daemon audit events
- `wait_for_scope` / `assert_scope_member` / `scope_members` / `scope_of` —
  scope membership assertions against the cgroup tree
- `capture_daemon_logs(dest)` — copy `decisions.log` and friends into the
  artifact directory (plus readable service logs)
- `run_privileged(argv)` — privileged setup steps, argv only (never a shell
  line), executed through `sudo -n`

Built-in scenarios:

- **smoke** — daemon up in `auto` mode → spawn the tree → wait until the root
  is contained in an `app-*` scope → wait for the matching `adopt` audit event
  → close the root → assert both survivors are members of the same
  `leftover/*` scope → capture daemon logs.
- **m0** — exercise GUI survivor containment and review in `adopt`, manual-stop
  vetoes, `taema run --bind` owner exit, runtime-directory GC in `auto`, and
  observe-mode no-mutation plus deduplicated would-stop audit records. It waits
  one real hour for an idle scope to reach its GC threshold, checks repeated
  unchanged passes, then advances a clock through a separate simulated 24-hour
  GC test. The per-scenario timeout is long enough for the real idle window.
- **upgrade** — remove the installed package, install the previous release,
  assert its version and daemon health, then install the current package and
  verify the version, service, and daemon health. The previous package can be
  built from its local source tag without downloading a release asset.
- **remove** — `xbps-remove taema`, then verify cleanup: package not
  queryable, binaries and the `/var/service/taema` link gone, no `taema
  daemon` process left.

- **m1** — keep a live managed app running while a glibc or musl VM installs the 0.3.0
  source-tag package with a committed JSON fixture and upgrades to 0.4.0. It checks valid
  decision preservation, invalid-owner review, the private backup, and no stop events.
- **m2** — replay the anonymized learning fixture and check owner hygiene and authorization
  reasons; verify signature matching, stop undo, and offline veto refusal with exit 4.
- **m3** — in a disposable 1 GiB QEMU guest, run live HTTP wake and fake QMP/save-hook
  checks, apply bounded memory pressure, and require guard reclaim and freezing above the
  earlyoom floor. Verify a leftover has `oom_score_adj=500`, record earlyoom's selected
  process when it fires, then measure daemon RSS, CPU, sampling, and pressure triggers for
  610 seconds. The two-libc run therefore takes at least 20 minutes plus guest setup.
  earlyoom is installed only inside the disposable guest.
- **graphical** — start a disposable headless graphical session (private
  dbus-daemon, `weston --backend=headless` as the outer root, niri nested
  inside it) under a test-owned `XDG_RUNTIME_DIR`, run a scripted
  `org.freedesktop.Notifications` server (`tools/vm/notify_server.py`) that
  records notifications and closes them or invokes actions on cue, open and
  close test windows and move focus through `niri msg`, read the window
  list back, and capture the headless output with `grim`, verifying the PNG
  decodes with the stdlib-only `read_png` (no new dependencies). The
  capture lands in the artifacts directory as `graphical.png`;
  `image_diff_fraction` compares two captures.
- **m5** — the 0.7.0 desktop and session gate (issue #67) inside the
  graphical session with the session agent up: default batching and grace
  delays verified first with batching and grace at stock values, then with
  fast test delays a last-window close with a surviving child reviews
  within 3 seconds and Stop applies it, `on_last_window = quit` stops past
  the grace while a reopen inside the grace cancels the stop, a wrapped
  desktop entry launches in its scope with `launched_by=launch` and the
  desktop id in `why`, killing the agent degrades to process-only mode and
  a restart re-registers within 30 seconds, a scripted storm of 50 closes
  stays within `max_per_hour` with a widget-feed screenshot, and the
  `taema-agent(1)` page plus the niri autostart snippet are installed.

## Artifacts

Per run, under `build/vm/runs/<run>/`:

```
summary.json          overall result per libc/scenario
serial.log            guest console (includes the ownership-fixup marker)
qemu.log              qemu stdout/stderr
logs/*.log            every harness step (provision, scenarios, collect)
artifacts/<name>.json per-scenario step results
artifacts/daemon-logs/ decisions.log and other daemon logs from the guest
known_hosts, qemu.pid transport state for this run only
```

## Safety: what the harness never does

- It never writes to the host's cgroups, never enables or stops any host
  service, and never modifies host user state: all state lives under
  `taema/build/vm/` (gitignored), and `~/.ssh/known_hosts` is replaced by a
  per-run file (`GlobalKnownHostsFile=/dev/null`).
- QEMU uses a disposable overlay; the cached base image is read-only in
  practice (each run gets its own copy-on-write snapshot).
- SSH and port forwarding bind to `127.0.0.1` only; guest access is a
  throwaway key generated into the state directory.
- Root inside the guest is reached only through `sudo -n` from the harness
  admin created in the image; nothing privileged executes on the host.

## M1, M2, and M3 release acceptance

Run the m1, m2, and upgrade scenarios on both libcs before the 0.4.0 tag. The m1 scenario
builds the previous package from the local taema-v0.3.0 source tag when it is not cached,
then checks a live application survives the package change and that SQLite migration keeps
valid answers, reviews invalid owners, and saves a private backup. The m2 scenario replays
the committed anonymized learning fixture, checks signature matching and stop undo, and
confirms an offline veto makes a manual stop return exit code 4.

The VM workflow checkout fetches full Git history so the previous source tag is available.
Populate the root image cache with the explicit network option when needed.

M3's pressure probe runs only inside QEMU and confines its memory hogs, cgroups, and temporary
configuration to the disposable guest. It needs a low-memory guest and at least 610 seconds
per libc to complete the idle-footprint gate.

## M5 release acceptance

Run the m5 scenario on both libcs before the 0.7.0 tag:

```sh
make -C taema vm-test VMFLAGS="--allow-network --scenarios m5"
```

It starts the disposable graphical session (weston headless plus nested
niri under a test-owned `XDG_RUNTIME_DIR`), writes a fast test drop-in
(`batch_seconds = 0`, `windowless_grace = 3`, fast adopt, `launch_wrap`
enabled) only after proving the stock 60-second batching delay and the
30-second grace hold, then checks every M5 criterion from issue #67 with
the session agent up. The drop-in and the `m5quit` unit are removed and
the daemon restarted during teardown. Captures land next to the
per-scenario results as `m5.png` and `m5-notify.jsonl`.

## CI

`.github/workflows/vm-harness.yml` runs the same command on a self-hosted
runner labelled `kvm` (`workflow_dispatch` only, so it never runs where KVM
is unavailable).  Job artifacts upload `taema/build/vm/runs/`.

## Unit tests

The listener wake path also has an opt-in live sandbox test. Run it only where
the current user has a writable delegated cgroup-v2 tree with `cgroup.freeze`:

```sh
cd taema
TAEMA_LIVE_FREEZE_TEST=1 PYTHONPATH=src python -m unittest tests.test_freeze_live
```

It creates one uniquely named leaf under `user/<uid>/leftover`, runs
`python3 -m http.server` on loopback, measures ten freeze/request/thaw cycles,
and removes the leaf and server during cleanup. The ordinary `make test` suite
skips this test unless the opt-in variable is set.

The locally testable parts are covered by `tests/test_vmharness.py` in the
ordinary suite (`make test`): config validation, image/cache layout, QEMU and
overlay argv (KVM vs TCG, loopback-only forwarding), recursive/private
SSH/SCP transport argv, the rootless `mkimage.sh` script generation
(proc handled by `unshare --mount-proc`, durable service enablement, idempotent
ownership fixup), fresh-run-dir refusal, prerequisite and network refusals,
plan step ordering, side-effect-free `--dry-run`, the full `run` pipeline
against stubbed transports (per-scenario PASS/FAIL results and artifact
collection without any boot), CLI argument handling for `vmh` and
`scenario.py`, and the scenario API (spawn/close/kill trees, event waits, scope
assertions against a fake cgroup tree, log capture, privileged argv).
Everything that needs a bootable guest (image build, provisioning, live
scenarios) requires `--allow-network` and is exercised by `vmh run`.
