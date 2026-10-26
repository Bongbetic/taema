#!/usr/bin/env python3
"""taema disposable Void VM test harness (host side).

One command (`make -C taema vm-test` or `tools/vm/vmh run`) builds the package
from the working tree, boots fresh Void glibc/musl VMs with QEMU (KVM when
available), provisions them over SSH, runs scripted scenarios as a test user
and collects logs and results as artifacts.  See docs/vm-harness.md.

Stdlib only.  Exit codes: 0 ok, 1 scenario/step failure, 2 refusal (missing
prerequisites, missing opt-in for network, bad configuration).

The harness never touches the host's cgroups, services, or user state: it only
writes under its state directory (default taema/build/vm, gitignored), keeps
SSH known_hosts and QEMU serial logs inside per-run directories, and forwards
SSH on loopback only.  Base images are cached; every run boots a disposable
qcow2 overlay that is discarded afterwards (clean snapshot per run).
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11 has no tomllib
    tomllib = None

VM_DIR = os.path.dirname(os.path.abspath(__file__))
TAEMA_ROOT = os.path.dirname(os.path.dirname(VM_DIR))
REPO_ROOT = os.path.dirname(TAEMA_ROOT)
CONFIG_PATH = os.path.join(VM_DIR, "config.toml")
BUILD_XBPS = os.path.join(TAEMA_ROOT, "tools", "build-xbps.sh")
MIGRATION_FIXTURE = os.path.join(
    TAEMA_ROOT, "tests", "fixtures", "upgrade-v3", "knowledge.json"
)
LEARNING_REPLAY_FIXTURE = os.path.join(
    TAEMA_ROOT, "tests", "fixtures", "learning-v3", "replay.json"
)
GUEST_TMP = "/tmp/taema-vm"

LIBCS = ("glibc", "musl")
SCENARIOS = ("smoke", "m0", "m1", "m2", "m3", "m4", "upgrade", "remove", "graphical")
ACCELS = ("auto", "kvm", "tcg")
IMAGE_KEYS = ("dir", "tarball", "rootfs", "base", "kernel", "initrd")


class HarnessError(Exception):
    """Refusal: bad configuration, missing prerequisites, missing opt-in."""


class RunError(HarnessError):
    """A build/boot/provision/scenario step failed during an actual run."""


# ---- configuration ---------------------------------------------------------


def load_config(path=None):
    """Load and validate one harness config file (defaults live in config.toml)."""
    path = path or CONFIG_PATH
    if tomllib is None:
        raise HarnessError("python3.11+ (tomllib) is required")
    try:
        with open(path, "rb") as f:
            raw = tomllib.load(f)
    except FileNotFoundError:
        raise HarnessError("config file not found: %s" % path)
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise HarnessError("cannot read config %s: %s" % (path, e))
    cfg = _validate(raw, path)
    # Relative paths always resolve against the taema/ directory, never the cwd.
    if not os.path.isabs(cfg["paths"]["state_dir"]):
        cfg["paths"]["state_dir"] = os.path.join(TAEMA_ROOT, cfg["paths"]["state_dir"])
    return cfg


def _validate(raw, path="<config>"):
    def need(key, kind, lo=None):
        if key not in raw:
            raise HarnessError("%s: missing [%s]" % (path, key))
        val = raw[key]
        if not isinstance(val, kind) or (isinstance(val, list) and not val):
            raise HarnessError("%s: %s must be %s" % (path, key, kind.__name__))
        if lo is not None and isinstance(val, int) and val < lo:
            raise HarnessError("%s: %s must be >= %s" % (path, key, lo))
        return val

    libcs = need("libcs", list)
    for c in libcs:
        if c not in LIBCS:
            raise HarnessError(
                "%s: unknown libc %r (want %s)" % (path, c, "/".join(LIBCS))
            )
    scenarios = need("scenarios", list)
    for s in scenarios:
        if s not in SCENARIOS:
            raise HarnessError(
                "%s: unknown scenario %r (want %s)" % (path, s, "/".join(SCENARIOS))
            )
    if raw.get("accel", "auto") not in ACCELS:
        raise HarnessError("%s: unknown accel %r" % (path, raw.get("accel")))
    need("memory_mb", int, 512)
    need("cpus", int, 1)
    need("boot_timeout_s", int, 1)
    need("scenario_timeout_s", int, 1)
    user = need("test_user", str)
    if not re.fullmatch(r"[a-z_][a-z0-9_-]*", user) or len(user) > 32:
        raise HarnessError("%s: invalid test_user %r" % (path, user))

    paths = raw.get("paths")
    if not isinstance(paths, dict):
        raise HarnessError("%s: missing [paths]" % path)
    for key in ("state_dir", "package_repo"):
        if not isinstance(paths.get(key), str) or not paths[key]:
            raise HarnessError("%s: paths.%s must be a non-empty string" % (path, key))

    tools = raw.get("tools")
    if not isinstance(tools, dict) or not tools:
        raise HarnessError("%s: missing [tools]" % path)
    for key, val in tools.items():
        if not isinstance(val, str) or not val:
            raise HarnessError("%s: tools.%s must be a non-empty string" % (path, key))

    images = raw.get("images")
    if not isinstance(images, dict):
        raise HarnessError("%s: missing [images]" % path)
    for key in ("base_url", "previous_url"):
        url = images.get(key)
        if not isinstance(url, str) or not url.startswith(("http://", "https://")):
            raise HarnessError("%s: images.%s must be an http(s) url" % (path, key))
    previous_ref = images.get("previous_ref")
    if previous_ref is not None and (
        not isinstance(previous_ref, str)
        or not re.fullmatch(r"[A-Za-z0-9._/-]+", previous_ref)
        or previous_ref.startswith("-")
    ):
        raise HarnessError("%s: images.previous_ref must be a safe ref name" % path)
    for libc in libcs:
        entry = images.get(libc)
        if not isinstance(entry, dict):
            raise HarnessError("%s: missing [images.%s]" % (path, libc))
        if not isinstance(entry.get("tarball"), str) or not entry["tarball"]:
            raise HarnessError("%s: images.%s.tarball missing" % (path, libc))
        sha = entry.get("sha256")
        if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha or ""):
            raise HarnessError(
                "%s: images.%s.sha256 must be a 64-char hex digest" % (path, libc)
            )
    return raw


def with_overrides(
    cfg, state_dir=None, libcs=None, scenarios=None, accel=None, memory_mb=None
):
    """A validated copy of cfg with CLI overrides applied."""
    new = dict(cfg)
    new["paths"] = dict(cfg["paths"])
    new["images"] = dict(cfg["images"])
    if state_dir:
        if not os.path.isabs(state_dir):
            state_dir = os.path.join(TAEMA_ROOT, state_dir)
        new["paths"]["state_dir"] = state_dir
    if libcs:
        new["libcs"] = list(libcs)
    if scenarios:
        new["scenarios"] = list(scenarios)
    if accel:
        new["accel"] = accel
    if memory_mb is not None:
        new["memory_mb"] = memory_mb
    return _validate(new, "<cli>")


def parse_libcs(text):
    return [c.strip() for c in text.split(",") if c.strip()]


def parse_scenarios(text):
    names = [s.strip() for s in text.split(",") if s.strip()]
    if names == ["all"]:
        return list(SCENARIOS)
    return names


def state_dir(cfg):
    return cfg["paths"]["state_dir"]


def image_spec(cfg, libc):
    entry = cfg["images"][libc]
    return {
        "tarball": entry["tarball"],
        "sha256": entry["sha256"],
        "url": cfg["images"]["base_url"].rstrip("/") + "/" + entry["tarball"],
    }


def cache_paths(cfg, libc):
    d = os.path.join(state_dir(cfg), "images", libc)
    tarball = cfg["images"][libc]["tarball"]
    return {
        "dir": d,
        "tarball": os.path.join(d, tarball),
        "rootfs": os.path.join(d, "rootfs"),
        "base": os.path.join(d, "base.qcow2"),
        "kernel": os.path.join(d, "vmlinuz"),
        "initrd": os.path.join(d, "initramfs.img"),
    }


def ssh_key_paths(cfg):
    d = os.path.join(state_dir(cfg), "images")
    return os.path.join(d, "id_ed25519"), os.path.join(d, "id_ed25519.pub")


def previous_pkg_path(cfg):
    return os.path.join(
        state_dir(cfg),
        "pkg",
        "previous",
        os.path.basename(cfg["images"]["previous_url"]),
    )


def read_version(root=TAEMA_ROOT):
    path = os.path.join(root, "src", "taema", "__init__.py")
    try:
        with open(path) as f:
            m = re.search(r'__version__ = "(.*)"', f.read())
    except OSError as e:
        raise HarnessError("cannot read version: %s" % e)
    if not m:
        raise HarnessError("__version__ not found in %s" % path)
    return m.group(1)


def package_repo_dir(cfg):
    """Absolute path of the local xbps repository the package builds into."""
    repo = cfg["paths"]["package_repo"]
    if not os.path.isabs(repo):
        repo = os.path.join(TAEMA_ROOT, repo)
    return repo


def package_path(cfg):
    return os.path.join(
        package_repo_dir(cfg), "taema-%s_1.noarch.xbps" % read_version()
    )


def previous_version(cfg):
    m = re.match(
        r"taema-(.+?)(?:_\d+)?\.noarch\.xbps$",
        os.path.basename(cfg["images"]["previous_url"]),
    )
    if not m:
        raise HarnessError(
            "cannot derive previous version from %s" % cfg["images"]["previous_url"]
        )
    return m.group(1)


def needs_previous_package(scenarios):
    """Whether selected VM scenarios install the prior release."""
    return any(name in scenarios for name in ("m1", "upgrade"))


def bootstrap_sources(pub, package_repo, previous, scenarios):
    """Files copied to a guest before provisioning and scenario execution."""
    sources = [
        os.path.join(VM_DIR, "provision.sh"),
        os.path.join(VM_DIR, "scenario.py"),
        pub,
        package_repo,
    ]
    if needs_previous_package(scenarios):
        sources.append(previous)
    if "m1" in scenarios:
        sources.append(MIGRATION_FIXTURE)
    if "m2" in scenarios:
        sources.append(LEARNING_REPLAY_FIXTURE)
    if "m3" in scenarios:
        sources.extend(
            [os.path.join(TAEMA_ROOT, "tests"), os.path.join(TAEMA_ROOT, "schema")]
        )
    return sources


def scenario_command(name, cfg, repo_name, previous):
    """Build the guest command and inputs for one selected scenario."""
    remote = "python3 %s/scenario.py %s --artifacts %s/artifacts" % (
        GUEST_TMP,
        name,
        GUEST_TMP,
    )
    if name in ("upgrade", "m1"):
        remote += (
            " --package-dir %s/%s --previous %s/%s"
            " --previous-version %s --current-version %s"
            % (
                GUEST_TMP,
                repo_name,
                GUEST_TMP,
                os.path.basename(previous),
                previous_version(cfg),
                read_version(),
            )
        )
    if name == "m1":
        remote += " --migration-fixture %s/%s" % (
            GUEST_TMP,
            os.path.basename(MIGRATION_FIXTURE),
        )
    elif name == "m2":
        remote += " --replay-fixture %s/%s" % (
            GUEST_TMP,
            os.path.basename(LEARNING_REPLAY_FIXTURE),
        )
    return remote


# ---- prerequisites and acceleration ---------------------------------------


def _tool_ok(tool):
    if "/" in tool:
        return os.path.isfile(tool) and os.access(tool, os.X_OK)
    return shutil.which(tool) is not None


def doctor(cfg, tools=None):
    """Missing tool values (as configured) for the requested tool keys."""
    names = list(tools) if tools is not None else sorted(cfg["tools"])
    return [cfg["tools"][t] for t in names if not _tool_ok(cfg["tools"][t])]


def kvm_available():
    return os.access("/dev/kvm", os.R_OK | os.W_OK)


def resolve_accel(cfg):
    accel = cfg.get("accel", "auto")
    if accel == "tcg":
        return "tcg"
    if accel == "kvm":
        if not kvm_available():
            raise HarnessError("accel=kvm requested but /dev/kvm is not usable")
        return "kvm"
    return "kvm" if kvm_available() else "tcg"


def free_port():
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def create_run_dir(cfg, libc, name=None):
    runs = os.path.join(state_dir(cfg), "runs")
    name = name or "%s-%d-%s" % (
        time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()),
        os.getpid(),
        libc,
    )
    path = os.path.join(runs, name)
    if os.path.exists(path):
        raise HarnessError("run dir exists: %s (refusing to reuse a snapshot)" % path)
    os.makedirs(path)
    return path


# ---- command builders ------------------------------------------------------


def qemu_argv(cfg, libc, *, kvm, port, run_dir):
    cp = cache_paths(cfg, libc)
    accel = (
        ["-accel", "kvm", "-cpu", "host"]
        if kvm
        else ["-accel", "tcg", "-cpu", "qemu64"]
    )
    return (
        [
            cfg["tools"]["qemu"],
            "-name",
            "taema-vm-" + os.path.basename(run_dir),
            "-m",
            str(cfg["memory_mb"]),
            "-smp",
            str(cfg["cpus"]),
        ]
        + accel
        + [
            "-kernel",
            cp["kernel"],
            "-initrd",
            cp["initrd"],
            "-append",
            "root=/dev/vda rw console=ttyS0,115200 loglevel=3",
            "-drive",
            "file=%s,if=virtio,format=qcow2" % os.path.join(run_dir, "disk.qcow2"),
            "-nic",
            "user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:%d-:22" % port,
            "-serial",
            "file:" + os.path.join(run_dir, "serial.log"),
            "-display",
            "none",
            "-monitor",
            "none",
            "-pidfile",
            os.path.join(run_dir, "qemu.pid"),
            "-no-reboot",
        ]
    )


def overlay_argv(base, overlay, qemu_img="qemu-img"):
    return [qemu_img, "create", "-f", "qcow2", "-b", base, "-F", "qcow2", overlay]


def ssh_argv(cfg, port, key, known_hosts, user, remote=None):
    argv = [
        cfg["tools"]["ssh"],
        "-i",
        key,
        "-p",
        str(port),
        "-o",
        "UserKnownHostsFile=" + known_hosts,
        "-o",
        "GlobalKnownHostsFile=/dev/null",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        "BatchMode=yes",
        "-o",
        "LogLevel=ERROR",
        "-o",
        "ConnectTimeout=5",
        "%s@127.0.0.1" % user,
    ]
    if remote is not None:
        argv.append(remote)
    return argv


def scp_argv(cfg, port, key, known_hosts, sources, dest):
    return (
        [
            cfg["tools"]["scp"],
            "-r",
            "-i",
            key,
            "-P",
            str(port),
            "-o",
            "UserKnownHostsFile=" + known_hosts,
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "BatchMode=yes",
            "-o",
            "LogLevel=ERROR",
            "-o",
            "ConnectTimeout=5",
        ]
        + list(sources)
        + [dest]
    )


def mkimage_argv(cfg, rootfs, pub):
    """argv to configure an extracted rootfs, confined to a user namespace.

    A user namespace may only mount procfs when it also owns a PID namespace
    (kernel rule), so unshare creates the PID namespace and mounts proc at
    <rootfs>/proc before mkimage.sh runs; the script itself never mounts /proc.
    """
    return [
        cfg["tools"]["unshare"],
        "-rmfp",
        "--mount-proc=" + os.path.join(rootfs, "proc"),
        "sh",
        os.path.join(VM_DIR, "mkimage.sh"),
        rootfs,
        pub,
    ]


# ---- plan ------------------------------------------------------------------


def build_plan(cfg, *, libcs=None, scenarios=None, kvm=None):
    """A machine-readable description of everything `run` would do."""
    libcs = list(libcs or cfg["libcs"])
    scenarios = list(scenarios or cfg["scenarios"])
    if kvm is None:
        accel = resolve_accel(cfg)
        kvm = accel == "kvm"
    else:
        accel = "kvm" if kvm else "tcg"

    key, pub = ssh_key_paths(cfg)
    vmadmin = "vmadmin"
    repo_name = os.path.basename(cfg["paths"]["package_repo"].rstrip("/"))
    pkg = package_path(cfg)
    prev = previous_pkg_path(cfg)
    network_urls = [image_spec(cfg, c)["url"] for c in libcs]
    if (
        needs_previous_package(scenarios)
        and not os.path.isfile(prev)
        and not previous_source_available(cfg)
    ):
        network_urls.append(cfg["images"]["previous_url"])

    sources = bootstrap_sources(pub, package_repo_dir(cfg), prev, scenarios)

    vms = []
    for libc in libcs:
        run_dir = os.path.join(state_dir(cfg), "runs", "RUN-" + libc)
        port = free_port()
        known = os.path.join(run_dir, "known_hosts")
        qemu = qemu_argv(cfg, libc, kvm=kvm, port=port, run_dir=run_dir)
        steps = [
            {"name": "wait-ssh", "user": vmadmin},
            {
                "name": "mkdir-bootstrap",
                "argv": ssh_argv(
                    cfg,
                    port,
                    key,
                    known,
                    vmadmin,
                    "mkdir -p %s" % GUEST_TMP,
                ),
            },
            {
                "name": "scp-bootstrap",
                "argv": scp_argv(
                    cfg,
                    port,
                    key,
                    known,
                    sources,
                    vmadmin + "@127.0.0.1:" + GUEST_TMP + "/",
                ),
            },
            {
                "name": "provision",
                "argv": ssh_argv(
                    cfg,
                    port,
                    key,
                    known,
                    vmadmin,
                    "sudo -n sh %s/provision.sh --package-dir %s/%s --user %s"
                    " --authorized-key %s/%s"
                    % (
                        GUEST_TMP,
                        GUEST_TMP,
                        repo_name,
                        cfg["test_user"],
                        GUEST_TMP,
                        os.path.basename(pub),
                    ),
                ),
            },
        ]
        for s in scenarios:
            remote = scenario_command(s, cfg, repo_name, prev)
            steps.append(
                {
                    "name": "scenario:" + s,
                    "argv": ssh_argv(cfg, port, key, known, cfg["test_user"], remote),
                }
            )
        steps.append(
            {
                "name": "collect",
                "argv": scp_argv(
                    cfg,
                    port,
                    key,
                    known,
                    [vmadmin + "@127.0.0.1:%s/artifacts/" % GUEST_TMP],
                    os.path.join(run_dir, "artifacts") + "/",
                ),
            }
        )
        steps.append({"name": "teardown"})
        vms.append(
            {
                "libc": libc,
                "run_dir": run_dir,
                "port": port,
                "key": key,
                "pub": pub,
                "qemu": qemu,
                "steps": steps,
            }
        )

    return {
        "accel": accel,
        "kvm": kvm,
        "scenarios": scenarios,
        "libcs": libcs,
        "package": {"path": pkg, "argv": ["sh", BUILD_XBPS, package_repo_dir(cfg)]},
        "network": {"urls": network_urls},
        "vms": vms,
    }


def print_plan(plan, out):
    out.write("package: %s\n" % plan["package"]["path"])
    out.write("build: %s\n" % " ".join(plan["package"]["argv"]))
    for url in plan["network"]["urls"]:
        out.write("network: %s\n" % url)
    for vm in plan["vms"]:
        out.write(
            "VM %s accel=%s port=%d run=%s\n"
            % (vm["libc"], plan["accel"], vm["port"], vm["run_dir"])
        )
        out.write("  qemu: %s\n" % " ".join(vm["qemu"]))
        for step in vm["steps"]:
            line = "  step: %s" % step["name"]
            if step.get("argv"):
                line += " :: " + " ".join(step["argv"])
            elif step.get("remote"):
                line += " :: " + step["remote"]
            out.write(line + "\n")


# ---- network (opt-in) ------------------------------------------------------


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _download(url, dest, sha256=None):
    tmp = dest + ".part"
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    try:
        with urllib.request.urlopen(url, timeout=60) as resp, open(tmp, "wb") as f:
            shutil.copyfileobj(resp, f)
        if sha256:
            got = _sha256(tmp)
            if got != sha256:
                raise HarnessError("sha256 mismatch for %s (got %s)" % (url, got))
        os.replace(tmp, dest)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def fetch_image(cfg, libc, allow_network=False):
    """Download and verify one base tarball; refused without --allow-network."""
    if not allow_network:
        raise HarnessError(
            "base image %s is not cached; re-run with --allow-network" % libc
        )
    spec = image_spec(cfg, libc)
    cp = cache_paths(cfg, libc)
    if os.path.isfile(cp["tarball"]) and _sha256(cp["tarball"]) == spec["sha256"]:
        return cp["tarball"]
    _download(spec["url"], cp["tarball"], spec["sha256"])
    return cp["tarball"]


def previous_source_available(cfg):
    """Whether the configured previous release source ref exists locally."""
    ref = cfg["images"].get("previous_ref")
    if not ref:
        return False
    try:
        result = subprocess.run(
            [
                cfg["tools"].get("git", "git"),
                "rev-parse",
                "--verify",
                ref + "^{commit}",
            ],
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
    except OSError:
        return False
    return result.returncode == 0


def build_previous_package(cfg, dest=None):
    """Build the previous package from a checked-out source tag into the cache."""
    ref = cfg["images"].get("previous_ref")
    if not ref or not previous_source_available(cfg):
        raise HarnessError("previous source ref is not available locally")
    dest = dest or previous_pkg_path(cfg)
    os.makedirs(state_dir(cfg), exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="taema-previous-", dir=state_dir(cfg)
    ) as temporary:
        archive = os.path.join(temporary, "source.tar")
        git = cfg["tools"].get("git", "git")
        exported = subprocess.run(
            [git, "archive", "--format=tar", "--output", archive, "--", ref],
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if exported.returncode:
            raise HarnessError(
                "cannot archive previous source %s: %s"
                % (ref, (exported.stderr or exported.stdout).strip()[-1000:])
            )
        extracted = subprocess.run(
            [cfg["tools"]["tar"], "-xf", archive, "-C", temporary],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if extracted.returncode:
            raise HarnessError(
                "cannot extract previous source %s: %s"
                % (ref, (extracted.stderr or extracted.stdout).strip()[-1000:])
            )
        old_root = os.path.join(temporary, "taema")
        repository = os.path.join(temporary, "repo")
        built = subprocess.run(
            ["sh", os.path.join(old_root, "tools", "build-xbps.sh"), repository],
            cwd=old_root,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=1800,
            check=False,
        )
        if built.returncode:
            raise HarnessError(
                "cannot build previous package from %s: %s"
                % (ref, (built.stdout or "build exited %d" % built.returncode)[-2000:])
            )
        package = os.path.join(repository, os.path.basename(dest))
        if not os.path.isfile(package):
            raise HarnessError(
                "previous source %s did not build %s" % (ref, os.path.basename(dest))
            )
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.copy2(package, dest)
    return dest


def fetch_previous(cfg, allow_network=False):
    dest = previous_pkg_path(cfg)
    if os.path.isfile(dest):
        return dest
    if previous_source_available(cfg):
        return build_previous_package(cfg, dest)
    if not allow_network:
        raise HarnessError(
            "previous release package and source tag are not cached; "
            "re-run with --allow-network"
        )
    _download(cfg["images"]["previous_url"], dest)
    return dest


# ---- image build -----------------------------------------------------------


def find_rootfs(extract_dir):
    if os.path.isdir(os.path.join(extract_dir, "etc")):
        return extract_dir
    kids = [
        k
        for k in os.listdir(extract_dir)
        if os.path.isdir(os.path.join(extract_dir, k))
    ]
    if len(kids) == 1 and os.path.isdir(os.path.join(extract_dir, kids[0], "etc")):
        return os.path.join(extract_dir, kids[0])
    raise HarnessError("extracted tarball has no etc/ under %s" % extract_dir)


def build_image(cfg, libc, log=None):
    """Build a bootable base qcow2 (with sshd/dhcpcd and a key-login admin)
    from the cached Void rootfs tarball.  Everything unprivileged runs confined
    under `unshare -rm`; the disk image is assembled with mke2fs -d (no root,
    no loop devices, no host mounts)."""
    log = log or (lambda msg: None)
    cp = cache_paths(cfg, libc)
    if os.path.isfile(cp["base"]):
        return cp["base"]
    if not os.path.isfile(cp["tarball"]):
        raise HarnessError("tarball for %s missing; fetch first" % libc)
    _pub = os.path.join(cp["dir"], "..", "id_ed25519.pub")
    _key, pub = ssh_key_paths(cfg)
    if not os.path.isfile(pub):
        raise HarnessError("ssh key missing; fetch first")

    extract = cp["rootfs"] + ".tmp"
    if os.path.exists(extract):
        shutil.rmtree(extract)
    os.makedirs(extract)
    log("extracting %s" % os.path.basename(cp["tarball"]))
    # --no-same-owner: we are unprivileged; device nodes (dev/) are excluded
    # because they cannot be created without root (runits devtmpfs recreates
    # them at boot).  -p keeps setuid bits (sudo) intact.
    cmd = [
        cfg["tools"]["tar"],
        "-xJpf",
        cp["tarball"],
        "-C",
        extract,
        "--no-same-owner",
        "--exclude=./dev",
        "--exclude=dev",
    ]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RunError("extract failed: %s" % r.stderr[-800:])
    rootfs = find_rootfs(extract)
    if os.path.exists(cp["rootfs"]):
        shutil.rmtree(cp["rootfs"])
    os.replace(extract, cp["rootfs"])
    rootfs = cp["rootfs"]

    log("configuring rootfs in a user namespace")
    os.makedirs(os.path.join(rootfs, "proc"), exist_ok=True)
    r = subprocess.run(mkimage_argv(cfg, rootfs, pub), capture_output=True, text=True)
    if r.returncode != 0:
        raise RunError("mkimage failed: %s\n%s" % (r.stdout[-800:], r.stderr[-800:]))

    raw = cp["base"] + ".raw"
    if os.path.exists(raw):
        os.unlink(raw)
    size = int(cfg.get("image_size_mb", 4096))
    with open(raw, "wb") as f:
        f.truncate(size * 1024 * 1024)
    log("creating ext4 filesystem (mke2fs -d)")
    r = subprocess.run(
        [cfg["tools"]["mke2fs"], "-F", "-q", "-t", "ext4", "-d", rootfs, raw],
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        raise RunError("mke2fs failed: %s" % r.stderr[-800:])

    # Keep kernel and initramfs on the host side for direct -kernel boot.
    boot = [
        f for f in os.listdir(os.path.join(rootfs, "boot")) if f.startswith("vmlinuz")
    ]
    initrd = [
        f for f in os.listdir(os.path.join(rootfs, "boot")) if f.startswith("initramfs")
    ]
    if not boot or not initrd:
        raise RunError("no kernel/initramfs in the image boot directory")
    shutil.copy2(os.path.join(rootfs, "boot", sorted(boot)[-1]), cp["kernel"])
    shutil.copy2(os.path.join(rootfs, "boot", sorted(initrd)[-1]), cp["initrd"])

    log("converting to qcow2")
    tmp = cp["base"] + ".building"
    if os.path.exists(tmp):
        os.unlink(tmp)
    r = subprocess.run(
        [cfg["tools"]["qemu_img"], "convert", "-f", "raw", "-O", "qcow2", raw, tmp],
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        raise RunError("qemu-img convert failed: %s" % r.stderr[-800:])
    os.replace(tmp, cp["base"])
    os.unlink(raw)
    log("base image ready: %s" % cp["base"])
    return cp["base"]


# ---- package build ---------------------------------------------------------


def build_package(cfg):
    r = subprocess.run(
        ["sh", BUILD_XBPS, package_repo_dir(cfg)],
        cwd=TAEMA_ROOT,
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        raise RunError(
            "package build failed:\n%s\n%s" % (r.stdout[-1200:], r.stderr[-1200:])
        )
    pkg = package_path(cfg)
    if not os.path.isfile(pkg):
        raise RunError("package build produced no %s" % pkg)
    return pkg


# ---- run pipeline ----------------------------------------------------------


def ensure_ssh_key(cfg):
    key, pub = ssh_key_paths(cfg)
    if os.path.isfile(key) and os.path.isfile(pub):
        return key, pub
    os.makedirs(os.path.dirname(key), exist_ok=True)
    r = subprocess.run(
        [
            cfg["tools"]["ssh_keygen"],
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "taema-vm",
            "-f",
            key,
        ],
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        raise RunError("ssh-keygen failed: %s" % r.stderr[-400:])
    os.chmod(key, 0o600)
    return key, pub


def wait_ssh(cfg, port, key, known, user, timeout, qemu, serial):
    deadline = time.monotonic() + timeout
    probe = ssh_argv(cfg, port, key, known, user, "true")
    while time.monotonic() < deadline:
        if qemu.poll() is not None:
            tail = _tail(serial)
            raise RunError(
                "qemu exited before ssh was ready (rc=%s)\nserial tail:\n%s"
                % (qemu.returncode, tail)
            )
        try:
            r = subprocess.run(probe, capture_output=True, text=True, timeout=15)
        except subprocess.TimeoutExpired:
            r = None
        if r is not None and r.returncode == 0:
            return
        time.sleep(2)
    raise RunError(
        "ssh not ready within %ss\nserial tail:\n%s" % (timeout, _tail(serial))
    )


def _tail(path, n=40):
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return "(no serial log)"
    return "\n".join(data.decode("utf-8", "replace").splitlines()[-n:])


def _log_file(run_dir, name):
    d = os.path.join(run_dir, "logs")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, name + ".log")


def run_step(name, argv, run_dir, timeout=None):
    """Execute one harness step; output goes to the run's log directory."""
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise RunError("step %s timed out after %ss" % (name, e.timeout))
    with open(_log_file(run_dir, name), "w") as f:
        f.write("$ %s\n%s\n%s" % (" ".join(argv), r.stdout, r.stderr))
    if r.returncode != 0:
        raise RunError(
            "step %s failed (rc=%d); see %s\n%s"
            % (
                name,
                r.returncode,
                _log_file(run_dir, name),
                (r.stdout + r.stderr)[-600:],
            )
        )
    return r


def stop_qemu(proc, timeout=20):
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass


def run_vm(cfg, plan_vm, plan, scenarios, run_dir, out, err):
    """Boot one VM, provision it, run scenarios, collect artifacts."""
    libc = plan_vm["libc"]
    key = plan_vm["key"]
    pub = plan_vm["pub"]
    port = free_port()  # plan port is a preview; pick again for the real run
    known = os.path.join(run_dir, "known_hosts")
    run_dir_abs = run_dir
    qemu = qemu_argv(cfg, libc, kvm=plan["kvm"], port=port, run_dir=run_dir_abs)
    overlay = os.path.join(run_dir, "disk.qcow2")
    ovr = overlay_argv(
        cache_paths(cfg, libc)["base"], overlay, qemu_img=cfg["tools"]["qemu_img"]
    )
    r = subprocess.run(ovr, capture_output=True, text=True)
    if r.returncode != 0:
        raise RunError("overlay creation failed: %s" % r.stderr[-400:])

    admin = "vmadmin"
    user = cfg["test_user"]
    repo_name = os.path.basename(cfg["paths"]["package_repo"].rstrip("/"))
    pkg_src = package_repo_dir(cfg)
    prev = previous_pkg_path(cfg)

    err.write(
        "vmh: booting %s VM (accel=%s, port=%d, run=%s)\n"
        % (libc, plan["accel"], port, run_dir)
    )
    with open(os.path.join(run_dir, "qemu.log"), "w") as qlog:
        proc = subprocess.Popen(qemu, stdout=qlog, stderr=subprocess.STDOUT)
    try:
        wait_ssh(
            cfg,
            port,
            key,
            known,
            admin,
            cfg["boot_timeout_s"],
            proc,
            os.path.join(run_dir, "serial.log"),
        )
        run_step(
            "mkdir-bootstrap",
            ssh_argv(cfg, port, key, known, admin, "mkdir -p %s" % GUEST_TMP),
            run_dir,
        )
        sources = bootstrap_sources(pub, pkg_src, prev, scenarios)
        run_step(
            "scp-bootstrap",
            scp_argv(
                cfg, port, key, known, sources, admin + "@127.0.0.1:" + GUEST_TMP + "/"
            ),
            run_dir,
            timeout=300,
        )
        run_step(
            "provision",
            ssh_argv(
                cfg,
                port,
                key,
                known,
                admin,
                "sudo -n sh %s/provision.sh --package-dir %s/%s --user %s"
                " --authorized-key %s/%s"
                % (
                    GUEST_TMP,
                    GUEST_TMP,
                    repo_name,
                    user,
                    GUEST_TMP,
                    os.path.basename(pub),
                ),
            ),
            run_dir,
            timeout=300,
        )
        results = {}
        for s in scenarios:
            remote = scenario_command(s, cfg, repo_name, prev)
            try:
                run_step(
                    "scenario-" + s,
                    ssh_argv(cfg, port, key, known, user, remote),
                    run_dir,
                    timeout=cfg["scenario_timeout_s"],
                )
                results[s] = "PASS"
            except RunError as e:
                # A failed scenario is a result, not a pipeline abort: record
                # it, keep going, and still collect the artifacts below.
                results[s] = "FAIL"
                err.write("vmh: %s scenario %s failed: %s\n" % (libc, s, e))
            out.write("vmh: %s %s: %s\n" % (libc, s, results[s]))
        # collect guest artifacts even when a scenario failed
        dest = os.path.join(run_dir, "artifacts")
        os.makedirs(dest, exist_ok=True)
        try:
            run_step(
                "collect",
                scp_argv(
                    cfg,
                    port,
                    key,
                    known,
                    [admin + "@127.0.0.1:%s/artifacts/" % GUEST_TMP],
                    dest + "/",
                ),
                run_dir,
                timeout=120,
            )
        except RunError as e:
            err.write("vmh: collect failed (continuing to teardown): %s\n" % e)
        return results
    finally:
        stop_qemu(proc)
        if not plan.get("keep_run") and os.path.exists(overlay):
            try:
                os.unlink(overlay)
            except OSError:
                pass


def cmd_run(cfg, args, out, err):
    libcs = cfg["libcs"]
    scenarios = cfg["scenarios"]
    plan = build_plan(
        cfg, libcs=libcs, scenarios=scenarios, kvm=(False if args.tcg else None)
    )

    missing = doctor(cfg)
    if missing:
        for m in missing:
            err.write("vmh: missing required tool: %s\n" % m)
        return 2

    if args.dry_run:
        print_plan(plan, out)
        out.write("prerequisites: ok\n")
        return 0

    # Network opt-in gate happens before anything is created or executed.
    need_net = []
    for libc in libcs:
        if not os.path.isfile(cache_paths(cfg, libc)["base"]):
            need_net.append("base image for " + libc)
    if (
        needs_previous_package(scenarios)
        and not os.path.isfile(previous_pkg_path(cfg))
        and not previous_source_available(cfg)
    ):
        need_net.append("previous release package or source tag")
    if need_net and not args.allow_network:
        raise HarnessError(
            "not cached: %s; re-run with --allow-network" % ", ".join(need_net)
        )

    ensure_ssh_key(cfg)
    if args.allow_network:
        for libc in libcs:
            if not os.path.isfile(cache_paths(cfg, libc)["base"]):
                fetch_image(cfg, libc, allow_network=True)
                build_image(cfg, libc, log=lambda m: err.write("vmh: %s\n" % m))
    if needs_previous_package(scenarios) and not os.path.isfile(previous_pkg_path(cfg)):
        fetch_previous(cfg, allow_network=args.allow_network)
    else:
        for libc in libcs:
            if not os.path.isfile(cache_paths(cfg, libc)["base"]):
                raise HarnessError("base image for %s missing" % libc)

    if args.no_build:
        if not os.path.isfile(package_path(cfg)):
            raise HarnessError(
                "package not built: %s (run without --no-build)" % package_path(cfg)
            )
    else:
        err.write("vmh: building package from the working tree\n")
        build_package(cfg)

    summary = {"accel": plan["accel"], "scenarios": scenarios, "vms": {}}
    failed = False
    for libc in libcs:
        run_dir = create_run_dir(cfg, libc)
        (summary["vms"].setdefault(libc, {})).update(
            {"run_dir": run_dir, "scenarios": {}}
        )
        try:
            vm_plan = next(v for v in plan["vms"] if v["libc"] == libc)
            vm_plan["keep_run"] = args.keep_run
            results = run_vm(cfg, vm_plan, plan, scenarios, run_dir, out, err)
            summary["vms"][libc]["scenarios"] = results
            if any(v != "PASS" for v in results.values()):
                failed = True
        except RunError as e:
            failed = True
            summary["vms"][libc]["error"] = str(e)
            err.write("vmh: %s FAILED: %s\n" % (libc, e))
        finally:
            with open(os.path.join(run_dir, "summary.json"), "w") as f:
                json.dump(summary, f, indent=2, sort_keys=True)
            err.write("vmh: artifacts: %s\n" % run_dir)

    return 1 if failed else 0


# ---- entry points ----------------------------------------------------------


def cmd_doctor(cfg, out, err):
    missing = doctor(cfg)
    if missing:
        for m in missing:
            err.write("vmh: missing required tool: %s\n" % m)
        return 2
    out.write(
        "vmh: all tools present (kvm=%s)\n" % ("yes" if kvm_available() else "no")
    )
    return 0


def cmd_fetch(cfg, args, out, err):
    for libc in cfg["libcs"]:
        path = fetch_image(cfg, libc, allow_network=args.allow_network)
        out.write("vmh: image %s ok: %s\n" % (libc, path))
    if needs_previous_package(cfg["scenarios"]):
        out.write(
            "vmh: previous release ok: %s\n"
            % fetch_previous(cfg, allow_network=args.allow_network)
        )
    return 0


def cmd_build(cfg, out, err):
    missing = doctor(cfg, tools=["make", "xbps_create", "xbps_rindex"])
    if missing:
        for m in missing:
            err.write("vmh: missing required tool: %s\n" % m)
        return 2
    out.write("vmh: package: %s\n" % build_package(cfg))
    return 0


def main(argv, out=None, err=None):
    out = out or sys.stdout
    err = err or sys.stderr
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--config", help="harness config file (default: tools/vm/config.toml)"
    )
    common.add_argument("--state-dir", help="override paths.state_dir")
    net = argparse.ArgumentParser(add_help=False)
    net.add_argument(
        "--allow-network",
        action="store_true",
        help="permit downloads (base images, previous release)",
    )
    runp = argparse.ArgumentParser(add_help=False)
    runp.add_argument(
        "--libc", help="comma-separated libcs to boot (default from config)"
    )
    runp.add_argument(
        "--scenarios",
        help="comma-separated: smoke,m0,m1,m2,m3,m4,upgrade,remove or all",
    )
    runp.add_argument("--memory-mb", type=int, help="guest RAM in MiB (minimum 512)")
    runp.add_argument("--tcg", action="store_true", help="force TCG emulation")
    runp.add_argument("--dry-run", action="store_true", help="print the plan and exit")
    runp.add_argument(
        "--no-build",
        action="store_true",
        help="reuse the package already in the package repo",
    )
    runp.add_argument(
        "--keep-run",
        action="store_true",
        help="keep the run's disk overlay for debugging",
    )

    parser = argparse.ArgumentParser(
        prog="vmh", description="disposable Void VM test harness for taema"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("doctor", parents=[common], help="check prerequisites")
    sub.add_parser("fetch", parents=[common, net], help="download cached base images")
    sub.add_parser(
        "build", parents=[common], help="build the .xbps from the working tree"
    )
    sub.add_parser(
        "run",
        parents=[common, net, runp],
        help="build, boot, provision, and run scenarios",
    )
    args = parser.parse_args(argv)

    try:
        cfg = load_config(args.config)
        cfg = with_overrides(
            cfg,
            state_dir=getattr(args, "state_dir", None),
            libcs=parse_libcs(args.libc) if getattr(args, "libc", None) else None,
            scenarios=parse_scenarios(args.scenarios)
            if getattr(args, "scenarios", None)
            else None,
            accel="tcg" if getattr(args, "tcg", False) else None,
            memory_mb=getattr(args, "memory_mb", None),
        )
        if args.cmd == "doctor":
            return cmd_doctor(cfg, out, err)
        if args.cmd == "fetch":
            return cmd_fetch(cfg, args, out, err)
        if args.cmd == "build":
            return cmd_build(cfg, out, err)
        return cmd_run(cfg, args, out, err)
    except RunError as e:
        err.write("vmh: %s\n" % e)
        return 1
    except HarnessError as e:
        err.write("vmh: %s\n" % e)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
