"""Disposable Void VM harness: config, plans, refusals, and the guest scenario API."""

import contextlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(ROOT)
VM_DIR = os.path.join(ROOT, "tools", "vm")


def read_text(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def load(name):
    path = os.path.join(VM_DIR, name + ".py")
    spec = importlib.util.spec_from_file_location("taema_vm_" + name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


vmh = load("vmh")
scenario = load("scenario")

ALL_TOOLS = sorted(
    {
        "qemu",
        "qemu_img",
        "ssh",
        "scp",
        "ssh_keygen",
        "mke2fs",
        "make",
        "git",
        "xbps_create",
        "xbps_rindex",
        "tar",
        "unshare",
    }
)
TOOL_NAMES = {
    "qemu": "qemu-system-x86_64",
    "qemu_img": "qemu-img",
    "xbps_create": "xbps-create",
    "xbps_rindex": "xbps-rindex",
}


def stub_tools(bindir, skip=()):
    """Create exit-0 stubs for every configured tool; returns the tools dict for config."""
    os.makedirs(bindir, exist_ok=True)
    tools = {}
    for key in ALL_TOOLS:
        name = TOOL_NAMES.get(key, key)
        path = os.path.join(bindir, name)
        if key in skip:
            tools[key] = os.path.join(bindir, "missing-" + name)
            continue
        if not os.path.exists(path):
            with open(path, "w") as f:
                f.write("#!/bin/sh\nexit 0\n")
            os.chmod(path, 0o755)
        tools[key] = path
    return tools


class VmTestCase(unittest.TestCase):
    """Shared temp state + a hermetic config whose tools are stubs in a temp dir."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.state = os.path.join(self.tmp, "state")
        self.bindir = os.path.join(self.tmp, "bin")
        self.tools = stub_tools(self.bindir)
        self.cfg_path = os.path.join(self.tmp, "config.toml")

    def write_config(
        self, libcs=None, scenarios=None, glibc_sha=None, package_repo="build/repo"
    ):
        lines = [
            "libcs = [%s]"
            % ", ".join('"%s"' % c for c in (libcs or ["glibc", "musl"])),
            "scenarios = [%s]"
            % ", ".join('"%s"' % s for s in (scenarios or ["smoke"])),
            'accel = "auto"',
            "memory_mb = 1024",
            "cpus = 1",
            "boot_timeout_s = 5",
            "scenario_timeout_s = 5",
            'test_user = "taematest"',
            "[paths]",
            'state_dir = "%s"' % self.state,
            'package_repo = "%s"' % package_repo,
            "[tools]",
        ]
        for key, path in sorted(self.tools.items()):
            lines.append('%s = "%s"' % (key, path))
        lines += [
            "",
            "[images]",
            'base_url = "https://repo-default.voidlinux.org/live/current"',
            'previous_url = "https://github.com/Bongbetic/taema/releases/download/'
            'taema-v0.3.0/taema-0.3.0_1.noarch.xbps"',
            "",
            "[images.glibc]",
            'tarball = "void-x86_64-ROOTFS-20250202.tar.xz"',
            'sha256 = "%s"'
            % (
                glibc_sha
                or "3f48e6673ac5907a897d913c97eb96edbfb230162731b4016562c51b3b8f1876"
            ),
            "",
            "[images.musl]",
            'tarball = "void-x86_64-musl-ROOTFS-20250202.tar.xz"',
            'sha256 = "27b2945ea7e2ca2a6ab123ce6f284b255adea2182820da25483d700ffe16e7c2"',
        ]
        with open(self.cfg_path, "w") as f:
            f.write("\n".join(lines) + "\n")
        return self.cfg_path

    def run_main(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        code = vmh.main(list(argv), out=out, err=err)
        return code, out.getvalue(), err.getvalue()

    def stub_tool(self, key, body):
        """Replace one configured tool with a custom stub script."""
        path = self.tools[key]
        with open(path, "w") as f:
            f.write(body)
        os.chmod(path, 0o755)
        return path


class ConfigTest(VmTestCase):
    def test_default_config_valid(self):
        cfg = vmh.load_config()
        self.assertEqual(cfg["libcs"], ["glibc", "musl"])
        self.assertEqual(cfg["scenarios"], ["smoke", "m0"])
        self.assertIn(cfg["accel"], ("auto", "kvm", "tcg"))
        self.assertGreaterEqual(cfg["memory_mb"], 512)
        self.assertGreater(cfg["boot_timeout_s"], 0)
        self.assertGreaterEqual(cfg["scenario_timeout_s"], 3600)

    def test_default_images_pinned(self):
        cfg = vmh.load_config()
        for libc in ("glibc", "musl"):
            spec = vmh.image_spec(cfg, libc)
            self.assertTrue(spec["url"].startswith("https://"))
            self.assertTrue(spec["url"].endswith("/" + spec["tarball"]))
            self.assertEqual(len(spec["sha256"]), 64)
            int(spec["sha256"], 16)  # lowercase hex digest

    def test_invalid_libc_rejected(self):
        self.write_config(libcs=["ppc"])
        with self.assertRaises(vmh.HarnessError):
            vmh.load_config(self.cfg_path)

    def test_invalid_scenario_rejected(self):
        self.write_config(scenarios=["wipe"])
        with self.assertRaises(vmh.HarnessError):
            vmh.load_config(self.cfg_path)

    def test_invalid_sha_rejected(self):
        self.write_config(glibc_sha="nope")
        with self.assertRaises(vmh.HarnessError):
            vmh.load_config(self.cfg_path)

    def test_missing_config_file_is_error(self):
        with self.assertRaises(vmh.HarnessError):
            vmh.load_config(os.path.join(self.tmp, "absent.toml"))


class CacheAndRefusalTest(VmTestCase):
    def test_cache_paths_isolated_per_libc(self):
        cfg = vmh.load_config(self.write_config())
        g, m = vmh.cache_paths(cfg, "glibc"), vmh.cache_paths(cfg, "musl")
        for key in ("dir", "tarball", "rootfs", "base"):
            self.assertNotEqual(g[key], m[key])
        self.assertTrue(g["base"].startswith(self.state))
        self.assertTrue(g["base"].endswith(".qcow2"))

    def test_fetch_requires_network_opt_in(self):
        cfg = vmh.load_config(self.write_config())
        with self.assertRaises(vmh.HarnessError) as cm:
            vmh.fetch_image(cfg, "glibc", allow_network=False)
        self.assertIn("--allow-network", str(cm.exception))
        self.assertFalse(os.path.exists(self.state))

    def test_fetch_command_refused_without_network(self):
        code, out, err = self.run_main(
            "fetch", "--config", self.write_config(), "--state-dir", self.state
        )
        self.assertEqual(code, 2)
        self.assertIn("--allow-network", err)
        self.assertFalse(os.path.exists(self.state))

    def test_run_refused_without_cached_images(self):
        code, out, err = self.run_main(
            "run", "--config", self.write_config(), "--state-dir", self.state
        )
        self.assertEqual(code, 2)
        self.assertIn("--allow-network", err)
        self.assertFalse(os.path.exists(self.state))

    def test_run_refused_when_prerequisite_missing(self):
        self.tools = stub_tools(self.bindir, skip=("qemu",))
        path = self.write_config()
        code, out, err = self.run_main(
            "run", "--config", path, "--state-dir", self.state
        )
        self.assertEqual(code, 2)
        self.assertIn("missing-qemu", err)
        self.assertFalse(os.path.exists(self.state))

    def test_doctor_reports_missing_tools(self):
        self.tools = stub_tools(self.bindir, skip=("qemu", "scp"))
        path = self.write_config()
        code, out, err = self.run_main("doctor", "--config", path)
        self.assertEqual(code, 2)
        self.assertIn("missing-qemu", out + err)
        self.assertIn("missing-scp", out + err)


class QemuPlanTest(VmTestCase):
    def setUp(self):
        super().setUp()
        self.cfg = vmh.load_config(self.write_config())

    def test_qemu_argv_kvm(self):
        run_dir = os.path.join(self.state, "runs", "x")
        argv = vmh.qemu_argv(self.cfg, "glibc", kvm=True, port=2222, run_dir=run_dir)
        self.assertEqual(argv[0], self.tools["qemu"])
        joined = " ".join(argv)
        self.assertIn("-accel kvm", joined)
        self.assertIn("-cpu host", joined)
        self.assertIn("tcp:127.0.0.1:2222-:22", joined)
        self.assertIn(os.path.join(run_dir, "disk.qcow2"), joined)
        self.assertIn("file:" + os.path.join(run_dir, "serial.log"), joined)

    def test_qemu_argv_tcg(self):
        run_dir = os.path.join(self.state, "runs", "x")
        argv = vmh.qemu_argv(self.cfg, "musl", kvm=False, port=2345, run_dir=run_dir)
        joined = " ".join(argv)
        self.assertNotIn("-enable-kvm", joined)
        self.assertIn("-accel tcg", joined)
        self.assertIn(vmh.cache_paths(self.cfg, "musl")["kernel"], joined)
        self.assertIn(vmh.cache_paths(self.cfg, "musl")["initrd"], joined)

    def test_hostfwd_is_loopback_only(self):
        run_dir = os.path.join(self.state, "runs", "x")
        argv = vmh.qemu_argv(self.cfg, "glibc", kvm=False, port=1, run_dir=run_dir)
        nic = argv[argv.index("-nic") + 1]
        self.assertTrue(
            nic.startswith("user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:")
        )

    def test_overlay_argv_backs_run_disk_on_cached_base(self):
        cfg = self.cfg
        base = vmh.cache_paths(cfg, "glibc")["base"]
        overlay = os.path.join(self.state, "runs", "x", "disk.qcow2")
        argv = vmh.overlay_argv(base, overlay)
        self.assertEqual(argv[1:4], ["create", "-f", "qcow2"])
        self.assertIn(base, argv)
        self.assertIn(overlay, argv)

    def test_free_port_is_loopback_available(self):
        port = vmh.free_port()
        self.assertIsInstance(port, int)
        self.assertGreater(port, 1024)
        # the port must actually be bindable again after discovery
        import socket

        s = socket.socket()
        try:
            s.bind(("127.0.0.1", port))
        finally:
            s.close()

    def test_run_dir_is_fresh_or_refused(self):
        cfg = self.cfg
        d1 = vmh.create_run_dir(cfg, "glibc", name="fixed-name")
        self.assertTrue(os.path.isdir(d1))
        with self.assertRaises(vmh.HarnessError):
            vmh.create_run_dir(cfg, "glibc", name="fixed-name")


class PlanTest(VmTestCase):
    def setUp(self):
        super().setUp()
        self.cfg = vmh.load_config(self.write_config())

    def test_plan_covers_both_libcs(self):
        plan = vmh.build_plan(self.cfg, kvm=False)
        self.assertEqual([v["libc"] for v in plan["vms"]], ["glibc", "musl"])
        self.assertEqual(plan["accel"], "tcg")
        for v in plan["vms"]:
            self.assertEqual(v["qemu"][0], self.tools["qemu"])
            self.assertIn("-accel tcg", " ".join(v["qemu"]))

    def test_plan_package_path(self):
        plan = vmh.build_plan(self.cfg, kvm=False)
        self.assertEqual(
            plan["package"]["path"],
            os.path.join(
                ROOT, "build", "repo", "taema-%s_1.noarch.xbps" % vmh.read_version(ROOT)
            ),
        )
        self.assertEqual(
            plan["package"]["argv"],
            ["sh", vmh.BUILD_XBPS, vmh.package_repo_dir(self.cfg)],
        )

    def test_plan_package_repo_can_be_outside_the_worktree(self):
        repo = os.path.join(self.tmp, "external-package-repo")
        self.cfg["paths"]["package_repo"] = repo
        plan = vmh.build_plan(self.cfg, kvm=False)
        self.assertEqual(
            plan["package"]["path"],
            os.path.join(repo, "taema-%s_1.noarch.xbps" % vmh.read_version(ROOT)),
        )
        self.assertEqual(plan["package"]["argv"], ["sh", vmh.BUILD_XBPS, repo])

    def test_plan_bootstraps_test_user_ssh_key(self):
        pub = vmh.ssh_key_paths(self.cfg)[1]
        steps = vmh.build_plan(self.cfg, libcs=["glibc"], kvm=False)["vms"][0]["steps"]
        bootstrap = next(step for step in steps if step["name"] == "scp-bootstrap")
        provision = next(step for step in steps if step["name"] == "provision")
        self.assertIn(pub, bootstrap["argv"])
        self.assertIn(
            "--authorized-key /tmp/taema-vm/id_ed25519.pub", provision["argv"][-1]
        )

    def test_plan_step_order(self):
        plan = vmh.build_plan(
            self.cfg,
            libcs=["glibc"],
            scenarios=["smoke", "m0", "upgrade", "remove"],
            kvm=False,
        )
        names = [s["name"] for s in plan["vms"][0]["steps"]]
        self.assertEqual(names[0], "wait-ssh")
        self.assertIn("scp-bootstrap", names)
        self.assertIn("provision", names)
        self.assertLess(names.index("provision"), names.index("scenario:smoke"))
        self.assertLess(names.index("scenario:smoke"), names.index("scenario:m0"))
        self.assertLess(names.index("scenario:m0"), names.index("scenario:upgrade"))
        self.assertLess(names.index("scenario:upgrade"), names.index("scenario:remove"))
        self.assertEqual(names[-1], "teardown")
        self.assertIn("collect", names)

    def test_m1_and_m2_plan_transfers_acceptance_fixtures(self):
        plan = vmh.build_plan(
            self.cfg,
            libcs=["glibc"],
            scenarios=["m1", "m2"],
            kvm=False,
        )
        vm = plan["vms"][0]
        bootstrap = next(
            step for step in vm["steps"] if step["name"] == "scp-bootstrap"
        )
        m1 = next(step for step in vm["steps"] if step["name"] == "scenario:m1")
        m2 = next(step for step in vm["steps"] if step["name"] == "scenario:m2")
        self.assertIn(vmh.MIGRATION_FIXTURE, bootstrap["argv"])
        self.assertIn(vmh.LEARNING_REPLAY_FIXTURE, bootstrap["argv"])
        self.assertIn(vmh.previous_pkg_path(self.cfg), bootstrap["argv"])
        self.assertIn("--migration-fixture", m1["argv"][-1])
        self.assertIn(
            "--previous /tmp/taema-vm/taema-0.3.0_1.noarch.xbps",
            m1["argv"][-1],
        )
        self.assertIn("--previous-version 0.3.0", m1["argv"][-1])
        self.assertIn("--replay-fixture", m2["argv"][-1])

    def test_plan_network_inputs_listed(self):
        plan = vmh.build_plan(self.cfg, scenarios=["upgrade"], kvm=False)
        urls = plan["network"]["urls"]
        self.assertTrue(any("ROOTFS" in u for u in urls))
        self.assertTrue(any("taema-" in u for u in urls))

    def test_plan_omits_previous_url_when_source_tag_is_available(self):
        with mock.patch.object(vmh, "previous_source_available", return_value=True):
            plan = vmh.build_plan(self.cfg, scenarios=["upgrade"], kvm=False)
        self.assertFalse(any("taema-" in url for url in plan["network"]["urls"]))


class DryRunTest(VmTestCase):
    def test_dry_run_prints_plan_without_side_effects(self):
        path = self.write_config(scenarios=["smoke", "m0"])
        code, out, err = self.run_main(
            "run", "--dry-run", "--config", path, "--state-dir", self.state, "--tcg"
        )
        self.assertEqual(code, 0, err)
        self.assertIn("qemu-system", out)
        self.assertIn("-accel tcg", out)
        self.assertIn("glibc", out)
        self.assertIn("musl", out)
        self.assertIn("scenario:smoke", out)
        self.assertIn("scenario:m0", out)
        self.assertFalse(
            os.path.exists(self.state), "dry run must not create the state dir"
        )


class PackageBuildTest(VmTestCase):
    def test_build_uses_configured_package_repo(self):
        cfg = vmh.load_config(self.write_config())
        repo = os.path.join(self.tmp, "external-package-repo")
        cfg["paths"]["package_repo"] = repo
        package = vmh.package_path(cfg)

        def fake_run(argv, **kwargs):
            self.assertEqual(argv, ["sh", vmh.BUILD_XBPS, repo])
            self.assertEqual(kwargs["cwd"], vmh.TAEMA_ROOT)
            os.makedirs(repo, exist_ok=True)
            with open(package, "wb") as f:
                f.write(b"package")
            return subprocess.CompletedProcess(argv, 0, "", "")

        with mock.patch.object(vmh.subprocess, "run", side_effect=fake_run) as run:
            self.assertEqual(vmh.build_package(cfg), package)
        run.assert_called_once()


class PreviousPackageBuildTest(VmTestCase):
    def test_previous_package_builds_from_a_local_tag_without_network(self):
        cfg = vmh.load_config(self.write_config(libcs=["glibc"]))
        cfg["images"]["previous_ref"] = "taema-v0.3.0"
        dest = vmh.previous_pkg_path(cfg)

        def fake_run(argv, **kwargs):
            if argv[0] == self.tools["git"]:
                archive = argv[argv.index("--output") + 1]
                with open(archive, "wb") as stream:
                    stream.write(b"source archive")
            elif argv[0] == self.tools["tar"]:
                pass
            else:
                self.assertEqual(argv[0], "sh")
                repository = argv[-1]
                os.makedirs(repository, exist_ok=True)
                with open(os.path.join(repository, os.path.basename(dest)), "wb") as f:
                    f.write(b"previous package")
            return subprocess.CompletedProcess(argv, 0, "", "")

        with (
            mock.patch.object(vmh, "previous_source_available", return_value=True),
            mock.patch.object(vmh.subprocess, "run", side_effect=fake_run) as run,
        ):
            self.assertEqual(vmh.fetch_previous(cfg, allow_network=False), dest)

        with open(dest, "rb") as stream:
            self.assertEqual(stream.read(), b"previous package")
        self.assertEqual(run.call_count, 3)


class ImageBuildScriptTest(VmTestCase):
    """Rootless image-build script generation (no live extraction or boot)."""

    def setUp(self):
        super().setUp()
        self.cfg = vmh.load_config(self.write_config())
        self.script = read_text(os.path.join(VM_DIR, "mkimage.sh"))

    def test_mkimage_argv_runs_under_mount_and_pid_namespace_with_proc(self):
        rootfs = os.path.join(self.state, "images", "glibc", "rootfs")
        pub = os.path.join(self.state, "images", "id_ed25519.pub")
        argv = vmh.mkimage_argv(self.cfg, rootfs, pub)
        self.assertEqual(argv[0], self.tools["unshare"])
        self.assertIn("-rmfp", argv)
        # a user namespace may only mount procfs alongside its own PID
        # namespace, so unshare must mount it at rootfs/proc before the script
        self.assertIn("--mount-proc=" + os.path.join(rootfs, "proc"), argv)
        self.assertEqual(
            argv[-4:], ["sh", os.path.join(VM_DIR, "mkimage.sh"), rootfs, pub]
        )

    def test_mkimage_script_never_mounts_proc_itself(self):
        self.assertNotIn("mount -t proc", self.script)

    def test_mkimage_enables_services_in_durable_default_runlevel(self):
        # /var/service points into /run (tmpfs), so enablement links must be
        # written under /etc/runit/runsvdir/default to survive guest boots
        self.assertIn('mkdir -p "$R/etc/runit/runsvdir/default"', self.script)
        self.assertIn(
            'ln -sf /etc/sv/sshd "$R/etc/runit/runsvdir/default/sshd"', self.script
        )
        self.assertIn(
            'ln -sf /etc/sv/dhcpcd "$R/etc/runit/runsvdir/default/dhcpcd"', self.script
        )
        self.assertIn("openssh dhcpcd python3 iproute2 sudo dbus elogind", self.script)
        self.assertIn(
            'ln -sf /etc/sv/dbus "$R/etc/runit/runsvdir/default/dbus"', self.script
        )
        self.assertIn(
            'ln -sf /etc/sv/elogind "$R/etc/runit/runsvdir/default/elogind"',
            self.script,
        )

    def test_mkimage_fixup_reads_guest_file_and_is_idempotent(self):
        # sed must read the fixup file inside the rootfs; the old code read
        # the *host* path /etc/vmh-fixup.sh, which does not exist
        self.assertNotIn("1r /etc/vmh-fixup.sh", self.script)
        self.assertIn('sed -i "1r $R/etc/vmh-fixup.sh"', self.script)
        # re-running mkimage on a configured rootfs must not stack fixups
        self.assertIn("grep -q 'vmh-fixed'", self.script)

    def test_mkimage_strips_host_environment_from_chroot(self):
        # a host TMPDIR/XBPS_* override does not exist inside the chroot and
        # would make xbps-install fail while staging package scripts
        self.assertIn(
            "env -u TMPDIR -u XBPS_ROOT -u XBPS_ARCH -u XBPS_TARGET_ARCH", self.script
        )

    def test_mkimage_fixup_preserves_setuid_bits_across_chown(self):
        # chown clears set-user-ID/set-group-ID bits (POSIX); without a
        # restore pass sudo refuses to run and provisioning dies with
        # "sudo: /usr/bin/sudo must be owned by uid 0 and have the setuid bit"
        # (observed on the reference machine's first live provision step)
        self.assertIn("-perm -4000", self.script)  # snapshot selector
        self.assertIn("-perm -2000", self.script)  # setgid too
        self.assertIn("chmod 4755 /usr/bin/sudo /usr/bin/su", self.script)
        # snapshot before chown, restore after it
        self.assertLess(
            self.script.index("-perm -4000"), self.script.index("chown -R 0:0")
        )
        self.assertLess(
            self.script.index("chown -R 0:0"),
            self.script.index("done < /etc/vmh-suid.bak"),
        )


class TransportTest(VmTestCase):
    """SSH/SCP command generation: recursive copies, loopback, private hosts."""

    def setUp(self):
        super().setUp()
        self.cfg = vmh.load_config(self.write_config())

    def test_scp_transfers_are_recursive(self):
        # bootstrap copies the package repository directory and collect
        # copies the artifacts directory; scp refuses directories without -r
        argv = vmh.scp_argv(
            self.cfg,
            2222,
            "/k",
            "/kh",
            [os.path.join(VM_DIR, "provision.sh")],
            "vmadmin@127.0.0.1:/tmp/taema-vm/",
        )
        self.assertEqual(argv[0], self.tools["scp"])
        self.assertIn("-r", argv)

    def test_ssh_is_loopback_only_with_private_known_hosts(self):
        known = os.path.join(self.state, "runs", "x", "known_hosts")
        argv = vmh.ssh_argv(self.cfg, 2222, "/k", known, "vmadmin", "true")
        self.assertIn("UserKnownHostsFile=" + known, argv)
        self.assertIn("GlobalKnownHostsFile=/dev/null", argv)
        self.assertIn("BatchMode=yes", argv)
        self.assertNotIn(os.path.expanduser("~/.ssh/known_hosts"), argv)
        self.assertEqual(argv[-2:], ["vmadmin@127.0.0.1", "true"])


class RunPipelineTest(VmTestCase):
    """The `run` pipeline against stubbed transports: no QEMU, no network."""

    def setUp(self):
        super().setUp()
        package_repo = os.path.join(self.tmp, "package-repo")
        self.cfg_path = self.write_config(
            libcs=["glibc"], scenarios=["smoke"], package_repo=package_repo
        )
        self.cfg = vmh.load_config(self.cfg_path)
        self.stub_tool("qemu", "#!/bin/sh\nexec sleep 60\n")
        self.stub_tool("qemu_img", "#!/bin/sh\nexit 0\n")
        self.stub_tool("scp", "#!/bin/sh\nexit 0\n")
        self.fail_marker = os.path.join(self.tmp, "fail-scenario")
        self.stub_tool(
            "ssh",
            "#!/bin/sh\n"
            'case "$*" in *scenario.py*) [ -f "%s" ] && exit 1 ;; esac\n'
            "exit 0\n" % self.fail_marker,
        )
        # Offline cache: fake base image, keypair and package, so `run` needs
        # neither --allow-network nor a real package build.
        cp = vmh.cache_paths(self.cfg, "glibc")
        os.makedirs(cp["dir"], exist_ok=True)
        with open(cp["base"], "wb") as f:
            f.write(b"base")
        key, pub = vmh.ssh_key_paths(self.cfg)
        os.makedirs(os.path.dirname(key), exist_ok=True)
        for p in (key, pub):
            with open(p, "wb") as f:
                f.write(b"key")
        pkg = vmh.package_path(self.cfg)
        os.makedirs(os.path.dirname(pkg), exist_ok=True)
        with open(pkg, "wb") as f:
            f.write(b"pkg")
        self.out, self.err = io.StringIO(), io.StringIO()

    def run_offline(self):
        return vmh.main(
            [
                "run",
                "--config",
                self.cfg_path,
                "--state-dir",
                self.state,
                "--tcg",
                "--no-build",
                "--libc",
                "glibc",
            ],
            out=self.out,
            err=self.err,
        )

    def _only_run_dir(self):
        runs = os.path.join(self.state, "runs")
        names = os.listdir(runs)
        self.assertEqual(len(names), 1, names)
        return os.path.join(runs, names[0])

    def test_offline_run_passes_and_saves_logs_and_results(self):
        code = self.run_offline()
        self.assertEqual(code, 0, self.err.getvalue())
        run_dir = self._only_run_dir()
        with open(os.path.join(run_dir, "summary.json")) as f:
            summary = json.load(f)
        self.assertEqual(summary["accel"], "tcg")
        self.assertEqual(summary["vms"]["glibc"]["scenarios"], {"smoke": "PASS"})
        for rel in (
            "qemu.log",
            "logs/provision.log",
            "logs/scenario-smoke.log",
            "logs/collect.log",
        ):
            self.assertTrue(os.path.isfile(os.path.join(run_dir, rel)), rel)
        # the disposable overlay is discarded without --keep-run
        self.assertFalse(os.path.exists(os.path.join(run_dir, "disk.qcow2")))

    def test_failing_scenario_recorded_and_artifacts_still_collected(self):
        with open(self.fail_marker, "w") as f:
            f.write("")
        code = self.run_offline()
        self.assertEqual(code, 1, self.err.getvalue())
        run_dir = self._only_run_dir()
        with open(os.path.join(run_dir, "summary.json")) as f:
            summary = json.load(f)
        self.assertEqual(summary["vms"]["glibc"]["scenarios"], {"smoke": "FAIL"})
        self.assertTrue(
            os.path.isfile(os.path.join(run_dir, "logs/scenario-smoke.log"))
        )
        # a failed scenario must not skip artifact collection
        self.assertTrue(os.path.isfile(os.path.join(run_dir, "logs/collect.log")))


class HarnessCliParsingTest(VmTestCase):
    def test_parse_scenarios_all(self):
        self.assertEqual(
            vmh.parse_scenarios("all"),
            ["smoke", "m0", "m1", "m2", "m3", "upgrade", "remove"],
        )

    def test_m0_acceptance_is_a_registered_guest_scenario(self):
        self.assertIn("m0", vmh.SCENARIOS)
        self.assertIn("m0", scenario.SCENARIOS)
        for name in ("m1", "m2"):
            self.assertIn(name, vmh.SCENARIOS)
            self.assertIn(name, scenario.SCENARIOS)

    def test_m3_release_acceptance_is_a_registered_guest_scenario(self):
        self.assertIn("m3", vmh.SCENARIOS)
        self.assertIn("m3", scenario.SCENARIOS)
        cfg = vmh.load_config(self.write_config(libcs=["glibc"], scenarios=["m3"]))
        plan = vmh.build_plan(cfg, libcs=["glibc"], scenarios=["m3"], kvm=False)
        step = next(
            item for item in plan["vms"][0]["steps"] if item["name"] == "scenario:m3"
        )
        self.assertIn("scenario.py m3", step["argv"][-1])

    def test_m3_can_boot_a_low_memory_guest(self):
        config = self.write_config(libcs=["glibc"], scenarios=["m3"])
        code, out, err = self.run_main(
            "run",
            "--dry-run",
            "--config",
            config,
            "--state-dir",
            self.state,
            "--libc",
            "glibc",
            "--memory-mb",
            "512",
        )
        self.assertEqual(code, 0, err)
        self.assertIn("-m 512", out)

    def test_m3_bootstraps_fake_libvirt_acceptance_tests(self):
        sources = vmh.bootstrap_sources(
            "/tmp/key.pub", "/tmp/repo", "/tmp/previous.xbps", ["m3"]
        )
        self.assertIn(os.path.join(ROOT, "tests"), sources)
        self.assertIn(os.path.join(ROOT, "schema"), sources)

    def test_parse_libcs(self):
        self.assertEqual(vmh.parse_libcs("glibc, musl"), ["glibc", "musl"])

    def test_previous_version_derived_from_default_config(self):
        self.assertEqual(vmh.previous_version(vmh.load_config()), "0.3.0")

    def test_unknown_subcommand_is_usage_error(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as cm:
                vmh.main(["teleport"], out=io.StringIO(), err=io.StringIO())
        self.assertEqual(cm.exception.code, 2)


class HarnessSurfacesTest(unittest.TestCase):
    """Docs, make targets and the opt-in KVM workflow: text contracts."""

    def test_release_notes_document_adopt_change_and_version(self):
        notes = read_text(os.path.join(REPO, "CHANGELOG.md"))
        self.assertIn("## Behaviour changes", notes)
        self.assertIn("### adopt now contains and asks", notes)
        self.assertIn("leftover/", notes)
        self.assertIn("review", notes)

        workflow = read_text(os.path.join(REPO, ".github", "workflows", "release.yml"))
        self.assertIn('cat CHANGELOG.md >> "$RUNNER_TEMP/notes.md"', workflow)
        self.assertEqual(vmh.read_version(ROOT), "0.5.0")

    def test_release_notes_document_0_5_0_resource_governor(self):
        notes = read_text(os.path.join(REPO, "CHANGELOG.md"))
        release = " ".join(
            notes.split("# 0.5.0", 1)[1].split("# 0.4.0", 1)[0].split()
        ).lower()
        self.assertIn("pressure guard", release)
        self.assertIn("memory budget", release)
        self.assertIn("low-memory", release)
        readme = read_text(os.path.join(REPO, "README.md"))
        self.assertIn("## Memory", readme)
        self.assertIn("taema memory budget", readme)
        self.assertIn("git tag taema-v0.5.0", readme)

    def test_release_notes_document_forget_all_and_feedback_field(self):
        notes = read_text(os.path.join(REPO, "CHANGELOG.md"))
        release = " ".join(notes.split("# 0.4.0", 1)[1].split("# 0.3.0", 1)[0].split())
        self.assertIn("taema forget --all APP", release)
        self.assertIn("optional boolean `all` field", release)

    def test_release_workflow_combines_manual_and_generated_release_notes(self):
        workflow = read_text(os.path.join(REPO, ".github", "workflows", "release.yml"))
        self.assertIn('notes="$(cat "$RUNNER_TEMP/notes.md")"', workflow)
        self.assertIn('--title "tæma ${VERSION}"', workflow)
        self.assertIn('--notes "$notes" --generate-notes', workflow)
        self.assertNotIn("--notes-file", workflow)

    def test_readme_mode_table_describes_adopt_lifecycle(self):
        readme = read_text(os.path.join(REPO, "README.md"))
        self.assertIn(
            "| `adopt` | Adopts eligible apps, contains GUI survivors under `leftover/` "
            "for review, and honors `taema run --bind` by stopping that scope when "
            "its command exits; idle shared and unit scopes are reviewed, not stopped. |",
            readme,
        )

    def test_docs_document_one_command_scenarios_and_safety(self):
        docs = read_text(os.path.join(ROOT, "docs", "vm-harness.md"))
        self.assertIn("make -C taema vm-test", docs)
        self.assertIn("Scenario API", docs)
        self.assertIn("--allow-network", docs)
        self.assertIn("never", docs)  # host-safety guarantees section
        self.assertIn("cgroups", docs)
        self.assertIn("artifacts", docs)

    def test_makefile_targets_invoke_the_harness(self):
        mk = read_text(os.path.join(ROOT, "Makefile"))
        for target in ("vm-test", "vm-dry-run", "vm-doctor"):
            self.assertIn(target + ":", mk)
        self.assertIn("tools/vm/vmh.py run", mk)

    def test_package_builder_indexes_for_host_and_musl_guests(self):
        script = read_text(os.path.join(ROOT, "tools", "build-xbps.sh"))
        self.assertIn('xbps-rindex -f -a "$repo/$pkg.noarch.xbps"', script)
        self.assertIn(
            'XBPS_ARCH=x86_64-musl xbps-rindex -f -a "$repo/$pkg.noarch.xbps"', script
        )

    def test_workflow_is_opt_in_kvm_only_and_uploads_artifacts(self):
        wf = read_text(os.path.join(REPO, ".github", "workflows", "vm-harness.yml"))
        self.assertIn("workflow_dispatch", wf)
        self.assertNotIn("  push:", wf)  # never auto-runs without KVM
        self.assertIn("kvm", wf)
        self.assertIn('default: "smoke,m0"', wf)
        self.assertIn("timeout-minutes: 180", wf)
        self.assertIn("upload-artifact", wf)
        self.assertNotIn("continue-on-error", wf)


class ScenarioM3MoveTest(unittest.TestCase):
    def test_m3_move_keeps_direct_write_when_delegated(self):
        cgroot = os.path.join(tempfile.mkdtemp(), "cg")
        self.addCleanup(shutil.rmtree, os.path.dirname(cgroot), True)
        dest = os.path.join(cgroot, "user", str(os.getuid()), "leftover", "cache")
        os.makedirs(dest)
        open(os.path.join(dest, "cgroup.procs"), "w", encoding="ascii").close()
        with mock.patch.object(scenario, "CGROOT", cgroot):
            with mock.patch.object(scenario.subprocess, "run") as run:
                scenario._m3_move(123, dest)
        with open(os.path.join(dest, "cgroup.procs"), encoding="ascii") as source:
            self.assertEqual(source.read(), "123\n")
        run.assert_not_called()

    def test_m3_move_uses_sudo_tee_only_when_direct_write_is_denied(self):
        cgroot = os.path.join(tempfile.mkdtemp(), "cg")
        self.addCleanup(shutil.rmtree, os.path.dirname(cgroot), True)
        base = os.path.join(cgroot, "user", str(os.getuid()))
        dest = os.path.join(base, "leftover", "cache")
        os.makedirs(dest)
        open(os.path.join(dest, "cgroup.procs"), "w", encoding="ascii").close()
        completed = subprocess.CompletedProcess([], 0, "", "")
        with mock.patch.object(scenario, "CGROOT", cgroot):
            with mock.patch("builtins.open", side_effect=PermissionError("denied")):
                with mock.patch.object(
                    scenario.subprocess, "run", return_value=completed
                ) as run:
                    scenario._m3_move(123, dest)
        run.assert_called_once_with(
            ["sudo", "-n", "tee", os.path.join(dest, "cgroup.procs")],
            input="123\n",
            capture_output=True,
            text=True,
            timeout=10,
        )

    def test_m3_move_reports_privileged_write_failure(self):
        cgroot = os.path.join(tempfile.mkdtemp(), "cg")
        self.addCleanup(shutil.rmtree, os.path.dirname(cgroot), True)
        dest = os.path.join(cgroot, "user", str(os.getuid()), "leftover", "cache")
        os.makedirs(dest)
        denied = subprocess.CompletedProcess([], 1, "", "sudo denied cgroup write")
        with mock.patch.object(scenario, "CGROOT", cgroot):
            with mock.patch("builtins.open", side_effect=PermissionError("denied")):
                with mock.patch.object(scenario.subprocess, "run", return_value=denied):
                    with self.assertRaisesRegex(
                        scenario.ScenarioError, "sudo denied cgroup write"
                    ):
                        scenario._m3_move(123, dest)

    def test_m3_move_does_not_use_sudo_for_other_write_errors(self):
        cgroot = os.path.join(tempfile.mkdtemp(), "cg")
        self.addCleanup(shutil.rmtree, os.path.dirname(cgroot), True)
        dest = os.path.join(cgroot, "user", str(os.getuid()), "leftover", "cache")
        os.makedirs(dest)
        with mock.patch.object(scenario, "CGROOT", cgroot):
            with mock.patch("builtins.open", side_effect=OSError("read-only")):
                with mock.patch.object(scenario.subprocess, "run") as run:
                    with self.assertRaisesRegex(OSError, "read-only"):
                        scenario._m3_move(123, dest)
        run.assert_not_called()


class ScenarioM3MemoryControllerTest(unittest.TestCase):
    def make_controller_tree(self, base_state="memory", leftover_state="memory"):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root, True)
        base = os.path.join(root, "user", str(os.getuid()))
        leftover = os.path.join(base, "leftover")
        os.makedirs(leftover)
        for path, controllers, active in (
            (base, "memory", base_state),
            (leftover, "memory", leftover_state),
        ):
            with open(os.path.join(path, "cgroup.controllers"), "w") as target:
                target.write(controllers + "\n")
            with open(os.path.join(path, "cgroup.subtree_control"), "w") as target:
                target.write(active + "\n")
        return base, leftover

    def test_already_enabled_memory_controller_needs_no_writes(self):
        base, leftover = self.make_controller_tree("memory", "memory")
        with mock.patch.object(scenario.subprocess, "run") as run:
            scenario._m3_enable_memory_controllers(base, leftover)
        run.assert_not_called()

    def test_enables_memory_directly_at_each_parent(self):
        base, leftover = self.make_controller_tree("", "")
        with mock.patch.object(scenario.subprocess, "run") as run:
            scenario._m3_enable_memory_controllers(base, leftover)
        for path in (base, leftover):
            with open(os.path.join(path, "cgroup.subtree_control")) as source:
                self.assertEqual(source.read(), "+memory\n")
        run.assert_not_called()

    def test_permission_error_uses_noninteractive_sudo_tee(self):
        base, leftover = self.make_controller_tree("", "memory")
        subtree = os.path.join(base, "cgroup.subtree_control")
        real_open = open
        completed = subprocess.CompletedProcess([], 0, "", "")

        def privileged_write(argv, input, **kwargs):
            with real_open(subtree, "w") as target:
                target.write(input)
            return completed

        def deny_direct_subtree_write(path, mode="r", *args, **kwargs):
            if path == subtree and "w" in mode:
                raise PermissionError("denied")
            return real_open(path, mode, *args, **kwargs)

        with mock.patch("builtins.open", side_effect=deny_direct_subtree_write):
            with mock.patch.object(
                scenario.subprocess, "run", side_effect=privileged_write
            ) as run:
                scenario._m3_enable_memory_controllers(base, leftover)
        run.assert_called_once_with(
            ["sudo", "-n", "tee", subtree],
            input="+memory\n",
            capture_output=True,
            text=True,
            timeout=10,
        )

    def test_missing_memory_controller_fails_with_parent_detail(self):
        base, leftover = self.make_controller_tree("memory", "memory")
        with open(os.path.join(leftover, "cgroup.controllers"), "w") as target:
            target.write("cpu\n")
        with self.assertRaisesRegex(
            scenario.ScenarioError,
            "memory controller unavailable.*%s" % leftover,
        ):
            scenario._m3_enable_memory_controllers(base, leftover)

    def test_other_enable_error_is_reported_without_sudo_fallback(self):
        base, leftover = self.make_controller_tree("", "memory")
        subtree = os.path.join(base, "cgroup.subtree_control")
        real_open = open

        def deny_write(path, mode="r", *args, **kwargs):
            if path == subtree and "w" in mode:
                raise OSError("controller busy")
            return real_open(path, mode, *args, **kwargs)

        with mock.patch("builtins.open", side_effect=deny_write):
            with mock.patch.object(scenario.subprocess, "run") as run:
                with self.assertRaisesRegex(
                    scenario.ScenarioError,
                    "cannot enable memory controller.*controller busy",
                ):
                    scenario._m3_enable_memory_controllers(base, leftover)
        run.assert_not_called()


class ScenarioM3FixtureHelpersTest(unittest.TestCase):
    @staticmethod
    def _quiet_status(active=False):
        return {"status": {"details": {"guard": {"active": active}}}}

    @staticmethod
    def _quiet_pressure(some_total=0, some_avg10=0.0, full_total=0, full_avg10=0.0):
        return {
            "some": {"total": some_total, "avg10": some_avg10},
            "full": {"total": full_total, "avg10": full_avg10},
        }

    def test_footprint_quiet_wait_requires_guard_to_finish(self):
        clock = [0.0]

        def sleep(duration):
            clock[0] += duration

        with (
            mock.patch.object(scenario.time, "monotonic", side_effect=lambda: clock[0]),
            mock.patch.object(scenario.time, "sleep", side_effect=sleep),
        ):
            result = scenario._m3_wait_for_footprint_quiet(
                status_reader=lambda: self._quiet_status(active=clock[0] < 4),
                psi_reader=lambda: self._quiet_pressure(),
                timeout=20,
                quiet_seconds=2,
                poll_interval=1,
            )

        self.assertGreaterEqual(result["waited_seconds"], 6)
        self.assertEqual(result["stable_seconds"], 2)

    def test_footprint_quiet_wait_resets_when_psi_counters_change(self):
        clock = [0.0]

        def sleep(duration):
            clock[0] += duration

        def pressure():
            some_total = 1 if clock[0] >= 3 else 0
            return self._quiet_pressure(some_total=some_total)

        with (
            mock.patch.object(scenario.time, "monotonic", side_effect=lambda: clock[0]),
            mock.patch.object(scenario.time, "sleep", side_effect=sleep),
        ):
            result = scenario._m3_wait_for_footprint_quiet(
                status_reader=lambda: self._quiet_status(),
                psi_reader=pressure,
                timeout=20,
                quiet_seconds=3,
                poll_interval=1,
            )

        self.assertGreaterEqual(result["waited_seconds"], 7)
        self.assertEqual(result["stable_seconds"], 3)
        self.assertEqual(result["some_total"], 1)

    def test_footprint_quiet_wait_finishes_after_stable_pressure_window(self):
        clock = [0.0]

        def sleep(duration):
            clock[0] += duration

        with (
            mock.patch.object(scenario.time, "monotonic", side_effect=lambda: clock[0]),
            mock.patch.object(scenario.time, "sleep", side_effect=sleep),
        ):
            result = scenario._m3_wait_for_footprint_quiet(
                status_reader=lambda: self._quiet_status(),
                psi_reader=lambda: self._quiet_pressure(),
                timeout=20,
                quiet_seconds=3,
                poll_interval=1,
            )

        self.assertEqual(result["stable_seconds"], 3)
        self.assertGreaterEqual(result["waited_seconds"], 3)

    def test_footprint_psi_reader_parses_avg10_and_total_counters(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as source:
            source.write(
                "some avg10=0.12 avg60=4.21 avg300=11.80 total=69040792\n"
                "full avg10=0.00 avg60=4.11 avg300=11.52 total=67415772\n"
            )
            path = source.name
        self.addCleanup(os.unlink, path)

        result = scenario._m3_psi_pressure_snapshot(path)

        self.assertEqual(result["some"], {"avg10": 0.12, "total": 69040792})
        self.assertEqual(result["full"], {"avg10": 0.0, "total": 67415772})

    def test_idle_footprint_guard_uses_production_thresholds_and_cooldown(self):
        idle_config = scenario._m3_guard_config(pressure_fixture=False)
        pressure_config = scenario._m3_guard_config()

        self.assertIn("cooldown = 10", idle_config)
        self.assertIn('psi_some = "150ms/2s"', idle_config)
        self.assertIn('psi_full = "50ms/2s"', idle_config)
        self.assertIn("cooldown = 1", pressure_config)
        self.assertIn('psi_some = "1ms/2s"', pressure_config)

    def test_required_live_unittest_gate_rejects_a_skipped_test(self):
        self.assertFalse(
            scenario._m3_unittest_passed(
                0, "Ran 1 test in 0.001s\n\nOK (skipped=1)\n", fail_on_skip=True
            )
        )
        self.assertTrue(scenario._m3_unittest_passed(0, "Ran 1 test\n\nOK\n"))
        self.assertFalse(
            scenario._m3_unittest_passed(1, "Ran 1 test\n\nFAILED (errors=1)\n")
        )

    def test_required_live_unittest_runner_records_a_skip_as_failure(self):
        output = "Ran 1 test in 0.001s\n\nOK (skipped=1)\n"
        result = subprocess.CompletedProcess([], 0, output, None)
        with tempfile.TemporaryDirectory() as artifacts:
            rec = scenario.ResultRecorder("m3", artifacts)
            args = types.SimpleNamespace(artifacts=artifacts)
            with mock.patch.object(scenario.subprocess, "run", return_value=result):
                passed = scenario._m3_run_tests(
                    rec,
                    args,
                    "required-live-test",
                    [
                        "tests.test_freeze_live.LiveListenerWakeTests.test_http_request_thaws_listener_with_p95_under_three_seconds"
                    ],
                    fail_on_skip=True,
                )

        self.assertFalse(passed)
        self.assertFalse(rec.steps[0]["ok"])
        self.assertIn("skipped=1", rec.steps[0]["detail"])

    def test_footprint_gate_requires_enabled_guard_and_two_production_psi_fds(self):
        status = {
            "status": {
                "daemon": "running",
                "mode": "auto",
                "config_error": None,
            },
            "memory": {"enabled": True},
        }
        config = scenario._m3_guard_config(pressure_fixture=False)

        self.assertTrue(scenario._m3_footprint_guard_inputs(config, 2, status))
        self.assertFalse(scenario._m3_footprint_guard_inputs(config, 1, status))
        self.assertFalse(scenario._m3_footprint_guard_inputs(config, 3, status))
        self.assertFalse(
            scenario._m3_footprint_guard_inputs(
                scenario._m3_guard_config(pressure_fixture=True), 2, status
            )
        )
        self.assertFalse(
            scenario._m3_footprint_guard_inputs(
                config,
                2,
                {
                    "status": dict(status["status"], mode="observe"),
                    "memory": status["memory"],
                },
            )
        )

    def test_daemon_sample_counts_both_user_memory_pressure_fds(self):
        with (
            tempfile.TemporaryDirectory() as proc_root,
            tempfile.TemporaryDirectory() as cg_root,
        ):
            pid = 1234
            process_root = os.path.join(proc_root, str(pid))
            fd_root = os.path.join(process_root, "fd")
            os.makedirs(fd_root)
            with open(
                os.path.join(process_root, "status"), "w", encoding="ascii"
            ) as target:
                target.write("VmRSS:\t2048 kB\n")
            stat_fields = ["S"] + ["0"] * 13
            stat_fields[11] = "7"
            stat_fields[12] = "9"
            with open(
                os.path.join(process_root, "stat"), "w", encoding="ascii"
            ) as target:
                target.write("1234 (taemad) " + " ".join(stat_fields))
            for fd in ("3", "4", "5"):
                open(os.path.join(fd_root, fd), "w").close()
            pressure_path = os.path.join(cg_root, "user", "1000", "memory.pressure")
            links = {
                os.path.join(fd_root, "3"): pressure_path,
                os.path.join(fd_root, "4"): pressure_path,
                os.path.join(fd_root, "5"): os.path.join(cg_root, "memory.pressure"),
            }
            with (
                mock.patch.object(scenario, "PROCROOT", proc_root),
                mock.patch.object(scenario, "CGROOT", cg_root),
                mock.patch.object(scenario.os, "getuid", return_value=1000),
                mock.patch.object(
                    scenario.os, "readlink", side_effect=links.__getitem__
                ),
            ):
                sample = scenario._m3_daemon_sample(pid)

        self.assertEqual(sample, (2048, 16, 2))

    def test_post_guard_pressure_cap_uses_16_mib_margin_below_threshold(self):
        mib = 1024 * 1024
        target, cap = scenario._m3_post_guard_pressure_cap(
            allocated=30 * mib,
            available_bytes=200 * mib,
            earlyoom_threshold_bytes=100 * mib,
        )
        self.assertEqual(target, 84 * mib)
        self.assertEqual(cap, 146 * mib)

        target, cap = scenario._m3_post_guard_pressure_cap(
            allocated=0,
            available_bytes=mib,
            earlyoom_threshold_bytes=8 * mib,
        )
        self.assertEqual(target, 0)
        self.assertEqual(cap, 2 * mib)

    def test_earlyoom_parser_uses_reported_user_memory_denominator(self):
        mib = 1024 * 1024
        threshold_787 = (787 * mib * 5 + 99) // 100
        threshold_790 = (790 * mib * 5 + 99) // 100
        samples = scenario._m3_parse_earlyoom_memory_samples(
            "\x1b[0mmem avail:   58 of   787 MiB ( 7.39%), swap free: 0 MiB\n"
            "mem avail: 56 of 790 MiB (7.09%), swap free: 0 MiB\n"
        )
        self.assertEqual(
            samples,
            [
                {
                    "available_mib": 58,
                    "total_mib": 787,
                    "threshold_bytes": threshold_787,
                },
                {
                    "available_mib": 56,
                    "total_mib": 790,
                    "threshold_bytes": threshold_790,
                },
            ],
        )
        target, cap = scenario._m3_post_guard_pressure_cap(
            allocated=32 * mib,
            available_bytes=58 * mib,
            earlyoom_threshold_bytes=samples[-1]["threshold_bytes"],
        )
        self.assertEqual(target, threshold_790 - 16 * mib)
        self.assertEqual(cap, 32 * mib + max(2 * mib, 58 * mib - target))

    def test_pressure_ramp_is_bounded_to_four_8_mib_increments(self):
        mib = 1024 * 1024
        cap = 66 * mib
        for steps in range(4):
            cap, increment = scenario._m3_pressure_ramp_next_cap(cap, steps)
            self.assertEqual(increment, 8 * mib)
        self.assertEqual(cap, 98 * mib)
        self.assertEqual(scenario._m3_pressure_ramp_next_cap(cap, 4), (cap, 0))

    def test_cache_file_is_unique_and_created_in_selected_disk_area(self):
        with tempfile.TemporaryDirectory() as directory:
            first = scenario._m3_create_cache_file(directory)
            second = scenario._m3_create_cache_file(directory)
            self.assertNotEqual(first, second)
            self.assertEqual(os.path.dirname(first), directory)
            self.assertEqual(os.path.dirname(second), directory)
            self.assertTrue(os.path.isfile(first))
            self.assertTrue(os.path.isfile(second))

    def test_cache_stats_report_inactive_file_and_conservative_reclaimable_bytes(self):
        with tempfile.TemporaryDirectory() as path:
            with open(os.path.join(path, "memory.current"), "w") as target:
                target.write("4096\n")
            with open(os.path.join(path, "memory.stat"), "w") as target:
                target.write(
                    "file 1000\nshmem 200\ninactive_file 800\n"
                    "anon 300\nworkingset_refault_file 7\n"
                )
            stats = scenario._m3_cgroup_stats(path)
        self.assertEqual(stats["inactive_file_bytes"], 800)
        self.assertEqual(scenario._m3_reclaimable_file_cache_bytes(stats), 800)

    def test_thaw_uncaps_resumes_and_waits_for_both_cgroups(self):
        with tempfile.TemporaryDirectory() as root:
            candidate = os.path.join(root, "candidate")
            pressure = os.path.join(root, "pressure")
            os.mkdir(candidate)
            os.mkdir(pressure)
            for path in (candidate, pressure):
                with open(os.path.join(path, "cgroup.freeze"), "w") as target:
                    target.write("1\n")
                with open(os.path.join(path, "cgroup.events"), "w") as target:
                    target.write("populated 1\nfrozen 1\n")
            high = os.path.join(pressure, "memory.high")
            with open(high, "w") as target:
                target.write("2M\n")

            class RunningPressure:
                def __init__(self):
                    self.sent_signal = None

                def poll(self):
                    return None

                def send_signal(self, value):
                    self.sent_signal = value

            worker = RunningPressure()

            def thaw_events():
                time.sleep(0.05)
                for path in (candidate, pressure):
                    with open(os.path.join(path, "cgroup.events"), "w") as target:
                        target.write("populated 1\nfrozen 0\n")

            thread = threading.Thread(target=thaw_events)
            thread.start()
            try:
                scenario._m3_thaw_cgroups(
                    candidate, pressure, pressure_proc=worker, timeout=1, poll=0.01
                )
            finally:
                thread.join(timeout=1)

            self.assertEqual(worker.sent_signal, scenario.signal.SIGUSR2)
            with open(high) as source:
                self.assertEqual(source.read(), "max\n")
            for path in (candidate, pressure):
                with open(os.path.join(path, "cgroup.freeze")) as source:
                    self.assertEqual(source.read(), "0\n")


class ScenarioM3OomScoreTest(unittest.TestCase):
    def setUp(self):
        self.procroot = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.procroot, True)
        self.pid = 123
        self.pid_path = os.path.join(self.procroot, str(self.pid))
        os.makedirs(self.pid_path)
        self.adj_path = os.path.join(self.pid_path, "oom_score_adj")
        with open(self.adj_path, "w") as target:
            target.write("0\n")

    def test_set_oom_score_adj_keeps_direct_proc_write(self):
        with mock.patch.object(scenario, "PROCROOT", self.procroot):
            with mock.patch.object(scenario.subprocess, "run") as run:
                result = scenario._m3_set_oom_score_adj(self.pid, -1000)
        self.assertEqual(result, -1000)
        with open(self.adj_path) as source:
            self.assertEqual(source.read(), "-1000\n")
        run.assert_not_called()

    def test_set_oom_score_adj_falls_back_to_sudo_tee_on_permission_error(self):
        real_open = open
        completed = subprocess.CompletedProcess([], 0, "", "")

        def privileged_write(argv, input, **kwargs):
            with real_open(self.adj_path, "w") as target:
                target.write(input)
            return completed

        def deny_direct_write(path, mode="r", *args, **kwargs):
            if path == self.adj_path and "w" in mode:
                raise PermissionError("denied")
            return real_open(path, mode, *args, **kwargs)

        with mock.patch.object(scenario, "PROCROOT", self.procroot):
            with mock.patch("builtins.open", side_effect=deny_direct_write):
                with mock.patch.object(
                    scenario.subprocess, "run", side_effect=privileged_write
                ) as run:
                    self.assertEqual(
                        scenario._m3_set_oom_score_adj(self.pid, -1000), -1000
                    )
        run.assert_called_once_with(
            ["sudo", "-n", "tee", self.adj_path],
            input="-1000\n",
            capture_output=True,
            text=True,
            timeout=10,
        )

    def test_set_oom_score_adj_reports_privileged_failure(self):
        denied = subprocess.CompletedProcess([], 1, "", "sudo denied proc write")

        with mock.patch.object(scenario, "PROCROOT", self.procroot):
            with mock.patch(
                "builtins.open", side_effect=PermissionError("direct write denied")
            ):
                with mock.patch.object(scenario.subprocess, "run", return_value=denied):
                    with self.assertRaisesRegex(
                        scenario.ScenarioError, "sudo denied proc write"
                    ):
                        scenario._m3_set_oom_score_adj(self.pid, -1000)

    def test_process_oom_metrics_read_kernel_score_and_adjustment(self):
        with open(os.path.join(self.pid_path, "oom_score"), "w") as target:
            target.write("968\n")
        with mock.patch.object(scenario, "PROCROOT", self.procroot):
            metrics = scenario._m3_process_oom_metrics(self.pid)
        self.assertEqual(metrics, {"oom_score": 968, "oom_score_adj": 0})

    def test_process_oom_evidence_includes_pid_and_kernel_metrics(self):
        with open(os.path.join(self.pid_path, "oom_score"), "w") as target:
            target.write("1048\n")
        with open(self.adj_path, "w") as target:
            target.write("500\n")
        with mock.patch.object(scenario, "PROCROOT", self.procroot):
            evidence = scenario._m3_process_oom_evidence(self.pid)
        self.assertEqual(
            evidence,
            {"pid": self.pid, "oom_score": 1048, "oom_score_adj": 500},
        )


class ScenarioDaemonProcessTest(unittest.TestCase):
    def setUp(self):
        self.procroot = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.procroot, True)

    def _proc(self, pid, argv):
        root = os.path.join(self.procroot, str(pid))
        os.makedirs(root)
        with open(os.path.join(root, "cmdline"), "wb") as target:
            target.write(b"\0".join(arg.encode() for arg in argv) + b"\0")
        return root

    def test_daemon_argv_matches_new_entrypoint_and_public_cli(self):
        for argv in (
            ["/usr/bin/python3", "-P", "-m", "taema.daemon_entrypoint"],
            ["/usr/bin/python3", "-P", "-m", "taema", "daemon"],
        ):
            with self.subTest(argv=argv):
                self.assertTrue(scenario._is_taema_daemon_argv(argv))

    def test_daemon_argv_rejects_unrelated_processes_with_daemon_text(self):
        self.assertFalse(scenario._is_taema_daemon_argv(["grep", "taema daemon"]))
        self.assertFalse(
            scenario._is_taema_daemon_argv(
                ["/usr/bin/python3", "-m", "taema.not_daemon"]
            )
        )

    def test_m3_pid_finds_the_daemon_only_module_argv(self):
        self._proc(
            1234,
            ["/usr/bin/python3", "-P", "-m", "taema.daemon_entrypoint"],
        )
        with mock.patch.object(scenario, "PROCROOT", self.procroot):
            self.assertEqual(scenario._m3_daemon_pid(), 1234)


class ScenarioApiTest(unittest.TestCase):
    """Guest-side API: locally testable against temp dirs and real local processes."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.cgroot = os.path.join(self.tmp, "cg")
        self.procroot = os.path.join(self.tmp, "proc")
        os.makedirs(self.cgroot)
        os.makedirs(self.procroot)
        self.tree = None

    def test_replay_fixture_keeps_generic_owners_out_of_active_pairs(self):
        fixture = os.path.join(ROOT, "tests", "fixtures", "learning-v3", "replay.json")
        result = scenario.replay_learning_fixture(
            fixture, os.path.join(self.tmp, "replay")
        )
        self.assertEqual(result["active_generic_owners"], [])
        self.assertGreater(result["stop_count"], 0)
        self.assertEqual(result["stops_without_reason"], 0)
        self.assertGreater(result["reopened_pairs"], 0)

    def tearDown(self):
        if self.tree:
            scenario.kill_tree(self.tree, timeout=5)

    def test_cli_runner_becomes_session_leader(self):
        script = (
            "import json, os, sys; "
            "sys.path.insert(0, sys.argv[1]); import scenario; "
            "before=open('/proc/self/cgroup').read(); "
            "scenario.ensure_session_leader(); "
            "after=open('/proc/self/cgroup').read(); "
            "print(json.dumps({'pid': os.getpid(), 'sid': os.getsid(0), "
            "'before': before, 'after': after}))"
        )
        result = subprocess.run(
            [sys.executable, "-c", script, os.path.dirname(scenario.__file__)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        state = json.loads(result.stdout)
        self.assertEqual(state["sid"], state["pid"])
        self.assertEqual(
            state["after"],
            state["before"],
            "session boundary must preserve login cgroup placement",
        )

    def test_spawn_and_close_root_keeps_children(self):
        work = os.path.join(self.tmp, "work")
        self.tree = scenario.spawn_gui_tree(work, children=2)
        root = self.tree["root"]
        self.assertEqual(os.getsid(root), self.tree["session"])
        self.assertNotEqual(
            root, self.tree["session"], "fixture root must not be a session leader"
        )
        self.assertNotEqual(
            self.tree["session"],
            os.getsid(0),
            "fixture root must have a distinct session",
        )
        self.assertEqual(self.tree["supervisor"], self.tree["session"])
        root_exe = os.path.realpath("/proc/%d/exe" % root)
        child_exe = os.path.realpath("/proc/%d/exe" % self.tree["children"][0])
        self.assertNotEqual(
            root_exe,
            child_exe,
            "root and survivors must not trigger same-exe re-rooting",
        )
        self.assertTrue(os.path.exists(os.path.join(work, "tree.json")))
        for pid in self.tree["children"]:
            self.assertTrue(process_alive(pid))
        scenario.close_root(root, timeout=10)
        self.assertFalse(process_alive(root))
        for pid in self.tree["children"]:
            self.assertTrue(process_alive(pid), "children must survive a root close")

    def test_spawn_gui_tree_accepts_a_distinct_survivor_command(self):
        tail = shutil.which("tail")
        self.assertIsNotNone(tail)
        work = os.path.join(self.tmp, "work-tail")
        self.tree = scenario.spawn_gui_tree(
            work, children=1, child_argv=[tail, "-f", "/dev/null"]
        )
        self.assertEqual(
            os.path.realpath("/proc/%d/exe" % self.tree["children"][0]),
            os.path.realpath(tail),
        )

    def test_daemon_scope_strips_delegated_user_prefix(self):
        self.assertEqual(
            scenario.daemon_scope("user/1001/leftover/firefox-123"),
            "leftover/firefox-123",
        )
        self.assertEqual(
            scenario.daemon_scope("shared/helper-123"), "shared/helper-123"
        )

    def test_wait_for_event_returns_matching_line(self):
        log = os.path.join(self.tmp, "decisions.log")
        with open(log, "w") as f:
            f.write('{"event": "daemon_start"}\n')

        def later():
            time.sleep(0.2)
            with open(log, "a") as f:
                f.write('{"event": "adopt", "scope": "app-x"}\n')

        t = threading.Thread(target=later)
        t.start()
        line = scenario.wait_for_event(log, "adopt", timeout=5, poll=0.05)
        t.join()
        self.assertIn("adopt", line)
        self.assertEqual(json.loads(line)["event"], "adopt")

    def test_wait_for_event_timeout_raises(self):
        log = os.path.join(self.tmp, "decisions.log")
        with open(log, "w") as f:
            f.write('{"event": "daemon_start"}\n')
        with self.assertRaises(scenario.ScenarioError):
            scenario.wait_for_event(log, "auto_stop", timeout=0.3, poll=0.05)

    def test_wait_for_audit_event_matches_scope_and_trigger(self):
        log = os.path.join(self.tmp, "decisions.log")
        with open(log, "w") as f:
            f.write('{"event":"vetoed","trigger":"manual_stop","scope":"scope-x"}\n')
            f.write('{"event":"vetoed","trigger":"owner_exit","scope":"scope-x"}\n')
        event = scenario.wait_for_audit_event(
            log, "vetoed", "scope-x", trigger="owner_exit", timeout=5, poll=0.05
        )
        self.assertEqual(
            (event["event"], event["scope"], event["trigger"]),
            ("vetoed", "scope-x", "owner_exit"),
        )

    def _fake_scope(self, rel, pids):
        d = os.path.join(self.cgroot, rel)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "cgroup.procs"), "w") as f:
            f.write("".join("%d\n" % p for p in pids))
        return d

    def _fake_proc(self, pid, cgpath):
        d = os.path.join(self.procroot, str(pid))
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "cgroup"), "w") as f:
            f.write("0::%s\n" % cgpath)

    def test_scope_of_normalizes_to_cgroot(self):
        self._fake_proc(4242, "/sys/fs/cgroup/user/1000/leftover/o-1")
        rel = scenario.scope_of(4242, cgroot=self.cgroot, procroot=self.procroot)
        self.assertEqual(rel, "user/1000/leftover/o-1")

    def test_assert_scope_member_accepts_member(self):
        self._fake_scope("user/1000/app-a-1", [7, 9])
        self._fake_proc(7, "/sys/fs/cgroup/user/1000/app-a-1")
        rel = scenario.assert_scope_member(
            7, "app-", cgroot=self.cgroot, procroot=self.procroot
        )
        self.assertEqual(rel, "user/1000/app-a-1")

    def test_assert_scope_member_rejects_wrong_pid(self):
        # proc says pid 8 is in the scope, but the scope's cgroup.procs lists 9
        self._fake_scope("user/1000/leftover/o-2", [9])
        self._fake_proc(8, "/sys/fs/cgroup/user/1000/leftover/o-2")
        with self.assertRaises(scenario.ScenarioError):
            scenario.assert_scope_member(
                8, "leftover/", cgroot=self.cgroot, procroot=self.procroot
            )

    def test_assert_scope_member_rejects_wrong_prefix(self):
        self._fake_scope("user/1000/app-b-3", [11])
        self._fake_proc(11, "/sys/fs/cgroup/user/1000/app-b-3")
        with self.assertRaises(scenario.ScenarioError):
            scenario.assert_scope_member(
                11, "leftover/", cgroot=self.cgroot, procroot=self.procroot
            )

    def test_scope_members_lists_procs(self):
        self._fake_scope("user/1000/app-c", [3, 4, 5])
        self.assertEqual(
            scenario.scope_members("user/1000/app-c", cgroot=self.cgroot), [3, 4, 5]
        )

    def test_wait_for_scope(self):
        self._fake_proc(55, "/sys/fs/cgroup/user/1000/app-late")

        def later():
            time.sleep(0.2)
            self._fake_scope("user/1000/app-late", [55])

        t = threading.Thread(target=later)
        t.start()
        rel = scenario.wait_for_scope(
            55,
            ["app-"],
            timeout=5,
            poll=0.05,
            cgroot=self.cgroot,
            procroot=self.procroot,
        )
        t.join()
        self.assertEqual(rel, "user/1000/app-late")

    def test_wait_for_scope_gone_uses_proc_relative_path_and_polls(self):
        rel = "user/1000/scope-exit"
        scope_path = os.path.join(self.cgroot, rel)
        os.makedirs(scope_path)
        self.assertFalse(
            scenario.wait_for_scope_gone(
                rel, timeout=0.05, poll=0.01, cgroot=self.cgroot
            )
        )

        def remove_scope():
            time.sleep(0.1)
            shutil.rmtree(scope_path)

        t = threading.Thread(target=remove_scope)
        t.start()
        self.assertTrue(
            scenario.wait_for_scope_gone(rel, timeout=5, poll=0.01, cgroot=self.cgroot)
        )
        t.join()

    def test_wait_for_scope_timeout_raises(self):
        self._fake_proc(56, "/sys/fs/cgroup")
        with self.assertRaises(scenario.ScenarioError):
            scenario.wait_for_scope(
                56,
                ["leftover/"],
                timeout=0.3,
                poll=0.05,
                cgroot=self.cgroot,
                procroot=self.procroot,
            )

    def test_alive_treats_zombie_as_terminated(self):
        proc_dir = os.path.join(self.procroot, "123")
        os.makedirs(proc_dir)
        with open(os.path.join(proc_dir, "stat"), "w") as f:
            f.write("123 (fixture with ) in name) Z 1 1\n")

        with mock.patch.object(scenario, "PROCROOT", self.procroot):
            with mock.patch.object(scenario.os, "kill") as kill:
                self.assertFalse(scenario._alive(123))
        kill.assert_not_called()

    def test_capture_daemon_logs_copies_available_files(self):
        state = os.path.join(self.tmp, "state")
        os.makedirs(state)
        decisions = os.path.join(state, "decisions.log")
        with open(decisions, "w") as f:
            f.write('{"event": "daemon_start"}\n')
        os.chmod(decisions, 0o600)
        dest = os.path.join(self.tmp, "artifacts")
        copied = scenario.capture_daemon_logs(dest, state_dir=state)
        names = [os.path.basename(p) for p in copied]
        self.assertIn("decisions.log", names)
        self.assertEqual(
            os.stat(os.path.join(dest, "decisions.log")).st_mode & 0o777, 0o644
        )
        with open(os.path.join(dest, "decisions.log")) as f:
            self.assertIn("daemon_start", f.read())
        # missing files are tolerated
        shutil.rmtree(state)
        scenario.capture_daemon_logs(
            os.path.join(self.tmp, "artifacts2"), state_dir=state
        )

    def test_capture_daemon_logs_copies_privileged_files_and_skips_locks(self):
        state = os.path.join(self.tmp, "state")
        extra = os.path.join(self.tmp, "logs")
        os.makedirs(state)
        os.makedirs(extra)
        with open(os.path.join(state, "decisions.log"), "w") as f:
            f.write('{"event": "daemon_start"}\n')
        with open(os.path.join(extra, "current"), "w") as f:
            f.write("daemon log\n")
        with open(os.path.join(extra, "lock"), "w") as f:
            f.write("not a useful log\n")

        def privileged(argv, timeout=60):
            if argv[0] == "find":
                files = [os.path.join(extra, name) for name in ("current",)]
                return subprocess.CompletedProcess(argv, 0, "\0".join(files) + "\0", "")
            self.assertEqual(argv[:3], ["install", "-m", "0644"])
            shutil.copyfile(argv[3], argv[4])
            os.chmod(argv[4], 0o644)
            return subprocess.CompletedProcess(argv, 0, "", "")

        dest = os.path.join(self.tmp, "artifacts")
        with mock.patch.object(
            scenario, "run_privileged", side_effect=privileged
        ) as run:
            copied = scenario.capture_daemon_logs(
                dest, state_dir=state, extra_dirs=(extra,)
            )

        self.assertIn(os.path.join(dest, "logs", "current"), copied)
        self.assertFalse(os.path.exists(os.path.join(dest, "logs", "lock")))
        self.assertEqual(
            os.stat(os.path.join(dest, "logs", "current")).st_mode & 0o777, 0o644
        )
        self.assertEqual(
            [call.args[0][0] for call in run.call_args_list], ["find", "install"]
        )

    def test_wait_for_auto_status_retries_until_daemon_is_ready(self):
        unavailable = subprocess.CompletedProcess([], 1, "", "daemon not running")
        ready = subprocess.CompletedProcess([], 0, '{"mode": "auto"}', "")
        with mock.patch.object(
            scenario, "_run", side_effect=[unavailable, ready]
        ) as run:
            result, attempts = scenario.wait_for_auto_status(timeout=1, poll=0)
        self.assertEqual(attempts, 2)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(run.call_count, 2)

    def test_run_privileged_uses_sudo_n(self):
        stub = os.path.join(self.tmp, "bin")
        os.makedirs(stub, exist_ok=True)
        log = os.path.join(self.tmp, "sudo.log")
        with open(os.path.join(stub, "sudo"), "w") as f:
            f.write('#!/bin/sh\nprintf \'%%s\\n\' "$*" > "%s"\nexit 0\n' % log)
        os.chmod(os.path.join(stub, "sudo"), 0o755)
        old = os.environ.get("PATH", "")
        os.environ["PATH"] = stub + os.pathsep + old
        try:
            scenario.run_privileged(["/usr/bin/true", "--flag"])
        finally:
            os.environ["PATH"] = old
        with open(log) as f:
            self.assertEqual(f.read().strip(), "-n /usr/bin/true --flag")

    def test_kill_tree_terminates_everyone(self):
        work = os.path.join(self.tmp, "work2")
        tree = scenario.spawn_gui_tree(work, children=2)
        scenario.kill_tree(tree, timeout=10)
        self.assertFalse(process_alive(tree["root"]))
        for pid in tree["children"]:
            self.assertFalse(process_alive(pid))


def process_alive(pid):
    return scenario._alive(pid)


class ProvisionScriptTest(unittest.TestCase):
    """provision.sh refusal paths; all of them exit before any setup step."""

    def run_provision(self, *args):
        return subprocess.run(
            ["sh", os.path.join(VM_DIR, "provision.sh")] + list(args),
            capture_output=True,
            text=True,
        )

    def test_no_arguments_is_usage_error(self):
        r = self.run_provision()
        self.assertEqual(r.returncode, 2)
        self.assertIn("usage:", r.stderr)

    def test_unknown_argument_rejected(self):
        r = self.run_provision("--frobnicate")
        self.assertEqual(r.returncode, 2)
        self.assertIn("unknown argument", r.stderr)

    def test_missing_package_dir_fails_before_any_setup(self):
        user = "taemavmprovnobody"
        r = self.run_provision(
            "--package-dir",
            "/nonexistent/taema-repo",
            "--user",
            user,
            "--authorized-key",
            "/nonexistent/taema-authorized-key",
        )
        self.assertEqual(r.returncode, 1)
        self.assertIn("no such package dir", r.stderr)
        # the refusal happens before useradd: the host user list is untouched
        probe = subprocess.run(["id", "-u", user], capture_output=True, text=True)
        self.assertNotEqual(
            probe.returncode, 0, "provision.sh must refuse before creating users"
        )

    def test_script_installs_the_test_user_key_with_strict_permissions(self):
        script = read_text(os.path.join(VM_DIR, "provision.sh"))
        self.assertIn('install -d -m 700 -o "$uid" -g "$gid" "$user_home/.ssh"', script)
        self.assertIn('install -m 600 -o "$uid" -g "$gid" "$AUTHORIZED_KEY"', script)
        self.assertIn('"$user_home/.ssh/authorized_keys"', script)
        self.assertIn(
            'install -d -m 755 -o "$uid" -g "$gid" "$GUEST_TMP/artifacts"', script
        )


class ScenarioCliParsingTest(unittest.TestCase):
    """scenario.py argument handling: usage errors before anything runs."""

    def _usage_error(self, argv):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as cm:
                scenario.main(argv)
        return cm.exception.code

    def test_missing_artifacts_is_usage_error(self):
        self.assertEqual(self._usage_error(["smoke"]), 2)

    def test_unknown_scenario_is_usage_error(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        self.assertEqual(self._usage_error(["wipe", "--artifacts", tmp]), 2)

    def test_non_integer_timeout_is_usage_error(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        self.assertEqual(
            self._usage_error(["smoke", "--artifacts", tmp, "--timeout", "soon"]), 2
        )


class ScriptSyntaxTest(unittest.TestCase):
    def test_sh_n(self):
        for rel in ("tools/vm/provision.sh", "tools/vm/mkimage.sh", "tools/vm/vmh"):
            with self.subTest(script=rel):
                r = subprocess.run(
                    ["sh", "-n", os.path.join(ROOT, rel)],
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(r.returncode, 0, r.stderr)

    def test_python_compiles(self):
        for rel in ("tools/vm/vmh.py", "tools/vm/scenario.py"):
            with self.subTest(script=rel):
                r = subprocess.run(
                    ["python3", "-m", "py_compile", os.path.join(ROOT, rel)],
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(r.returncode, 0, r.stderr)


class ScenarioResultTest(unittest.TestCase):
    def test_write_result_schema(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        rec = scenario.ResultRecorder("smoke", artifacts=tmp)
        rec.step("spawn", True, "root=1")
        rec.step("close", True, "")
        path = rec.finish(ok=True)
        with open(path) as f:
            data = json.load(f)
        self.assertEqual(data["scenario"], "smoke")
        self.assertTrue(data["ok"])
        self.assertEqual([s["name"] for s in data["steps"]], ["spawn", "close"])
        self.assertTrue(all("ok" in s for s in data["steps"]))


class StopAuditEventTest(unittest.TestCase):
    def test_matches_pid_in_decisions_and_legacy_pid_list(self):
        self.assertTrue(
            scenario.audit_stopped_pid(
                {"event": "stop", "decisions": [{"pid": 42, "action": "kill"}]},
                42,
            )
        )
        self.assertTrue(scenario.audit_stopped_pid({"event": "stop", "pids": [42]}, 42))
        self.assertFalse(
            scenario.audit_stopped_pid(
                {"event": "stop", "decisions": [{"pid": 43, "action": "kill"}]},
                42,
            )
        )


if __name__ == "__main__":
    unittest.main()
