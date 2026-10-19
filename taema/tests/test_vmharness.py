"""Disposable Void VM harness: config, plans, refusals, and the guest scenario API."""
import contextlib
import importlib.util
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
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

ALL_TOOLS = sorted({"qemu", "qemu_img", "ssh", "scp", "ssh_keygen", "mke2fs",
                    "make", "xbps_create", "xbps_rindex", "tar", "unshare"})
TOOL_NAMES = {"qemu": "qemu-system-x86_64", "qemu_img": "qemu-img",
              "xbps_create": "xbps-create", "xbps_rindex": "xbps-rindex"}


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

    def write_config(self, libcs=None, scenarios=None, glibc_sha=None):
        lines = ['libcs = [%s]' % ", ".join('"%s"' % c for c in (libcs or ["glibc", "musl"])),
                 'scenarios = [%s]' % ", ".join('"%s"' % s for s in (scenarios or ["smoke"])),
                 'accel = "auto"', "memory_mb = 1024", "cpus = 1",
                 "boot_timeout_s = 5", "scenario_timeout_s = 5",
                 'test_user = "taematest"',
                 '[paths]',
                 'state_dir = "%s"' % self.state,
                 'package_repo = "build/repo"',
                 "[tools]"]
        for key, path in sorted(self.tools.items()):
            lines.append('%s = "%s"' % (key, path))
        lines += [
            "",
            "[images]",
            'base_url = "https://repo-default.voidlinux.org/live/current"',
            'previous_url = "https://github.com/Bongbetic/taema/releases/download/'
            'taema-v0.2.1/taema-0.2.1_1.noarch.xbps"',
            "",
            "[images.glibc]",
            'tarball = "void-x86_64-ROOTFS-20250202.tar.xz"',
            'sha256 = "%s"' % (glibc_sha or
                               "3f48e6673ac5907a897d913c97eb96edbfb230162731b4016562c51b3b8f1876"),
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
        code, out, err = self.run_main("fetch", "--config", self.write_config(),
                                       "--state-dir", self.state)
        self.assertEqual(code, 2)
        self.assertIn("--allow-network", err)
        self.assertFalse(os.path.exists(self.state))

    def test_run_refused_without_cached_images(self):
        code, out, err = self.run_main("run", "--config", self.write_config(),
                                       "--state-dir", self.state)
        self.assertEqual(code, 2)
        self.assertIn("--allow-network", err)
        self.assertFalse(os.path.exists(self.state))

    def test_run_refused_when_prerequisite_missing(self):
        self.tools = stub_tools(self.bindir, skip=("qemu",))
        path = self.write_config()
        code, out, err = self.run_main("run", "--config", path, "--state-dir", self.state)
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
        self.assertTrue(nic.startswith("user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:"))

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
        self.assertEqual(plan["package"]["path"],
                         os.path.join(ROOT, "build", "repo",
                                      "taema-%s_1.noarch.xbps" % vmh.read_version(ROOT)))
        self.assertEqual(plan["package"]["argv"],
                         ["sh", vmh.BUILD_XBPS, vmh.package_repo_dir(self.cfg)])

    def test_plan_package_repo_can_be_outside_the_worktree(self):
        repo = os.path.join(self.tmp, "external-package-repo")
        self.cfg["paths"]["package_repo"] = repo
        plan = vmh.build_plan(self.cfg, kvm=False)
        self.assertEqual(plan["package"]["path"],
                         os.path.join(repo, "taema-%s_1.noarch.xbps"
                                      % vmh.read_version(ROOT)))
        self.assertEqual(plan["package"]["argv"], ["sh", vmh.BUILD_XBPS, repo])

    def test_plan_bootstraps_test_user_ssh_key(self):
        pub = vmh.ssh_key_paths(self.cfg)[1]
        steps = vmh.build_plan(self.cfg, libcs=["glibc"], kvm=False)["vms"][0]["steps"]
        bootstrap = next(step for step in steps if step["name"] == "scp-bootstrap")
        provision = next(step for step in steps if step["name"] == "provision")
        self.assertIn(pub, bootstrap["argv"])
        self.assertIn("--authorized-key /tmp/taema-vm/id_ed25519.pub",
                      provision["argv"][-1])

    def test_plan_step_order(self):
        plan = vmh.build_plan(self.cfg, libcs=["glibc"],
                              scenarios=["smoke", "m0", "upgrade", "remove"], kvm=False)
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

    def test_plan_network_inputs_listed(self):
        plan = vmh.build_plan(self.cfg, scenarios=["upgrade"], kvm=False)
        urls = plan["network"]["urls"]
        self.assertTrue(any("ROOTFS" in u for u in urls))
        self.assertTrue(any("taema-" in u for u in urls))


class DryRunTest(VmTestCase):
    def test_dry_run_prints_plan_without_side_effects(self):
        path = self.write_config(scenarios=["smoke", "m0"])
        code, out, err = self.run_main("run", "--dry-run", "--config", path,
                                       "--state-dir", self.state, "--tcg")
        self.assertEqual(code, 0, err)
        self.assertIn("qemu-system", out)
        self.assertIn("-accel tcg", out)
        self.assertIn("glibc", out)
        self.assertIn("musl", out)
        self.assertIn("scenario:smoke", out)
        self.assertIn("scenario:m0", out)
        self.assertFalse(os.path.exists(self.state), "dry run must not create the state dir")


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
        self.assertEqual(argv[-4:], ["sh", os.path.join(VM_DIR, "mkimage.sh"),
                                     rootfs, pub])

    def test_mkimage_script_never_mounts_proc_itself(self):
        self.assertNotIn("mount -t proc", self.script)

    def test_mkimage_enables_services_in_durable_default_runlevel(self):
        # /var/service points into /run (tmpfs), so enablement links must be
        # written under /etc/runit/runsvdir/default to survive guest boots
        self.assertIn('mkdir -p "$R/etc/runit/runsvdir/default"', self.script)
        self.assertIn('ln -sf /etc/sv/sshd "$R/etc/runit/runsvdir/default/sshd"',
                      self.script)
        self.assertIn('ln -sf /etc/sv/dhcpcd "$R/etc/runit/runsvdir/default/dhcpcd"',
                      self.script)
        self.assertIn("openssh dhcpcd python3 iproute2 sudo dbus elogind",
                      self.script)
        self.assertIn('ln -sf /etc/sv/dbus "$R/etc/runit/runsvdir/default/dbus"',
                      self.script)
        self.assertIn('ln -sf /etc/sv/elogind "$R/etc/runit/runsvdir/default/elogind"',
                      self.script)

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
        self.assertIn("env -u TMPDIR -u XBPS_ROOT -u XBPS_ARCH -u XBPS_TARGET_ARCH",
                      self.script)

    def test_mkimage_fixup_preserves_setuid_bits_across_chown(self):
        # chown clears set-user-ID/set-group-ID bits (POSIX); without a
        # restore pass sudo refuses to run and provisioning dies with
        # "sudo: /usr/bin/sudo must be owned by uid 0 and have the setuid bit"
        # (observed on the reference machine's first live provision step)
        self.assertIn("-perm -4000", self.script)          # snapshot selector
        self.assertIn("-perm -2000", self.script)          # setgid too
        self.assertIn("chmod 4755 /usr/bin/sudo /usr/bin/su", self.script)
        # snapshot before chown, restore after it
        self.assertLess(self.script.index("-perm -4000"),
                        self.script.index("chown -R 0:0"))
        self.assertLess(self.script.index("chown -R 0:0"),
                        self.script.index("done < /etc/vmh-suid.bak"))


class TransportTest(VmTestCase):
    """SSH/SCP command generation: recursive copies, loopback, private hosts."""

    def setUp(self):
        super().setUp()
        self.cfg = vmh.load_config(self.write_config())

    def test_scp_transfers_are_recursive(self):
        # bootstrap copies the package repository directory and collect
        # copies the artifacts directory; scp refuses directories without -r
        argv = vmh.scp_argv(self.cfg, 2222, "/k", "/kh",
                            [os.path.join(VM_DIR, "provision.sh")],
                            "vmadmin@127.0.0.1:/tmp/taema-vm/")
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
        self.cfg_path = self.write_config(libcs=["glibc"], scenarios=["smoke"])
        self.cfg = vmh.load_config(self.cfg_path)
        self.stub_tool("qemu", "#!/bin/sh\nexec sleep 60\n")
        self.stub_tool("qemu_img", "#!/bin/sh\nexit 0\n")
        self.stub_tool("scp", "#!/bin/sh\nexit 0\n")
        self.fail_marker = os.path.join(self.tmp, "fail-scenario")
        self.stub_tool(
            "ssh",
            "#!/bin/sh\n"
            'case "$*" in *scenario.py*) [ -f "%s" ] && exit 1 ;; esac\n'
            "exit 0\n" % self.fail_marker)
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
        return vmh.main(["run", "--config", self.cfg_path,
                         "--state-dir", self.state, "--tcg", "--no-build",
                         "--libc", "glibc"], out=self.out, err=self.err)

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
        for rel in ("qemu.log", "logs/provision.log", "logs/scenario-smoke.log",
                    "logs/collect.log"):
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
            os.path.isfile(os.path.join(run_dir, "logs/scenario-smoke.log")))
        # a failed scenario must not skip artifact collection
        self.assertTrue(os.path.isfile(os.path.join(run_dir, "logs/collect.log")))


class HarnessCliParsingTest(VmTestCase):
    def test_parse_scenarios_all(self):
        self.assertEqual(vmh.parse_scenarios("all"), ["smoke", "m0", "upgrade", "remove"])

    def test_m0_acceptance_is_a_registered_guest_scenario(self):
        self.assertIn("m0", vmh.SCENARIOS)
        self.assertIn("m0", scenario.SCENARIOS)

    def test_parse_libcs(self):
        self.assertEqual(vmh.parse_libcs("glibc, musl"), ["glibc", "musl"])

    def test_previous_version_derived_from_default_config(self):
        self.assertEqual(vmh.previous_version(vmh.load_config()), "0.2.1")

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
        self.assertEqual(vmh.read_version(ROOT), "0.3.0")

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
        self.assertIn("never", docs)          # host-safety guarantees section
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
        self.assertIn('XBPS_ARCH=x86_64-musl xbps-rindex -f -a '
                      '"$repo/$pkg.noarch.xbps"', script)

    def test_workflow_is_opt_in_kvm_only_and_uploads_artifacts(self):
        wf = read_text(os.path.join(REPO, ".github", "workflows", "vm-harness.yml"))
        self.assertIn("workflow_dispatch", wf)
        self.assertNotIn("  push:", wf)  # never auto-runs without KVM
        self.assertIn("kvm", wf)
        self.assertIn('default: "smoke,m0"', wf)
        self.assertIn("timeout-minutes: 180", wf)
        self.assertIn("upload-artifact", wf)
        self.assertNotIn("continue-on-error", wf)


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
            capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        state = json.loads(result.stdout)
        self.assertEqual(state["sid"], state["pid"])
        self.assertEqual(state["after"], state["before"],
                         "session boundary must preserve login cgroup placement")

    def test_spawn_and_close_root_keeps_children(self):
        work = os.path.join(self.tmp, "work")
        self.tree = scenario.spawn_gui_tree(work, children=2)
        root = self.tree["root"]
        self.assertEqual(os.getsid(root), self.tree["session"])
        self.assertNotEqual(root, self.tree["session"],
                            "fixture root must not be a session leader")
        self.assertNotEqual(self.tree["session"], os.getsid(0),
                            "fixture root must have a distinct session")
        self.assertEqual(self.tree["supervisor"], self.tree["session"])
        root_exe = os.path.realpath("/proc/%d/exe" % root)
        child_exe = os.path.realpath("/proc/%d/exe" % self.tree["children"][0])
        self.assertNotEqual(root_exe, child_exe,
                            "root and survivors must not trigger same-exe re-rooting")
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
            work, children=1, child_argv=[tail, "-f", "/dev/null"])
        self.assertEqual(os.path.realpath("/proc/%d/exe" % self.tree["children"][0]),
                         os.path.realpath(tail))

    def test_daemon_scope_strips_delegated_user_prefix(self):
        self.assertEqual(scenario.daemon_scope("user/1001/leftover/firefox-123"),
                         "leftover/firefox-123")
        self.assertEqual(scenario.daemon_scope("shared/helper-123"), "shared/helper-123")

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
            f.write('{"event":"vetoed","trigger":"manual_stop",'
                    '"scope":"scope-x"}\n')
            f.write('{"event":"vetoed","trigger":"owner_exit",'
                    '"scope":"scope-x"}\n')
        event = scenario.wait_for_audit_event(
            log, "vetoed", "scope-x", trigger="owner_exit", timeout=5, poll=0.05)
        self.assertEqual((event["event"], event["scope"], event["trigger"]),
                         ("vetoed", "scope-x", "owner_exit"))

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
        rel = scenario.assert_scope_member(7, "app-", cgroot=self.cgroot,
                                           procroot=self.procroot)
        self.assertEqual(rel, "user/1000/app-a-1")

    def test_assert_scope_member_rejects_wrong_pid(self):
        # proc says pid 8 is in the scope, but the scope's cgroup.procs lists 9
        self._fake_scope("user/1000/leftover/o-2", [9])
        self._fake_proc(8, "/sys/fs/cgroup/user/1000/leftover/o-2")
        with self.assertRaises(scenario.ScenarioError):
            scenario.assert_scope_member(8, "leftover/", cgroot=self.cgroot,
                                         procroot=self.procroot)

    def test_assert_scope_member_rejects_wrong_prefix(self):
        self._fake_scope("user/1000/app-b-3", [11])
        self._fake_proc(11, "/sys/fs/cgroup/user/1000/app-b-3")
        with self.assertRaises(scenario.ScenarioError):
            scenario.assert_scope_member(11, "leftover/", cgroot=self.cgroot,
                                         procroot=self.procroot)

    def test_scope_members_lists_procs(self):
        self._fake_scope("user/1000/app-c", [3, 4, 5])
        self.assertEqual(scenario.scope_members("user/1000/app-c", cgroot=self.cgroot),
                         [3, 4, 5])

    def test_wait_for_scope(self):
        self._fake_proc(55, "/sys/fs/cgroup/user/1000/app-late")
        def later():
            time.sleep(0.2)
            self._fake_scope("user/1000/app-late", [55])
        t = threading.Thread(target=later)
        t.start()
        rel = scenario.wait_for_scope(55, ["app-"], timeout=5, poll=0.05,
                                      cgroot=self.cgroot, procroot=self.procroot)
        t.join()
        self.assertEqual(rel, "user/1000/app-late")

    def test_wait_for_scope_timeout_raises(self):
        self._fake_proc(56, "/sys/fs/cgroup")
        with self.assertRaises(scenario.ScenarioError):
            scenario.wait_for_scope(56, ["leftover/"], timeout=0.3, poll=0.05,
                                    cgroot=self.cgroot, procroot=self.procroot)

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
        self.assertEqual(os.stat(os.path.join(dest, "decisions.log")).st_mode & 0o777, 0o644)
        with open(os.path.join(dest, "decisions.log")) as f:
            self.assertIn("daemon_start", f.read())
        # missing files are tolerated
        shutil.rmtree(state)
        scenario.capture_daemon_logs(os.path.join(self.tmp, "artifacts2"), state_dir=state)

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
        with mock.patch.object(scenario, "run_privileged", side_effect=privileged) as run:
            copied = scenario.capture_daemon_logs(dest, state_dir=state,
                                                  extra_dirs=(extra,))

        self.assertIn(os.path.join(dest, "logs", "current"), copied)
        self.assertFalse(os.path.exists(os.path.join(dest, "logs", "lock")))
        self.assertEqual(os.stat(os.path.join(dest, "logs", "current")).st_mode & 0o777, 0o644)
        self.assertEqual([call.args[0][0] for call in run.call_args_list], ["find", "install"])

    def test_wait_for_auto_status_retries_until_daemon_is_ready(self):
        unavailable = subprocess.CompletedProcess([], 1, "", "daemon not running")
        ready = subprocess.CompletedProcess([], 0, '{"mode": "auto"}', "")
        with mock.patch.object(scenario, "_run", side_effect=[unavailable, ready]) as run:
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
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


class ProvisionScriptTest(unittest.TestCase):
    """provision.sh refusal paths; all of them exit before any setup step."""

    def run_provision(self, *args):
        return subprocess.run(
            ["sh", os.path.join(VM_DIR, "provision.sh")] + list(args),
            capture_output=True, text=True)

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
        r = self.run_provision("--package-dir", "/nonexistent/taema-repo",
                               "--user", user, "--authorized-key",
                               "/nonexistent/taema-authorized-key")
        self.assertEqual(r.returncode, 1)
        self.assertIn("no such package dir", r.stderr)
        # the refusal happens before useradd: the host user list is untouched
        probe = subprocess.run(["id", "-u", user], capture_output=True, text=True)
        self.assertNotEqual(probe.returncode, 0,
                            "provision.sh must refuse before creating users")

    def test_script_installs_the_test_user_key_with_strict_permissions(self):
        script = read_text(os.path.join(VM_DIR, "provision.sh"))
        self.assertIn('install -d -m 700 -o "$uid" -g "$gid" "$user_home/.ssh"',
                      script)
        self.assertIn('install -m 600 -o "$uid" -g "$gid" "$AUTHORIZED_KEY"',
                      script)
        self.assertIn('"$user_home/.ssh/authorized_keys"', script)
        self.assertIn('install -d -m 755 -o "$uid" -g "$gid" '
                      '"$GUEST_TMP/artifacts"', script)


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
            self._usage_error(["smoke", "--artifacts", tmp, "--timeout", "soon"]), 2)


class ScriptSyntaxTest(unittest.TestCase):
    def test_sh_n(self):
        for rel in ("tools/vm/provision.sh", "tools/vm/mkimage.sh", "tools/vm/vmh"):
            with self.subTest(script=rel):
                r = subprocess.run(["sh", "-n", os.path.join(ROOT, rel)],
                                   capture_output=True, text=True)
                self.assertEqual(r.returncode, 0, r.stderr)

    def test_python_compiles(self):
        for rel in ("tools/vm/vmh.py", "tools/vm/scenario.py"):
            with self.subTest(script=rel):
                r = subprocess.run(["python3", "-m", "py_compile", os.path.join(ROOT, rel)],
                                   capture_output=True, text=True)
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


if __name__ == "__main__":
    unittest.main()
