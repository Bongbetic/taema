import importlib.machinery
import importlib.util
import errno
import os
import tempfile
import unittest
from unittest import mock

from taema.core import cgroup
from taema.config import policy

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SYSTEM_TOML = os.path.join(ROOT, "etc", "taema.toml")


def load_helper():
    path = os.path.join(ROOT, "libexec", "taema-attach")
    loader = importlib.machinery.SourceFileLoader("taema_attach", path)
    spec = importlib.util.spec_from_loader("taema_attach", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def neutral(comm="catatonit", cg="/2", env=None):
    """Patch a fake process owned by the caller, so one rule at a time can be tested."""
    return [
        mock.patch.object(policy.inspect, "uid_of", return_value=os.getuid()),
        mock.patch.object(policy.inspect, "is_kernel_thread", return_value=False),
        mock.patch.object(policy.inspect, "comm", return_value=comm),
        mock.patch.object(policy.inspect, "environ", return_value=env or {}),
        mock.patch.object(policy.cgroup, "proc_cgroup", return_value=cg),
    ]


class Patched:
    def __init__(self, patches):
        self.patches = patches

    def __enter__(self):
        for p in self.patches:
            p.start()

    def __exit__(self, *a):
        for p in self.patches:
            p.stop()


class CgroupTests(unittest.TestCase):
    def test_valid_rel(self):
        for ok in ("scope-x", "app-claude-desktop/session-12", "shared/adb-5"):
            self.assertTrue(cgroup.valid_rel(ok), ok)
        for bad in (
            "",
            "..",
            "a/../b",
            "a//b",
            "/abs",
            "A",
            "a/",
            "-x",
            "a b",
            "./x",
            "x/.",
        ):
            self.assertFalse(cgroup.valid_rel(bad), bad)

    def test_prefix_guard(self):
        t = cgroup.CG + "/user/1000/app-claude-desktop"
        self.assertTrue(cgroup.is_prefix(t, "/user/1000/app-claude-desktop"))
        self.assertTrue(cgroup.is_prefix(t, "/user/1000/app-claude-desktop/session-9"))
        self.assertFalse(cgroup.is_prefix(t, "/user/1000/app-claude-desktop-2"))
        self.assertFalse(cgroup.is_prefix(t, "/2"))
        self.assertFalse(cgroup.is_prefix(t, None))

    def test_move_reports_missing_process_and_propagates_other_errors(self):
        with mock.patch(
            "builtins.open", side_effect=OSError(errno.ESRCH, "process gone")
        ):
            self.assertFalse(cgroup.move(42, "/fake/scope"))
        with mock.patch(
            "builtins.open", side_effect=OSError(errno.EPERM, "permission denied")
        ):
            with self.assertRaises(OSError):
                cgroup.move(42, "/fake/scope")

    def test_rmdir_tree_removes_empty_descendants(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = os.path.join(temporary, "scope")
            nested = os.path.join(root, "child", "leaf")
            os.makedirs(nested)
            cgroup.rmdir_tree(root)
            self.assertFalse(os.path.exists(root))


class ConfigTests(unittest.TestCase):
    def cfg(self):
        return policy.load_config(SYSTEM_TOML)

    def test_default_config_loads_and_mode_is_valid(self):
        cfg = self.cfg()
        self.assertIn(
            cfg["mode"], policy.MODES
        )  # the shipped file picks the mode (auto)
        self.assertEqual(cfg["paths"]["session_cgroup"], "auto")
        self.assertEqual(
            cfg["paths"]["socket"], "/run/user/%d/taema.sock" % os.getuid()
        )
        self.assertEqual(cfg["paths"]["helper"], "/usr/libexec/taema/taema-attach")

    def test_user_layer_can_add_but_not_remove_protected(self):
        system = {
            "mode": "observe",
            "protected": {
                "comm": ["niri", "pipewire"],
                "env_prefix": {"XDG_RUNTIME_DIR": ["/run/a"]},
            },
            "timers": {"idle_grace": 600},
        }
        user = {
            "mode": "enforce",
            "protected": {
                "comm": ["myshell"],
                "env_prefix": {"XDG_RUNTIME_DIR": ["/run/b"]},
            },
            "timers": {"idle_grace": 60},
        }
        m = policy.merge(system, user)
        self.assertEqual(m["mode"], "enforce")
        self.assertEqual(m["timers"]["idle_grace"], 60)
        self.assertEqual(m["protected"]["comm"], ["niri", "pipewire", "myshell"])
        self.assertEqual(
            m["protected"]["env_prefix"]["XDG_RUNTIME_DIR"], ["/run/a", "/run/b"]
        )
        # an empty user list does not clear the system list
        self.assertEqual(
            policy.merge(system, {"protected": {"comm": []}})["protected"]["comm"],
            ["niri", "pipewire"],
        )

    def test_layered_load(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "taema"))
            with open(os.path.join(d, "taema", "taema.toml"), "w") as f:
                f.write('mode = "adopt"\n[protected]\ncomm = ["extra"]\n')
            with (
                mock.patch.object(policy, "SYSTEM_CONFIG", SYSTEM_TOML),
                mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": d}),
                mock.patch.dict(os.environ, {}, clear=False),
            ):
                os.environ.pop("TAEMA_CONFIG", None)
                cfg = policy.load_config()
        self.assertEqual(cfg["mode"], "adopt")
        self.assertIn("extra", cfg["protected"]["comm"])
        self.assertIn("niri", cfg["protected"]["comm"])
        self.assertEqual(len(cfg["_sources"]), 2)

    def test_bad_mode_rejected(self):
        with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as f:
            f.write('mode = "yolo"\n')
        try:
            with self.assertRaises(ValueError):
                policy.load_config(f.name)
        finally:
            os.unlink(f.name)

    def test_load_config_defaults_the_learner_section(self):
        cfg = self.cfg()
        self.assertEqual(cfg["learner"]["deny_owners"], [])
        self.assertEqual(policy.timer(cfg, "leftover_expire_days", 0), 0)

    def test_user_layer_extends_learner_deny_owners(self):
        system = {"learner": {"deny_owners": ["a"]}}
        user = {"learner": {"deny_owners": ["b", "a"]}}
        m = policy.merge(system, user)
        self.assertEqual(m["learner"]["deny_owners"], ["a", "b"])
        # an empty user list never clears the system list
        self.assertEqual(
            policy.merge(system, {"learner": {"deny_owners": []}})["learner"][
                "deny_owners"
            ],
            ["a"],
        )


class OwnerDenylist(unittest.TestCase):
    """Names that must never own a learned pair (ticket #6, acceptance criteria 1 and 2)."""

    def test_each_rejected_class(self):
        cases = [
            ("MainThread", "generic"),
            ("Thread-1", "generic"),
            ("pool-3", "generic"),
            ("GC", "generic"),
            ("Finalizer", "generic"),
            ("3.12", "digit"),
            ("2024.1", "digit"),
            ("sh", "shell"),
            ("bash", "shell"),
            ("dash", "shell"),
            ("zsh", "shell"),
            ("fish", "shell"),
            ("bash:deploy.sh", "shell"),
            ("sleep", "trivial"),
            ("cat", "trivial"),
            ("head", "trivial"),
            ("sort", "trivial"),
            ("grep", "trivial"),
            ("true", "trivial"),
            ("python3", "script"),
            ("python3.12", "script"),
            ("node", "script"),
            ("java", "script"),
            ("perl", "script"),
            ("", "empty"),
            (None, "empty"),
        ]
        for key, why in cases:
            reason = policy.bad_owner(key)
            self.assertIsNotNone(reason, repr(key))
            self.assertIn(why, reason, repr(key))

    def test_plausible_application_names_pass(self):
        for ok in (
            "npm",
            "firefox",
            "code",
            "own0",
            "vite",
            "MainThreadly",
            "node:vite.js",
            "python3:http.server",
            "java:com.Main",
            "zsh-job",
        ):
            self.assertIsNone(policy.bad_owner(ok), ok)

    def test_configured_entries_extend_the_defaults(self):
        self.assertIsNone(policy.bad_owner("gpu-render"))
        self.assertIn("denied", policy.bad_owner("gpu-render", ["gpu-*"]))
        self.assertIsNone(
            policy.bad_owner("gpurender", ["gpu-*"])
        )  # only matching entries reject
        self.assertIsNotNone(
            policy.bad_owner("MainThread", ["gpu-*"])
        )  # the defaults still apply
        self.assertIsNotNone(policy.bad_owner("Thread-1", ["gpu-*"]))

    def test_owner_deny_reads_the_learner_section(self):
        self.assertEqual(policy.owner_deny(None), [])
        self.assertEqual(policy.owner_deny({}), [])
        self.assertEqual(
            policy.owner_deny({"learner": {"deny_owners": ["gpu-*"]}}), ["gpu-*"]
        )


class PolicyTests(unittest.TestCase):
    def cfg(self, **protected):
        cfg = policy.load_config(SYSTEM_TOML)
        cfg["protected"].update(protected)
        return cfg

    def test_shipped_runtime_units_define_memory_and_quit_detection(self):
        units = policy.load_units(
            {"paths": {"units_dir": os.path.join(ROOT, "etc", "units")}}
        )
        by_name = {unit["unit"]["name"]: unit for unit in units}
        podman = by_name["app-podman"]
        libvirt = by_name["app-libvirt-qemu"]

        self.assertEqual(podman["unit"]["class"], "container")
        self.assertEqual(podman["mem"]["idle_reclaim"], True)
        self.assertEqual(podman["gc"]["no_attach_grace"], 120)
        self.assertEqual(libvirt["unit"]["class"], "vm")
        self.assertEqual(libvirt["match"]["comm"], "qemu-system-*")
        self.assertTrue(libvirt["unit"]["group_by_qmp"])
        self.assertTrue(libvirt["gc"]["qmp_socket"])
        self.assertEqual(libvirt["gc"]["no_attach_grace"], 120)
        self.assertFalse(self.cfg()["mem"]["probe"])

    def test_protected_comm_and_pid1_and_root(self):
        cfg = self.cfg()
        with Patched(neutral(comm="niri")):
            self.assertIn("protected comm", policy.protected_reason(1234, cfg))
        self.assertEqual(policy.protected_reason(1, cfg), "pid 1")
        with mock.patch.object(policy.inspect, "uid_of", return_value=0):
            self.assertIn("not owned", policy.protected_reason(4321, cfg))

    def test_comm_globs(self):
        cfg = self.cfg()
        with Patched(neutral(comm="gvfsd-trash")):
            self.assertIn("protected comm", policy.protected_reason(1234, cfg))
        with Patched(neutral(comm="catatonit")):
            self.assertIsNone(policy.protected_reason(1234, cfg))

    def test_cgroup_prefix(self):
        cfg = self.cfg(cgroup_prefix=["/sys/fs/cgroup/other"])
        with Patched(neutral(cg="/other/1000/x")):
            self.assertIn("protected cgroup", policy.protected_reason(4242, cfg))
        with Patched(neutral(cg="/otherwise/x")):
            self.assertIsNone(policy.protected_reason(4242, cfg))

    def test_env_prefix(self):
        cfg = self.cfg(env_prefix={"XDG_RUNTIME_DIR": ["/run/mytool"]})
        with Patched(neutral(env={"XDG_RUNTIME_DIR": "/run/mytool/1000"})):
            self.assertIn("protected env", policy.protected_reason(4242, cfg))
        with Patched(neutral(env={"XDG_RUNTIME_DIR": "/run/mytoolbox"})):
            self.assertIsNone(policy.protected_reason(4242, cfg))

    def test_env_exclude(self):
        self.assertTrue(
            policy.env_excluded(
                {"XDG_RUNTIME_DIR": "/run/x/1000"}, {"XDG_RUNTIME_DIR": "/run/x/*"}
            )
        )
        self.assertFalse(
            policy.env_excluded(
                {"XDG_RUNTIME_DIR": "/run/user/1000"}, {"XDG_RUNTIME_DIR": "/run/x/*"}
            )
        )

    def test_units_parse(self):
        cfg = self.cfg()
        names = set()
        for d in ("etc/units", "examples/units"):
            cfg["paths"]["units_dir"] = os.path.join(ROOT, d)
            names |= {u["unit"]["name"] for u in policy.load_units(cfg)}
        self.assertEqual(
            names,
            {
                "app-claude-desktop",
                "app-herdr",
                "app-podman",
                "app-libvirt-qemu",
                "scope-emulator",
            },
        )

    def test_user_unit_replaces_system_unit_of_same_file(self):
        with (
            tempfile.TemporaryDirectory() as sysd,
            tempfile.TemporaryDirectory() as cfgd,
        ):
            os.makedirs(os.path.join(cfgd, "taema", "units"))
            with open(os.path.join(sysd, "podman.toml"), "w") as f:
                f.write('[unit]\nname = "app-podman"\nkind = "app"\n')
            with open(os.path.join(cfgd, "taema", "units", "podman.toml"), "w") as f:
                f.write(
                    '[unit]\nname = "app-podman"\nkind = "app"\nstop_when_unneeded = true\n'
                )
            cfg = self.cfg()
            with (
                mock.patch.object(policy, "SYSTEM_UNITS", sysd),
                mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": cfgd}),
            ):
                units = policy.load_units(cfg)
        self.assertEqual(len(units), 1)
        self.assertTrue(units[0]["unit"]["stop_when_unneeded"])

    def test_session_cgroups_auto(self):
        cfg = self.cfg()
        dirs = [
            cgroup.CG + "/2",
            cgroup.CG + "/7",
            cgroup.CG + "/user",
            cgroup.CG + "/other",
        ]
        procs = {cgroup.CG + "/2": [10], cgroup.CG + "/7": [20]}
        owners = {10: os.getuid(), 20: 0}
        with (
            mock.patch.object(policy.cgroup, "subdirs", return_value=dirs),
            mock.patch.object(
                policy.cgroup, "procs", side_effect=lambda d: procs.get(d, [])
            ),
            mock.patch.object(
                policy.inspect, "uid_of", side_effect=lambda p: owners[p]
            ),
        ):
            self.assertEqual(policy.session_cgroups(cfg), [cgroup.CG + "/2"])


class HelperTests(unittest.TestCase):
    """The root helper validates on its own and reads only the system config."""

    def setUp(self):
        self.h = load_helper()

    def fake(self, owner, comm="sleep", cg="/2", env=b""):
        h = self.h
        files = {
            "comm": comm.encode() + b"\n",
            "cgroup": ("0::%s\n" % cg).encode(),
            "environ": env,
        }
        st = mock.Mock(st_uid=owner)
        return [
            mock.patch.object(h.os, "stat", return_value=st),
            mock.patch.object(h, "read_proc", side_effect=lambda pid, n: files[n]),
        ]

    def test_paths(self):
        for ok in ("scope-x", "app-podman-1/conmon-2", "shared/adb-5"):
            self.assertTrue(self.h.valid_rel(ok))
        for bad in ("..", "a/../b", "/x", "a//b", "A", ""):
            self.assertFalse(self.h.valid_rel(bad))

    def test_check_pid_rules(self):
        h = self.h
        rules = {
            "comm": ["niri", "gvfsd*"],
            "env_prefix": {"XDG_RUNTIME_DIR": ["/run/mytool"]},
            "cgroup_prefix": ["/sys/fs/cgroup/other"],
        }
        with Patched(self.fake(1000)):
            self.assertEqual(h.check_pid(50, 1000, rules), ("sleep", "/2"))
        with Patched(self.fake(1001)):
            self.assertRaises(h.Refused, h.check_pid, 50, 1000, rules)
        with Patched(self.fake(1000, comm="gvfsd-fuse")):
            self.assertRaises(h.Refused, h.check_pid, 50, 1000, rules)
        with Patched(self.fake(1000, env=b"XDG_RUNTIME_DIR=/run/mytool/1000\0")):
            self.assertRaises(h.Refused, h.check_pid, 50, 1000, rules)
        with Patched(self.fake(1000, cg="/other/x")):
            self.assertRaises(h.Refused, h.check_pid, 50, 1000, rules)
        with Patched(self.fake(1000, cg="/user/1001/scope-x")):
            self.assertRaises(h.Refused, h.check_pid, 50, 1000, rules)
        with Patched(self.fake(1000, cg="/user/1000/app-x")):
            self.assertEqual(
                h.check_pid(50, 1000, rules), ("sleep", "/user/1000/app-x")
            )
        self.assertRaises(h.Refused, h.check_pid, 1, 1000, rules)

    def test_requires_sudo(self):
        with mock.patch.dict(os.environ, {"SUDO_UID": ""}):
            self.assertRaises(self.h.Refused, self.h.main, ["move", "scope-x", "50"])

    def test_config_must_be_root_owned(self):
        with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as f:
            f.write('[protected]\ncomm = ["x"]\n')
        try:
            if os.getuid() != 0:
                self.assertRaises(self.h.Refused, self.h.load_rules, f.name)
        finally:
            os.unlink(f.name)


if __name__ == "__main__":
    unittest.main()
