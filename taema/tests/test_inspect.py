import unittest

from taema.core import process as inspect

SERVER = (
    'u_str ESTAB 0 0 /run/user/1000/herdr.sock 100 * 101 users:(("herdr",pid=50,fd=9))'
)
CLIENT_OUT = 'u_str ESTAB 0 0 * 101 * 100 users:(("fzf",pid=70,fd=3))'
LISTEN = (
    'u_str LISTEN 0 128 /run/user/1000/herdr.sock 99 * 0 users:(("herdr",pid=50,fd=5))'
)
# member (pid 60) is a client of niri (outside); niri's end carries the path
M_CLIENT = 'u_str ESTAB 0 0 * 200 * 201 users:(("foot",pid=60,fd=4))'
NIRI_END = (
    'u_str ESTAB 0 0 /run/user/1000/wayland-1 201 * 200 users:(("niri",pid=1,fd=40))'
)
# member server whose client is a root process (peer end has no visible pids)
ROOT_SRV = 'u_str ESTAB 0 0 /run/foo.sock 300 * 301 users:(("srv",pid=80,fd=4))'
ROOT_CLI = "u_str ESTAB 0 0 * 301 * 300"


class UnixEdges(unittest.TestCase):
    def snap(self, *lines):
        return inspect.Snapshot("\n".join(lines), "", "")

    def test_outside_client_of_member_server_is_an_edge(self):
        e = inspect.edges({50}, self.snap(SERVER, CLIENT_OUT, LISTEN))
        self.assertEqual([x["kind"] for x in e[50]], ["unix_server"])
        self.assertEqual(e[50][0]["peers"], [70])

    def test_member_client_of_outside_server_is_not_an_edge(self):
        self.assertEqual(inspect.edges({60}, self.snap(M_CLIENT, NIRI_END)), {})

    def test_two_members_talking_is_not_an_edge(self):
        self.assertEqual(inspect.edges({50, 70}, self.snap(SERVER, CLIENT_OUT)), {})

    def test_unresolved_peer_is_conservative(self):
        e = inspect.edges({80}, self.snap(ROOT_SRV, ROOT_CLI))
        self.assertEqual(e[80][0]["kind"], "unix_server_unresolved")

    def test_listen_socket_alone_is_not_an_edge(self):
        self.assertEqual(inspect.edges({50}, self.snap(LISTEN)), {})


TCP_LISTEN = 'LISTEN 0 128 127.0.0.1:5037 0.0.0.0:* users:(("adb",pid=90,fd=10))'
TCP_SRV_SIDE = 'ESTAB 0 0 127.0.0.1:5037 127.0.0.1:40000 users:(("adb",pid=90,fd=11))'
TCP_CLIENT_SIDE = (
    'ESTAB 0 0 127.0.0.1:40000 127.0.0.1:5037 users:(("studio",pid=91,fd=7))'
)
TCP_REMOTE = "ESTAB 0 0 127.0.0.1:5037 10.0.0.5:51000"


class TcpEdges(unittest.TestCase):
    def snap(self, listen, *est):
        return inspect.Snapshot("", "\n".join(est), listen)

    def test_loopback_client_outside_is_an_edge(self):
        e = inspect.edges({90}, self.snap(TCP_LISTEN, TCP_SRV_SIDE, TCP_CLIENT_SIDE))
        self.assertEqual(e[90][0]["kind"], "tcp_server")
        self.assertEqual(e[90][0]["peers"], [91])

    def test_loopback_client_inside_set_is_not(self):
        self.assertEqual(
            inspect.edges(
                {90, 91}, self.snap(TCP_LISTEN, TCP_SRV_SIDE, TCP_CLIENT_SIDE)
            ),
            {},
        )

    def test_remote_client_is_an_edge(self):
        e = inspect.edges({90}, self.snap(TCP_LISTEN, TCP_REMOTE))
        self.assertIn(90, e)

    def test_listen_without_clients_has_no_edge(self):
        self.assertEqual(inspect.edges({90}, self.snap(TCP_LISTEN)), {})


class OtherEdges(unittest.TestCase):
    def test_podman_pause_used_by_outside_conmon(self):
        info = {
            "comm": {10: "catatonit", 11: "conmon", 12: "conmon"},
            "environ": {
                10: {"XDG_RUNTIME_DIR": "/r"},
                11: {"XDG_RUNTIME_DIR": "/r"},
                12: {"XDG_RUNTIME_DIR": "/other"},
            },
        }
        e = inspect.edges({10}, inspect.Snapshot("", "", ""), info)
        self.assertEqual(e[10][0]["kind"], "podman_pause")
        self.assertEqual(e[10][0]["peers"], [11])

    def test_podman_conmon_inside_set_is_not_outside(self):
        info = {
            "comm": {10: "catatonit", 11: "conmon"},
            "environ": {10: {"XDG_RUNTIME_DIR": "/r"}, 11: {"XDG_RUNTIME_DIR": "/r"}},
        }
        self.assertEqual(
            inspect.edges({10, 11}, inspect.Snapshot("", "", ""), info), {}
        )

    def test_ptrace_from_outside(self):
        info = {"comm": {5: "x"}, "tracer": {5: 99}, "environ": {}}
        e = inspect.edges({5}, inspect.Snapshot("", "", ""), info)
        self.assertEqual(e[5][0]["kind"], "ptrace")

    def test_stdio_is_never_an_edge(self):
        # edges() takes no pipe/pty input at all: shared stdio cannot produce an edge
        info = {"comm": {5: "sleep"}, "tracer": {}, "environ": {}}
        self.assertEqual(inspect.edges({5}, inspect.Snapshot("", "", ""), info), {})


class Parse(unittest.TestCase):
    def test_parse_real_format(self):
        txt = 'u_str ESTAB 0      0                                                         * 2302403             * 2302404  users:(("herdr",pid=11549,fd=11),("herdr",pid=11549,fd=9))'
        r = inspect.parse_ss_unix(txt)[0]
        self.assertEqual(
            (r["inode"], r["peer_inode"], r["pids"], r["path"]),
            (2302403, 2302404, {11549}, ""),
        )

    def test_parse_tcp_no_users(self):
        r = inspect.parse_ss_tcp(
            "LISTEN 0      128          0.0.0.0:22         0.0.0.0:*"
        )[0]
        self.assertEqual((r["local"], r["pids"]), ("0.0.0.0:22", set()))


if __name__ == "__main__":
    unittest.main()
