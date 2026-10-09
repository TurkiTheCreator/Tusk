import socket
import threading
import unittest

from core.utils import _resolve_cached, get_all_addresses, resolve_host
from discovery.banners import BannerGrabber


def serve_banner(payload, family=socket.AF_INET, addr="127.0.0.1"):
    """Accept connections forever, sending `payload` first. Returns (port, server)."""
    server = socket.socket(family)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((addr, 0))
    server.listen(5)

    def run():
        while True:
            try:
                conn, _ = server.accept()
            except OSError:
                return
            conn.sendall(payload)
            conn.close()

    threading.Thread(target=run, daemon=True).start()
    return server.getsockname()[1], server


def serve_http(family=socket.AF_INET, addr="127.0.0.1"):
    """Silent until it gets a request, then answers like a web server."""
    server = socket.socket(family)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((addr, 0))
    server.listen(5)

    def run():
        while True:
            try:
                conn, _ = server.accept()
            except OSError:
                return
            try:
                if conn.recv(4096):
                    conn.sendall(b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n")
            finally:
                conn.close()

    threading.Thread(target=run, daemon=True).start()
    return server.getsockname()[1], server


def ipv6_available():
    try:
        s = socket.socket(socket.AF_INET6)
        s.bind(("::1", 0))
        s.close()
        return True
    except OSError:
        return False


class ResolveTests(unittest.TestCase):
    def test_ipv4_and_ipv6_literals(self):
        self.assertEqual(resolve_host("127.0.0.1"), "127.0.0.1")
        if ipv6_available():
            self.assertEqual(resolve_host("::1"), "::1")

    def test_unresolvable_and_invalid_hosts_return_none(self):
        self.assertIsNone(resolve_host("nope.invalid"))
        self.assertIsNone(resolve_host("a" * 300))

    def test_port_is_filled_in_and_lookup_is_cached(self):
        _resolve_cached.cache_clear()
        first = get_all_addresses("127.0.0.1", 22)
        second = get_all_addresses("127.0.0.1", 8080)
        self.assertEqual(first[0][4], ("127.0.0.1", 22))
        self.assertEqual(second[0][4], ("127.0.0.1", 8080))
        self.assertEqual(_resolve_cached.cache_info().misses, 1)

    @unittest.skipUnless(ipv6_available(), "IPv6 loopback not available")
    def test_ipv6_sockaddr_keeps_extra_fields(self):
        addr = get_all_addresses("::1", 80)[0][4]
        self.assertEqual(addr[:2], ("::1", 80))
        self.assertEqual(len(addr), 4)


class BannerTests(unittest.TestCase):
    def setUp(self):
        self.grabber = BannerGrabber(timeout=1)
        self.servers = []

    def tearDown(self):
        for s in self.servers:
            s.close()

    def start(self, factory, *a, **kw):
        port, server = factory(*a, **kw)
        self.servers.append(server)
        return port

    def test_ssh_on_non_standard_port(self):
        port = self.start(serve_banner, b"SSH-2.0-OpenSSH_8.9p1 Ubuntu\r\n")
        self.assertEqual(self.grabber.grab_banner("127.0.0.1", port),
                         "SSH-2.0-OpenSSH_8.9p1 Ubuntu")

    @unittest.skipUnless(ipv6_available(), "IPv6 loopback not available")
    def test_banner_over_ipv6(self):
        port = self.start(serve_banner, b"SSH-2.0-OpenSSH_9.0\r\n", socket.AF_INET6, "::1")
        self.assertEqual(self.grabber.grab_banner("::1", port), "SSH-2.0-OpenSSH_9.0")

    def test_http_on_non_standard_port(self):
        port = self.start(serve_http)
        banner = self.grabber.grab_banner("127.0.0.1", port)
        self.assertTrue(banner.startswith("HTTP/1.1 200"))
        self.assertIn("nginx/1.18.0", banner)

    def test_closed_port_returns_empty_without_raising(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        self.assertEqual(self.grabber.grab_banner("127.0.0.1", port), "")

    def test_closed_port_is_not_logged_as_error(self):
        import io
        from contextlib import redirect_stdout
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        buf = io.StringIO()
        with redirect_stdout(buf):
            self.grabber.grab_banner("127.0.0.1", port)
        self.assertNotIn("[ERR]", buf.getvalue())

    def test_no_hardcoded_ipv4_sockets(self):
        import inspect
        import discovery.banners as banners
        self.assertNotIn("AF_INET", inspect.getsource(banners))


if __name__ == "__main__":
    unittest.main()
