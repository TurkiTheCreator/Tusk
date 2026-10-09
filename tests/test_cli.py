import io
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

import cli
from core.models import ScanError


class ParsePortsTests(unittest.TestCase):
    def test_single_list_and_range(self):
        self.assertEqual(cli.parse_ports("80"), [80])
        self.assertEqual(cli.parse_ports("443,80,80"), [80, 443])
        self.assertEqual(cli.parse_ports("1-3,8080"), [1, 2, 3, 8080])
        self.assertEqual(cli.parse_ports(" 22 , 80-81 "), [22, 80, 81])

    def test_bounds(self):
        self.assertEqual(cli.parse_ports("65535"), [65535])
        self.assertEqual(cli.parse_ports("1"), [1])
        for bad in ("0", "65536", "70000", "1-70000", "0-5"):
            with self.assertRaises(ValueError, msg=bad):
                cli.parse_ports(bad)

    def test_garbage(self):
        for bad in ("abc", "", ",", "9-1", "1-", "-5", "80,x"):
            with self.assertRaises(ValueError, msg=bad):
                cli.parse_ports(bad)


class ParseTargetTests(unittest.TestCase):
    def test_bare_hosts(self):
        self.assertEqual(cli.parse_target("example.com"), ("example.com", None))
        self.assertEqual(cli.parse_target("::1"), ("::1", None))
        self.assertEqual(cli.parse_target(" 10.0.0.1 "), ("10.0.0.1", None))

    def test_urls(self):
        self.assertEqual(cli.parse_target("https://host:8443/"), ("host", 8443))
        self.assertEqual(cli.parse_target("http://host/path?x=1"), ("host", None))
        self.assertEqual(cli.parse_target("http://[::1]:8080/"), ("::1", 8080))


def run_main(argv, errors=(), findings=None, resolves=True):
    """Run cli.main() with the scan itself stubbed out. Returns (exit_code, stdout)."""
    def fake_run(self, target):
        target.errors.extend(errors)
        target.findings = findings or {}

    out = io.StringIO()
    with mock.patch.object(sys, "argv", ["tusk"] + argv), \
         mock.patch("cli.Scanner.run", fake_run), \
         mock.patch("cli.resolve_host", return_value="127.0.0.1" if resolves else None), \
         redirect_stdout(out), redirect_stderr(io.StringIO()):
        try:
            code = cli.main()
        except SystemExit as e:  # argparse usage errors
            code = e.code
    return code, out.getvalue()


class ExitCodeTests(unittest.TestCase):
    def finding(self):
        from core.models import Finding
        return {80: [Finding("CVE-1", 7.5, None, "High")]}

    def test_clean_is_0(self):
        self.assertEqual(run_main(["scan", "-u", "h", "-p", "80"])[0], 0)

    def test_findings_is_1(self):
        self.assertEqual(run_main(["scan", "-u", "h", "-p", "80"], findings=self.finding())[0], 1)

    def test_scan_error_is_3_and_beats_findings(self):
        err = ScanError("cve_lookup", "port 80: HTTP 429", "LookupFailed")
        self.assertEqual(run_main(["scan", "-u", "h", "-p", "80"], errors=[err])[0], 3)
        self.assertEqual(
            run_main(["scan", "-u", "h", "-p", "80"], errors=[err], findings=self.finding())[0], 3
        )

    def test_port_discovery_failure_is_3_with_no_report(self):
        err = ScanError("port_discovery", "boom", "OSError")
        code, out = run_main(["scan", "-u", "h", "-p", "80"], errors=[err])
        self.assertEqual(code, 3)
        self.assertNotIn("[VULN]", out)

    def test_dns_failure_is_2(self):
        code, out = run_main(["scan", "-u", "nope.invalid", "-p", "80"], resolves=False)
        self.assertEqual(code, 2)
        self.assertIn("DNS lookup failed", out)

    def test_usage_errors_are_2(self):
        for argv in (
            ["scan", "-u", "h", "-p", "70000"],
            ["scan", "-u", "h", "-p", "9-1"],
            ["scan", "-u", "h", "--top-ports", "1000"],
            ["scan", "-u", "h", "--top-ports", "0"],
            ["scan"],
        ):
            self.assertEqual(run_main(argv)[0], 2, argv)

    def test_cve_lookup_failure_is_reported_not_all_clear(self):
        err = ScanError("cve_lookup", "port 22: HTTP 429", "LookupFailed")
        _, out = run_main(["scan", "-u", "h", "-p", "22"], errors=[err])
        self.assertIn("CVE lookup failed", out)
        self.assertNotIn("No vulnerabilities found", out)

    def test_clean_scan_says_no_vulnerabilities(self):
        _, out = run_main(["scan", "-u", "h", "-p", "22"])
        self.assertIn("No vulnerabilities found", out)

    def test_url_target_uses_host_and_port(self):
        seen = {}

        def fake_run(self, target):
            seen["host"], seen["ports"] = target.host, list(target.ports)
            target.findings = {}

        with mock.patch.object(sys, "argv", ["tusk", "scan", "-u", "https://h:8443/"]), \
             mock.patch("cli.Scanner.run", fake_run), \
             mock.patch("cli.resolve_host", return_value="1.2.3.4"), \
             redirect_stdout(io.StringIO()):
            cli.main()
        self.assertEqual(seen, {"host": "h", "ports": [8443]})

    def test_target_alias(self):
        self.assertEqual(run_main(["scan", "--target", "h", "-p", "80"])[0], 0)

    def test_help_and_config_errors(self):
        self.assertEqual(run_main([])[0], 0)
        self.assertEqual(run_main(["config"])[0], 2)


if __name__ == "__main__":
    unittest.main()
