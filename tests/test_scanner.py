import unittest
from unittest import mock

from core.models import ScanError
from core.scanner import Scanner
from core.target import Target
from intelligence.cve import LookupResult


class ScannerCVEStageTests(unittest.TestCase):
    def run_scan(self, lookup_results):
        scanner = Scanner()
        scanner.port_scanner.scan_ports = lambda host, ports: [22, 80]
        scanner.banner_grabber.grab_banners = lambda host, ports: {
            22: "SSH-2.0-OpenSSH_8.9p1", 80: "Server: nginx/1.18.0"}
        scanner.cve_lookup.lookup_all = lambda cpes: lookup_results
        target = Target("h")
        target.ports = [22, 80]
        scanner.run(target)
        return target

    def test_failed_lookup_becomes_scan_error_not_empty_result(self):
        target = self.run_scan({
            22: LookupResult(False, error="HTTP 429"),
            80: LookupResult(True, [{"id": "CVE-1", "cvss": 7.5, "vector": None,
                                     "version_ranges": []}]),
        })
        errors = [e for e in target.errors if e.stage == "cve_lookup"]
        self.assertEqual(len(errors), 1)
        self.assertIn("port 22", errors[0].message)
        self.assertIn("HTTP 429", errors[0].message)
        self.assertNotIn(22, target.cves)
        self.assertEqual(target.findings[80][0].cve_id, "CVE-1")
        self.assertEqual(target.findings[80][0].severity, "High")

    def test_old_cve_with_only_v2_score_gets_a_severity(self):
        target = self.run_scan({
            22: LookupResult(True, [{"id": "CVE-OLD", "cvss": 7.5, "vector": "AV:N",
                                     "version_ranges": []}]),
            80: LookupResult(True, []),
        })
        self.assertNotEqual(target.findings[22][0].severity, "Unknown")

    def test_api_key_reaches_lookup(self):
        scanner = Scanner(nvd_api_key="secret")
        self.assertEqual(scanner.cve_lookup._session.headers["apiKey"], "secret")

    def test_debug_flag_controls_logger(self):
        from core.logger import Logger
        Scanner(debug=True)
        self.assertTrue(Logger.verbose)
        Scanner(debug=False)
        self.assertFalse(Logger.verbose)


if __name__ == "__main__":
    unittest.main()
