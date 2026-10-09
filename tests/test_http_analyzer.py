import os
import subprocess
import sys
import tempfile
import unittest
import warnings
from pathlib import Path
from unittest import mock

import urllib3

from core.engine.rule_engine import RuleEngineError
from discovery.analyzers import http_analyzer
from discovery.analyzers.http_analyzer import DEFAULT_RULESET, HttpAnalyzer

ROOT = Path(__file__).resolve().parents[1]


class FakeResponse:
    def __init__(self, headers):
        self.headers = headers


def values(evidence):
    return [e.value for e in evidence]


class SchemeAndPortTests(unittest.TestCase):
    def analyze(self, open_ports, banners=None, headers=None, fail_schemes=()):
        calls = []

        def fake_get(url, **kw):
            calls.append(url)
            if url.split(":")[0] in fail_schemes:
                import requests
                raise requests.exceptions.ConnectionError()
            return FakeResponse(headers or {"Server": "x"})

        with mock.patch("requests.get", fake_get):
            result = HttpAnalyzer().analyze("h", open_ports, banners)
        return result, calls

    def test_hsts_checked_over_https_only(self):
        result, _ = self.analyze([443])
        self.assertIn("Strict-Transport-Security: MISSING", values(result["evidence"]))

        result, _ = self.analyze([80])
        self.assertNotIn("Strict-Transport-Security: MISSING", values(result["evidence"]))
        self.assertIn("Content-Security-Policy: MISSING", values(result["evidence"]))

    def test_non_standard_web_ports_are_probed(self):
        for port in (8080, 8443, 8000):
            _, calls = self.analyze([port])
            self.assertTrue(calls, port)

    def test_ssh_port_is_not_probed(self):
        _, calls = self.analyze([22])
        self.assertEqual(calls, [])

    def test_unknown_port_probed_when_banner_is_http(self):
        _, calls = self.analyze([9999], banners={9999: "HTTP/1.1 200 OK"})
        self.assertTrue(calls)
        _, calls = self.analyze([9999], banners={9999: "SSH-2.0-x"})
        self.assertEqual(calls, [])

    def test_https_first_on_8443_and_http_first_on_8080(self):
        _, calls = self.analyze([8443])
        self.assertTrue(calls[0].startswith("https://"))
        _, calls = self.analyze([8080])
        self.assertTrue(calls[0].startswith("http://"))

    def test_falls_back_to_other_scheme(self):
        result, calls = self.analyze([8080], fail_schemes=("http",))
        self.assertEqual([c.split(":")[0] for c in calls], ["http", "https"])
        self.assertTrue(result["evidence"])


class WarningTests(unittest.TestCase):
    def test_import_does_not_silence_urllib3(self):
        code = (
            "import warnings, urllib3\n"
            "import discovery.analyzers.http_analyzer\n"
            "f = [x for x in warnings.filters if x[2] is urllib3.exceptions.InsecureRequestWarning"
            " and x[0] == 'ignore']\n"
            "print(len(f))\n"
        )
        out = subprocess.run([sys.executable, "-c", code], cwd=ROOT,
                             capture_output=True, text=True).stdout.strip()
        self.assertEqual(out, "0")

    def test_insecure_silences_and_warns(self):
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with mock.patch("requests.get", return_value=FakeResponse({})), \
             mock.patch("urllib3.disable_warnings") as disable, redirect_stdout(buf):
            HttpAnalyzer(insecure=True).analyze("h", [443])
        disable.assert_called_once()
        self.assertIn("--insecure", buf.getvalue())

        with mock.patch("requests.get", return_value=FakeResponse({})), \
             mock.patch("urllib3.disable_warnings") as disable:
            HttpAnalyzer(insecure=False).analyze("h", [443])
        disable.assert_not_called()


class RulesetTests(unittest.TestCase):
    def test_default_ruleset_is_package_relative_and_exists(self):
        self.assertTrue(DEFAULT_RULESET.is_absolute())
        self.assertTrue((DEFAULT_RULESET / "meta.yaml").is_file())

    def test_works_from_another_working_directory(self):
        old = os.getcwd()
        os.chdir(tempfile.gettempdir())
        try:
            with mock.patch("requests.get", return_value=FakeResponse({})):
                result = HttpAnalyzer().analyze("h", [443])
            self.assertTrue(result["matches"])
        finally:
            os.chdir(old)

    def test_bad_ruleset_raises_ruleset_error(self):
        with mock.patch("requests.get", return_value=FakeResponse({})):
            with self.assertRaises(RuleEngineError):
                HttpAnalyzer(ruleset_path="/nonexistent").analyze("h", [443])

    def test_cli_prints_one_line_and_exits_2_on_bad_ruleset(self):
        env = dict(os.environ, TUSK_RULESET_PATH="/nonexistent", PYTHONPATH=str(ROOT))
        proc = subprocess.run(
            [sys.executable, "-c",
             "import sys, cli\n"
             "from unittest import mock\n"
             "from core.models import Finding\n"
             "sys.argv=['tusk','scan','-u','127.0.0.1','-p','1','--http-headers']\n"
             "def fake_run(s, t):\n"
             "    t.findings = {}; t.open_ports = [80]\n"
             "class R: headers = {}\n"
             "with mock.patch('cli.Scanner.run', fake_run),"
             " mock.patch('requests.get', return_value=R()),"
             " mock.patch('cli.resolve_host', return_value='1'):\n"
             "    sys.exit(cli.main())\n"],
            cwd=ROOT, env=env, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 2)
        self.assertNotIn("Traceback", proc.stderr)
        self.assertIn("Ruleset error", proc.stdout)

    def test_packaging_ships_rulesets(self):
        setup_py = (ROOT / "setup.py").read_text()
        self.assertIn('"rulesets"', setup_py)
        self.assertTrue((ROOT / "rulesets" / "__init__.py").is_file())


if __name__ == "__main__":
    unittest.main()
