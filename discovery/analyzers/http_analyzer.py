"""HTTP security header analyzer.

Issues a real HTTP or HTTPS GET to every open port that looks like a web
server, captures the response headers as Evidence, flags missing
security headers, and runs everything through the rule engine.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List

import requests
import urllib3

from core.engine.evidence import Evidence
from core.engine.rule_engine import Match, RuleEngine
from core.logger import Logger

# <root>/discovery/analyzers/http_analyzer.py -> <root>/rulesets/default
DEFAULT_RULESET = Path(__file__).resolve().parents[2] / "rulesets" / "default"

# Ports probed even when the banner grab returned nothing.
HTTP_PORTS = {80, 81, 443, 3000, 5000, 8000, 8008, 8080, 8081, 8443, 8888}
HTTPS_FIRST = {443, 8443}

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


class HttpAnalyzer:
    """Probes port 80/443, turns response headers into Evidence, and scores them."""

    def __init__(self, timeout: float = 10, ruleset_path: str = "", insecure: bool = False):
        self.timeout = timeout
        self.ruleset_path = ruleset_path or DEFAULT_RULESET
        self.insecure = insecure

    def _collect_evidence(self, host: str, port: int, scheme: str) -> List[Evidence]:
        url = f"{scheme}://{host}:{port}/"

        try:
            response = requests.get(
                url,
                timeout=self.timeout,
                verify=not self.insecure,
                allow_redirects=True,
            )
        except requests.exceptions.RequestException:
            return []

        headers = response.headers  # case-insensitive dict
        evidence = []

        for name, value in headers.items():
            evidence.append(
                Evidence(
                    type="header",
                    value=f"{name}: {value}",
                    source="http_analyzer",
                    port=port,
                )
            )

        for name in SECURITY_HEADERS:
            if name == "Strict-Transport-Security" and scheme != "https":
                continue  # HSTS is only meaningful over HTTPS
            if name not in headers:
                evidence.append(
                    Evidence(
                        type="header",
                        value=f"{name}: MISSING",
                        source="http_analyzer",
                        port=port,
                    )
                )

        return evidence

    def analyze(self, host: str, open_ports: List[int], banners=None) -> Dict[str, list]:
        """Probe every open port that looks like HTTP(S); return {"evidence", "matches"}."""
        banners = banners or {}
        evidence: List[Evidence] = []

        if self.insecure:
            Logger.warning("HTTPS certificate verification is disabled (--insecure)")
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        for port in open_ports:
            if port not in HTTP_PORTS and not banners.get(port, "").startswith("HTTP/"):
                continue
            schemes = ("https", "http") if port in HTTPS_FIRST else ("http", "https")
            for scheme in schemes:
                found = self._collect_evidence(host, port, scheme)
                if found:
                    evidence.extend(found)
                    break

        matches: List[Match] = []
        if evidence:
            engine = RuleEngine(self.ruleset_path)
            matches = engine.evaluate(evidence)

        return {"evidence": evidence, "matches": matches}
