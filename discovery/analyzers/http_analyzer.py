"""HTTP security header analyzer.

Issues a real HTTP GET to port 80 and an HTTPS GET to port 443 (whichever
are open), captures the response headers as Evidence, flags missing
security headers, and runs everything through the rule engine.
"""

from __future__ import annotations

from typing import Dict, List

import requests
import urllib3

from core.engine.evidence import Evidence
from core.engine.rule_engine import Match, RuleEngine
from core.logger import Logger

# Fingerprinting should not fail because of an untrusted/self-signed cert.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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

    def __init__(self, timeout: float = 10, ruleset_path: str = "rulesets/default", insecure: bool = False):
        self.timeout = timeout
        self.ruleset_path = ruleset_path
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

    def analyze(self, host: str, open_ports: List[int]) -> Dict[str, list]:
        """Probe open_ports 80/443 and return {"evidence": [...], "matches": [...]}."""
        evidence: List[Evidence] = []

        if self.insecure:
            Logger.warning("HTTPS certificate verification is disabled (--insecure)")

        if 80 in open_ports:
            evidence.extend(self._collect_evidence(host, 80, "http"))

        if 443 in open_ports:
            evidence.extend(self._collect_evidence(host, 443, "https"))

        matches: List[Match] = []
        if evidence:
            engine = RuleEngine(self.ruleset_path)
            matches = engine.evaluate(evidence)

        return {"evidence": evidence, "matches": matches}
