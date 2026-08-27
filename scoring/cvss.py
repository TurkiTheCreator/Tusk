"""CVSS 3.1 base score calculator.

Implements the Base Score formula exactly as defined by the FIRST.org
CVSS v3.1 specification (https://www.first.org/cvss/v3.1/specification-document),
section 7.1 "Base Metrics Equations" and Appendix A "Floating Point Rounding".

Pure math: no network calls, no third-party dependencies.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Dict

# --- Metric value tables (CVSS v3.1 spec, section 7.1) ---------------------

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_VALID_SCOPES = {"U", "C"}

_REQUIRED_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


class CVSSError(ValueError):
    """Raised when a CVSS vector string is malformed or has invalid values."""


@dataclass(frozen=True)
class CVSSResult:
    base_score: float
    severity: str
    impact_subscore: float
    exploitability_subscore: float


def _parse_vector(vector: str) -> Dict[str, str]:
    cleaned = vector.strip()

    # Tolerate an optional "CVSS:3.1/" prefix.
    if cleaned.upper().startswith("CVSS:"):
        _, _, cleaned = cleaned.partition("/")

    metrics: Dict[str, str] = {}
    for part in cleaned.split("/"):
        if not part:
            continue
        if ":" not in part:
            raise CVSSError(f"Malformed metric segment: {part!r}")
        key, _, value = part.partition(":")
        metrics[key.upper()] = value.upper()

    missing = [m for m in _REQUIRED_METRICS if m not in metrics]
    if missing:
        raise CVSSError(f"Vector missing required metric(s): {', '.join(missing)}")

    return metrics


def _roundup(value: float) -> float:
    """CVSS v3.1 Appendix A Roundup: round a number up to 1 decimal place."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def severity_band(score: float) -> str:
    """CVSS v3.1 Qualitative Severity Rating Scale."""
    if score <= 0.0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def calculate(vector: str) -> CVSSResult:
    """Calculate the CVSS v3.1 base score and severity band for a vector string.

    Example vector: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    """
    metrics = _parse_vector(vector)

    scope = metrics["S"]
    if scope not in _VALID_SCOPES:
        raise CVSSError(f"Invalid Scope (S) value: {metrics['S']}")

    try:
        av = _AV[metrics["AV"]]
        ac = _AC[metrics["AC"]]
        pr_table = _PR_CHANGED if scope == "C" else _PR_UNCHANGED
        pr = pr_table[metrics["PR"]]
        ui = _UI[metrics["UI"]]
        c = _CIA[metrics["C"]]
        i = _CIA[metrics["I"]]
        a = _CIA[metrics["A"]]
    except KeyError as e:
        raise CVSSError(f"Invalid value for metric {e}")

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))

    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        base_score = 0.0
    elif scope == "U":
        base_score = _roundup(min(impact + exploitability, 10.0))
    else:
        base_score = _roundup(min(1.08 * (impact + exploitability), 10.0))

    return CVSSResult(
        base_score=base_score,
        severity=severity_band(base_score),
        impact_subscore=round(impact, 1),
        exploitability_subscore=round(exploitability, 1),
    )
