"""Domain model for vulnerability findings.

`CandidateCVE` is the raw, unvalidated result of a CPE/version match against
NVD — exactly what intelligence/cve.py produces today. `Finding` is what the
rest of Tusk (output, scoring) should actually work with: it carries a
confidence status so callers never have to treat a version match as a
confirmed vulnerability.

`confidence_status` defaults to "Candidate" because that's what an
unvalidated CPE match honestly is. Validation (version-range checks, vendor
backport heuristics, EPSS, CISA KEV) will refine `confidence_score` /
`confidence_status` to "Likely Vulnerable" / "Verified" / "Not Applicable"
once that engine lands — this shape does not need to change again to support it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List, Optional

from scoring.cvss import severity_band


@dataclass(frozen=True)
class ScanError:
    """Represents a failure at a specific pipeline stage."""

    stage: str
    message: str
    exception_type: str
    traceback: Optional[str] = None


CONFIDENCE_STATUSES = (
    "Candidate",
    "Likely Vulnerable",
    "Verified",
    "Not Applicable",
)


@dataclass(frozen=True)
class CandidateCVE:
    """A raw CPE-matched CVE from NVD, before any validation."""

    id: str
    cvss_score: Optional[float]
    cvss_vector: Optional[str]
    version_ranges: List[Any] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict) -> "CandidateCVE":
        return cls(
            id=d["id"],
            cvss_score=d.get("cvss"),
            cvss_vector=d.get("vector"),
            version_ranges=d.get("version_ranges") or [],
        )


@dataclass
class Finding:
    """A CandidateCVE plus whatever validation/confidence signal is available."""

    cve_id: str
    cvss_score: Optional[float]
    cvss_vector: Optional[str]
    severity: str
    epss_score: Optional[float] = None
    kev_listed: Optional[bool] = None
    confidence_score: Optional[float] = None
    confidence_status: str = "Candidate"
    reasons: List[str] = field(default_factory=list)

    @classmethod
    def from_candidate(cls, c: CandidateCVE) -> "Finding":
        severity = (
            severity_band(c.cvss_score) if c.cvss_score is not None else "Unknown"
        )
        return cls(
            cve_id=c.id,
            cvss_score=c.cvss_score,
            cvss_vector=c.cvss_vector,
            severity=severity,
        )

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "severity": self.severity,
            "epss_score": self.epss_score,
            "kev_listed": self.kev_listed,
            "confidence_score": self.confidence_score,
            "confidence_status": self.confidence_status,
            "reasons": self.reasons,
        }
