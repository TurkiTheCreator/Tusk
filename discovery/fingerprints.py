"""Fingerprint definitions for vendor/product/version detection.

Separated from VersionDetector to keep responsibilities clear and the
fingerprint database easy to extend.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional, Pattern, Tuple

import re


@dataclass(frozen=True)
class Fingerprint:
    """A vendor/product/version regex fingerprint."""

    id: str
    vendor: str
    product: str
    version_pattern: str
    confidence: float = 0.5
    # Optional normalization of the extracted version string.
    version_normalizer: Optional[Callable[[str], str]] = None
    # Compiled regex for performance.
    _compiled: Optional[Pattern[str]] = None

    def compile(self) -> "Fingerprint":
        if self._compiled is None:
            object.__setattr__(
                self,
                "_compiled",
                re.compile(self.version_pattern, re.IGNORECASE | re.MULTILINE),
            )
        return self

    @property
    def compiled(self) -> Pattern[str]:
        if self._compiled is None:
            # Compile lazily but deterministically.
            return re.compile(
                self.version_pattern,
                re.IGNORECASE | re.MULTILINE,
            )
        return self._compiled


def _strip_prefix(v: str) -> str:
    return v.strip().lstrip("vV")


# NOTE: Patterns should include exactly one capturing group for the version.
FINGERPRINTS: Tuple[Fingerprint, ...] = (
    Fingerprint(
        id="openssh",
        vendor="OpenSSH",
        product="OpenSSH",
        version_pattern=r"OpenSSH[_/ ]([\d\.]+[\w\.]*)",
        confidence=0.95,
        version_normalizer=_strip_prefix,
    ),
    Fingerprint(
        id="nginx",
        vendor="nginx",
        product="nginx",
        version_pattern=r"nginx[/ ]([\d\.]+[\w\.]*)",
        confidence=0.9,
    ),
    Fingerprint(
        id="apache",
        vendor="Apache",
        product="Apache",
        version_pattern=r"Apache[/ ]([\d\.]+[\w\.]*)",
        confidence=0.9,
    ),
    Fingerprint(
        id="vsftpd",
        vendor="vsFTPd",
        product="vsFTPd",
        version_pattern=r"vsFTPd[\s/ ]([\d\.]+[\w\.]*)",
        confidence=0.9,
    ),
)


# Pre-compile for runtime speed.
FINGERPRINTS = tuple(fp.compile() for fp in FINGERPRINTS)

