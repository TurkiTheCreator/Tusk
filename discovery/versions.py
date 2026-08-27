from __future__ import annotations

from typing import Dict, Any, Tuple

from discovery.fingerprints import FINGERPRINTS, Fingerprint



class VersionDetector:
    """Detect vendor/product/version from a banner with confidence scoring."""

    def __init__(self):
        # Keep fingerprints external; this class only matches/selects.
        self.fingerprints: Tuple[Fingerprint, ...] = FINGERPRINTS

    def _pick_best(self, banner: str) -> Dict[str, Any]:
        if not banner:
            return {
                "product": "unknown",
                "version": "unknown",
                "confidence": 0.0,
            }

        best: Dict[str, Any] | None = None

        for fp in self.fingerprints:
            match = fp.compiled.search(banner)

            if not match:
                continue

            extracted = match.group(1)
            if fp.version_normalizer is not None:
                try:
                    extracted = fp.version_normalizer(extracted)
                except Exception:
                    # Normalization should never break detection.
                    pass

            candidate = {
                "product": fp.product,
                "version": extracted,
                "vendor": fp.vendor,
                "confidence": fp.confidence,
            }

            if best is None or candidate["confidence"] > best["confidence"]:
                best = candidate

        if best is None:
            return {
                "product": "unknown",
                "version": "unknown",
                "confidence": 0.0,
            }

        return best

    def extract_version(self, banner: str) -> Dict[str, Any]:
        # Preserve return structure compatibility.
        result = self._pick_best(banner)
        return {
            "product": result.get("product", "unknown"),
            "version": result.get("version", "unknown"),
            "confidence": result.get("confidence", 0.0),
            # vendor is additive; downstream modules ignore unknown keys.
            "vendor": result.get("vendor"),
        }

    def detect_versions(self, banners):
        versions = {}
        for port, banner in banners.items():
            versions[port] = self.extract_version(banner)
        return versions


