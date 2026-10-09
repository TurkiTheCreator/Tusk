import re

# "8.9p1" -> version "8.9", update "p1" (NVD stores the patch level in the update field)
_OPENSSH_PATCH = re.compile(r"^(\d+(?:\.\d+)*)(p\d+)$", re.IGNORECASE)


class CPEGenerator:

    def _normalize_field(self, value):
        """Normalize a CPE field: trim, lowercase."""
        if value is None:
            return "unknown"
        normalized = str(value).strip().lower()
        return normalized if normalized else "unknown"

    def _escape(self, value):
        """Backslash-escape CPE 2.3 special characters (keeps . _ - alnum)."""
        return re.sub(r"([^a-z0-9._\-])", r"\\\1", value)

    def generate_cpe(self, vendor, product, version):
        """Generate a CPE 2.3 string, or None if vendor/product/version is unknown."""
        vendor = self._normalize_field(vendor)
        product = self._normalize_field(product)
        version = self._normalize_field(version)

        if "unknown" in (vendor, product, version):
            return None

        update = "*"
        if product == "openssh":
            m = _OPENSSH_PATCH.match(version)
            if m:
                version, update = m.group(1), m.group(2)

        update_field = update if update == "*" else self._escape(update)
        return (
            f"cpe:2.3:a:{self._escape(vendor)}:{self._escape(product)}:"
            f"{self._escape(version)}:{update_field}:*:*:*:*:*:*"
        )

    def generate_cpes(self, versions):
        """Generate CPEs for detected versions; reject unknown vendor/product/version."""
        cpes = {}

        for port, info in versions.items():
            cpe = self.generate_cpe(
                info.get("nvd_vendor"),
                info.get("nvd_product"),
                info.get("version", "unknown"),
            )
            if cpe is not None:
                cpes[port] = cpe

        return cpes
