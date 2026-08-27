class CPEGenerator:

    def __init__(self):
        self.vendors = {
            "OpenSSH": "openbsd",
            "nginx": "nginx",
            "Apache": "apache",
            "vsFTPd": "vsftpd"
        }

    def _normalize_field(self, value):
        """Normalize a CPE field: trim, lowercase, escape."""
        if value is None:
            return "unknown"
        normalized = str(value).strip().lower()
        return normalized if normalized else "unknown"

    def generate_cpe(self, product, version, vendor=None):
        """Generate a CPE 2.3 string, or None if product/version is unknown."""
        product = self._normalize_field(product)
        version = self._normalize_field(version)

        if product == "unknown" or version == "unknown":
            return None

        vendor_norm = self._normalize_field(
            vendor or self.vendors.get(product, product)
        )

        cpe = (
            f"cpe:2.3:a:{vendor_norm}:"
            f"{product}:{version}:*:*:*:*:*:*:*"
        )
        return cpe

    def generate_cpes(self, versions):
        """Generate CPEs for detected versions; reject unknown product/version pairs."""
        cpes = {}

        for port, info in versions.items():
            product = info.get("product", "unknown")
            version = info.get("version", "unknown")
            vendor = info.get("vendor")

            cpe = self.generate_cpe(product, version, vendor)
            if cpe is not None:
                cpes[port] = cpe

        return cpes
    
