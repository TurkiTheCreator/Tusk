import re
import unittest

from discovery.versions import VersionDetector
from intelligence.cpe import CPEGenerator


class CPETests(unittest.TestCase):
    def setUp(self):
        self.gen = CPEGenerator()

    def test_nvd_names_from_banners(self):
        banners = {
            22: "SSH-2.0-OpenSSH_8.9p1 Ubuntu",
            80: "Server: Apache/2.4.41",
            443: "Server: nginx/1.18.0",
            21: "220 (vsFTPd 3.0.3)",
        }
        cpes = self.gen.generate_cpes(VersionDetector().detect_versions(banners))
        self.assertEqual(cpes[22], "cpe:2.3:a:openbsd:openssh:8.9:p1:*:*:*:*:*:*")
        self.assertEqual(cpes[80], "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*")
        self.assertEqual(cpes[443], "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*")
        self.assertEqual(cpes[21], "cpe:2.3:a:beasts:vsftpd:3.0.3:*:*:*:*:*:*:*")

    def test_openssh_without_patch_level(self):
        self.assertEqual(
            self.gen.generate_cpe("openbsd", "openssh", "9.0"),
            "cpe:2.3:a:openbsd:openssh:9.0:*:*:*:*:*:*:*",
        )

    def test_unknown_parts_give_none(self):
        self.assertIsNone(self.gen.generate_cpe(None, "openssh", "8.9"))
        self.assertIsNone(self.gen.generate_cpe("openbsd", "unknown", "8.9"))
        self.assertIsNone(self.gen.generate_cpe("openbsd", "openssh", "unknown"))

    def test_no_match_gives_no_cpe(self):
        versions = VersionDetector().detect_versions({8080: "hello"})
        self.assertEqual(self.gen.generate_cpes(versions), {})

    def test_special_characters_are_escaped(self):
        cpe = self.gen.generate_cpe("v", "p", "1.0:beta")
        self.assertIn("1.0\\:beta", cpe)
        self.assertEqual(len(re.split(r"(?<!\\):", cpe)), 13)  # still 13 CPE fields


if __name__ == "__main__":
    unittest.main()
