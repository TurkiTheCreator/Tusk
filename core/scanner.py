
from modules.ports import PortScanner
from modules.services import ServiceDetector
from modules.banners import BannerGrabber
from modules.versions import VersionDetector
from modules.cpe import CPEGenerator
from modules.cve import CVELookup
from modules.scoring import SeverityScorer


from core.logger import Logger


class Scanner:

    def __init__(self, threads=100):

        self.port_scanner = PortScanner(
            threads=threads
        )

        self.service_detector = ServiceDetector()

        self.banner_grabber = BannerGrabber()

        self.version_detector = VersionDetector()

        self.cpe_generator = CPEGenerator()

        self.cve_lookup = CVELookup()

        self.scorer = SeverityScorer()


    def run(self, target):

        try:
            ports = range(1, 1025)

            target.open_ports = self.port_scanner.scan_ports(
                target.host,
                ports
            )

            target.services = self.service_detector.detect_services(
                target.open_ports
            )

            target.banners = self.banner_grabber.grab_banners(
                target.host,
                target.open_ports
            )

            target.versions = self.version_detector.detect_versions(
                target.banners
            )

            target.cpes = self.cpe_generator.generate_cpes(
                target.versions
            )

            target.cves = self.cve_lookup.lookup_all(
                target.cpes
            )

            target.findings = self.scorer.score_vulnerabilities(
                target.cves
            )

        except KeyboardInterrupt:
            # Let cli.py handle clean output.
            raise
        except Exception as e:
            Logger.error(f"Internal scan error: {e}")
            # keep target partially filled; do not raise traceback
            if not hasattr(target, "findings") or target.findings is None:
                target.findings = {}


