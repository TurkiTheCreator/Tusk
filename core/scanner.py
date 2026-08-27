"""Scanner orchestrator: coordinates pipeline stages and error handling."""

import traceback

from discovery.ports import PortScanner
from discovery.services import ServiceDetector
from discovery.banners import BannerGrabber
from discovery.versions import VersionDetector
from intelligence.cpe import CPEGenerator
from intelligence.cve import CVELookup

from core.logger import Logger
from core.models import CandidateCVE, Finding, ScanError


class Scanner:

    def __init__(self, threads=100, port_timeout=0.5, banner_timeout=2, cve_timeout=10, cve_workers=10, debug=False):
        # Note: fast port scan timeout improves speed, but keep banners/CVE slower for reliability.
        self.debug = debug
        self.port_scanner = PortScanner(
            threads=threads,
            timeout=port_timeout,
        )

        self.service_detector = ServiceDetector()

        self.banner_grabber = BannerGrabber(timeout=banner_timeout)

        self.version_detector = VersionDetector()

        self.cpe_generator = CPEGenerator()

        self.cve_lookup = CVELookup(timeout=cve_timeout, max_workers=cve_workers)


    def run(self, target):
        """Execute the full scan pipeline, preserving partial results on stage failure."""
        if not hasattr(target, "errors"):
            target.errors = []

        try:
            ports = getattr(target, "ports", None)
            if ports is None:
                # Preserve existing behavior if no ports were provided.
                ports = range(1, 1025)
            else:
                ports = list(ports)

            try:
                target.open_ports = self.port_scanner.scan_ports(
                    target.host,
                    ports
                )
            except Exception as e:
                target.errors.append(
                    ScanError(
                        stage="port_discovery",
                        message=str(e),
                        exception_type=type(e).__name__,
                        traceback=traceback.format_exc() if self.debug else None,
                    )
                )
                Logger.error(f"Port discovery failed: {e}")
                if self.debug:
                    Logger.error(traceback.format_exc())
                return

            try:
                target.services = self.service_detector.detect_services(
                    target.open_ports
                )
            except Exception as e:
                target.errors.append(
                    ScanError(
                        stage="service_detection",
                        message=str(e),
                        exception_type=type(e).__name__,
                        traceback=traceback.format_exc() if self.debug else None,
                    )
                )
                Logger.error(f"Service detection failed: {e}")
                if self.debug:
                    Logger.error(traceback.format_exc())

            try:
                target.banners = self.banner_grabber.grab_banners(
                    target.host,
                    target.open_ports
                )
            except Exception as e:
                target.errors.append(
                    ScanError(
                        stage="banner_grabbing",
                        message=str(e),
                        exception_type=type(e).__name__,
                        traceback=traceback.format_exc() if self.debug else None,
                    )
                )
                Logger.error(f"Banner grabbing failed: {e}")
                if self.debug:
                    Logger.error(traceback.format_exc())

            try:
                target.versions = self.version_detector.detect_versions(
                    target.banners
                )
            except Exception as e:
                target.errors.append(
                    ScanError(
                        stage="version_detection",
                        message=str(e),
                        exception_type=type(e).__name__,
                        traceback=traceback.format_exc() if self.debug else None,
                    )
                )
                Logger.error(f"Version detection failed: {e}")
                if self.debug:
                    Logger.error(traceback.format_exc())

            try:
                target.cpes = self.cpe_generator.generate_cpes(
                    target.versions
                )
            except Exception as e:
                target.errors.append(
                    ScanError(
                        stage="cpe_generation",
                        message=str(e),
                        exception_type=type(e).__name__,
                        traceback=traceback.format_exc() if self.debug else None,
                    )
                )
                Logger.error(f"CPE generation failed: {e}")
                if self.debug:
                    Logger.error(traceback.format_exc())

            try:
                target.cves = self.cve_lookup.lookup_all(
                    target.cpes
                )
            except Exception as e:
                target.errors.append(
                    ScanError(
                        stage="cve_lookup",
                        message=str(e),
                        exception_type=type(e).__name__,
                        traceback=traceback.format_exc() if self.debug else None,
                    )
                )
                Logger.error(f"CVE lookup failed: {e}")
                if self.debug:
                    Logger.error(traceback.format_exc())

            target.findings = {
                port: [
                    Finding.from_candidate(CandidateCVE.from_dict(d))
                    for d in vulns
                ]
                for port, vulns in target.cves.items()
            }

        except KeyboardInterrupt:
            # Let cli.py handle clean output.
            raise
