class Target:
    def __init__(self, host):
        self.host = host

        # Milestone 1
        self.open_ports = []

        # Milestone 2
        self.services = {}

        # Milestone 3
        self.banners = {}

        # Milestone 4
        self.versions = {}

        # Milestone 5
        self.cpes = {}

        # Milestone 6
        self.cves = {}

        # Final findings: Dict[int, List[core.models.Finding]]
        self.findings = {}

        # Errors encountered during scan: List[ScanError]
        self.errors = []