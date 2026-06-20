
class SeverityScorer:

    def classify(self, cvss):

        if cvss is None:
            return "UNKNOWN"

        if cvss < 4.0:
            return "LOW"

        if cvss < 7.0:
            return "MEDIUM"

        if cvss < 9.0:
            return "HIGH"

        return "CRITICAL"


    def score_vulnerabilities(self, cves):

        results = {}

        for port, vulns in cves.items():

            results[port] = []

            for vuln in vulns:

                severity = self.classify(
                    vuln["cvss"]
                )

                results[port].append({

                    "id": vuln["id"],
                    "cvss": vuln["cvss"],
                    "severity": severity

                })

        return results

