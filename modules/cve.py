import requests
from requests.exceptions import Timeout, ConnectionError as ReqConnectionError, RequestException



class CVELookup:

    def lookup(self, cpe):
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

        params = {
            "cpeName": cpe
        }

        try:
            response = requests.get(
                url,
                params=params,
                timeout=10
            )

            response.raise_for_status()

            data = response.json()

            vulnerabilities = []

            for item in data.get(
                "vulnerabilities",
                []
            ):

                cve = item["cve"]

                cve_id = cve["id"]

                metrics = cve.get(
                    "metrics",
                    {}
                )

                cvss = None

                if "cvssMetricV31" in metrics:

                    cvss = metrics[
                        "cvssMetricV31"
                    ][0]["cvssData"]["baseScore"]

                vulnerabilities.append({

                    "id": cve_id,
                    "cvss": cvss

                })

            return vulnerabilities

        except Timeout:
            # Network timeout should not fail the whole scan.
            return []
        except ReqConnectionError:
            return []
        except RequestException:
            return []
        except Exception:
            return []


    def lookup_all(self, cpes):

        results = {}

        for port, cpe in cpes.items():

            results[port] = self.lookup(
                cpe
            )

        return results


