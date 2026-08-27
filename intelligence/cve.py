import requests
from concurrent.futures import ThreadPoolExecutor
from requests.exceptions import Timeout, ConnectionError as ReqConnectionError, RequestException

from intelligence.cve_cache import CVECache


class CVELookup:
    def __init__(self, timeout=10, max_workers=10, cache=None):
        self.timeout = timeout
        self.max_workers = max_workers
        self._cache = {}
        self.cve_cache = cache if cache is not None else CVECache()

    def lookup(self, cpe):
        if cpe in self._cache:
            return self._cache[cpe]

        cached = self.cve_cache.get(cpe)
        if cached is not None:
            self._cache[cpe] = cached
            return cached

        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {"cpeName": cpe}

        try:
            response = requests.get(
                url,
                params=params,
                timeout=self.timeout,
            )
            response.raise_for_status()

            data = response.json()
            vulnerabilities = []

            for item in data.get("vulnerabilities", []):
                cve = item["cve"]
                cve_id = cve["id"]
                metrics = cve.get("metrics", {})

                cvss = None
                vector = None
                if "cvssMetricV31" in metrics:
                    cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
                    cvss = cvss_data["baseScore"]
                    vector = cvss_data.get("vectorString")

                # Captured (not yet consumed) for validation/version_range.py:
                # NVD's vulnerable-version-range data, previously discarded.
                version_ranges = cve.get("configurations", [])

                vulnerabilities.append({
                    "id": cve_id,
                    "cvss": cvss,
                    "vector": vector,
                    "version_ranges": version_ranges,
                })

            self._cache[cpe] = vulnerabilities
            self.cve_cache.set(cpe, vulnerabilities)
            return vulnerabilities

        except Timeout:
            self._cache[cpe] = []
            return []
        except ReqConnectionError:
            self._cache[cpe] = []
            return []
        except RequestException:
            self._cache[cpe] = []
            return []
        except Exception:
            self._cache[cpe] = []
            return []

    def lookup_all(self, cpes):
        # Concurrency with bounded workers, but preserve per-port mapping.
        results = {}
        items = list(cpes.items())

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_by_port = {
                port: executor.submit(self.lookup, cpe)
                for port, cpe in items
            }
            for port, future in future_by_port.items():
                results[port] = future.result()

        return results

