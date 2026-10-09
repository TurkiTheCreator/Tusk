import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import List, Optional

import requests
from requests.exceptions import RequestException

from intelligence.cve_cache import CVECache

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RETRY_STATUSES = (403, 429, 503)
# Newest metric version first; fall back to older ones for old CVEs.
METRIC_KEYS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


@dataclass
class LookupResult:
    ok: bool
    vulns: List[dict] = field(default_factory=list)
    error: Optional[str] = None


class RateLimiter:
    """Sliding window: at most `max_calls` in any `period` seconds, thread-safe."""

    def __init__(self, max_calls, period=30.0):
        self.max_calls = max_calls
        self.period = period
        self._calls = deque()
        self._lock = threading.Lock()

    def wait(self):
        while True:
            with self._lock:
                now = time.monotonic()
                while self._calls and now - self._calls[0] >= self.period:
                    self._calls.popleft()
                if len(self._calls) < self.max_calls:
                    self._calls.append(now)
                    return
                sleep_for = self.period - (now - self._calls[0])
            time.sleep(sleep_for)


def _pick_cvss(metrics):
    for key in METRIC_KEYS:
        entries = metrics.get(key)
        if not entries:
            continue
        entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        data = entry["cvssData"]
        return data.get("baseScore"), data.get("vectorString")
    return None, None


class CVELookup:
    def __init__(self, timeout=10, max_workers=10, cache=None, api_key="", max_retries=3):
        self.timeout = timeout
        self.max_workers = max_workers
        self.max_retries = max_retries
        self._cache = {}
        self.cve_cache = cache if cache is not None else CVECache()

        self._session = requests.Session()
        if api_key:
            self._session.headers["apiKey"] = api_key
        # NVD: 5 requests / 30 s without a key, 50 with one.
        self._limiter = RateLimiter(50 if api_key else 5)

    def _parse(self, data):
        vulnerabilities = []
        for item in data.get("vulnerabilities", []):
            cve = item["cve"]
            cvss, vector = _pick_cvss(cve.get("metrics", {}))
            # Captured (not yet consumed) for validation/version_range.py.
            vulnerabilities.append({
                "id": cve["id"],
                "cvss": cvss,
                "vector": vector,
                "version_ranges": cve.get("configurations", []),
            })
        return vulnerabilities

    def _fetch(self, cpe):
        last_error = "unknown error"
        for attempt in range(self.max_retries + 1):
            delay = 2 ** attempt
            self._limiter.wait()
            try:
                response = self._session.get(
                    NVD_URL, params={"cpeName": cpe}, timeout=self.timeout
                )
            except RequestException as e:
                last_error = f"{type(e).__name__}: {e}"
            else:
                if response.status_code == 200:
                    try:
                        return LookupResult(True, self._parse(response.json()))
                    except (ValueError, KeyError) as e:
                        return LookupResult(False, error=f"bad NVD response: {e}")

                last_error = f"HTTP {response.status_code}"
                if response.status_code not in RETRY_STATUSES:
                    return LookupResult(False, error=last_error)
                retry_after = response.headers.get("Retry-After", "")
                if retry_after.isdigit():
                    delay = int(retry_after)

            if attempt < self.max_retries:
                time.sleep(delay)
        return LookupResult(False, error=last_error)

    def lookup(self, cpe):
        if cpe in self._cache:
            return self._cache[cpe]

        cached = self.cve_cache.get(cpe)
        if cached is not None:
            result = LookupResult(True, cached)
            self._cache[cpe] = result
            return result

        result = self._fetch(cpe)
        if result.ok:  # never cache failures
            self._cache[cpe] = result
            self.cve_cache.set(cpe, result.vulns)
        return result

    def lookup_all(self, cpes):
        # Concurrency with bounded workers, but preserve per-port mapping.
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {port: executor.submit(self.lookup, cpe) for port, cpe in cpes.items()}
            return {port: f.result() for port, f in futures.items()}
