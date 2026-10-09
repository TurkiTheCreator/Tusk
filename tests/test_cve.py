import unittest
from unittest import mock

import requests

from intelligence import cve as cve_mod
from intelligence.cve import CVELookup, RateLimiter, _pick_cvss


class FakeCache:
    def __init__(self):
        self.store = {}

    def get(self, key):
        return self.store.get(key)

    def set(self, key, value):
        self.store[key] = value


class FakeResponse:
    def __init__(self, status, body=None, headers=None):
        self.status_code = status
        self._body = body
        self.headers = headers or {}

    def json(self):
        return self._body


def nvd_body(metrics):
    return {"vulnerabilities": [{"cve": {"id": "CVE-2020-0001", "metrics": metrics}}]}


def make_lookup(**kw):
    lookup = CVELookup(cache=FakeCache(), **kw)
    lookup._limiter.wait = lambda: None  # no real waiting in tests
    return lookup


class LookupTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch("time.sleep")
        self.sleep = patcher.start()
        self.addCleanup(patcher.stop)

    def test_success_is_cached(self):
        lookup = make_lookup()
        lookup._session.get = mock.Mock(return_value=FakeResponse(200, nvd_body({})))
        first = lookup.lookup("cpe:x")
        second = lookup.lookup("cpe:x")
        self.assertTrue(first.ok)
        self.assertEqual(first.vulns[0]["id"], "CVE-2020-0001")
        self.assertIs(first, second)
        self.assertEqual(lookup._session.get.call_count, 1)

    def test_empty_result_is_ok_not_failure(self):
        lookup = make_lookup()
        lookup._session.get = mock.Mock(return_value=FakeResponse(200, {"vulnerabilities": []}))
        result = lookup.lookup("cpe:x")
        self.assertTrue(result.ok)
        self.assertEqual(result.vulns, [])

    def test_retryable_status_fails_and_is_not_cached(self):
        for status in (403, 429, 503):
            lookup = make_lookup(max_retries=2)
            lookup._session.get = mock.Mock(return_value=FakeResponse(status))
            result = lookup.lookup("cpe:x")
            self.assertFalse(result.ok)
            self.assertEqual(result.error, f"HTTP {status}")
            self.assertEqual(lookup._session.get.call_count, 3)  # 1 try + 2 retries
            self.assertNotIn("cpe:x", lookup._cache)
            self.assertEqual(lookup.cve_cache.store, {})

    def test_retry_then_success(self):
        lookup = make_lookup()
        lookup._session.get = mock.Mock(
            side_effect=[FakeResponse(429, headers={"Retry-After": "7"}),
                         FakeResponse(200, nvd_body({}))]
        )
        self.assertTrue(lookup.lookup("cpe:x").ok)
        self.sleep.assert_called_with(7)

    def test_timeout_is_a_failure(self):
        lookup = make_lookup(max_retries=0)
        lookup._session.get = mock.Mock(side_effect=requests.exceptions.Timeout("slow"))
        result = lookup.lookup("cpe:x")
        self.assertFalse(result.ok)
        self.assertIn("Timeout", result.error)

    def test_non_retryable_status_does_not_retry(self):
        lookup = make_lookup()
        lookup._session.get = mock.Mock(return_value=FakeResponse(404))
        self.assertFalse(lookup.lookup("cpe:x").ok)
        self.assertEqual(lookup._session.get.call_count, 1)

    def test_malformed_body_is_a_failure(self):
        lookup = make_lookup()
        lookup._session.get = mock.Mock(
            return_value=FakeResponse(200, {"vulnerabilities": [{"nope": 1}]})
        )
        self.assertFalse(lookup.lookup("cpe:x").ok)

    def test_api_key_header_and_limits(self):
        self.assertNotIn("apiKey", CVELookup(cache=FakeCache())._session.headers)
        self.assertEqual(CVELookup(cache=FakeCache())._limiter.max_calls, 5)
        keyed = CVELookup(cache=FakeCache(), api_key="secret")
        self.assertEqual(keyed._session.headers["apiKey"], "secret")
        self.assertEqual(keyed._limiter.max_calls, 50)

    def test_lookup_all_keeps_per_port_mapping(self):
        lookup = make_lookup()
        lookup._session.get = mock.Mock(return_value=FakeResponse(200, nvd_body({})))
        results = lookup.lookup_all({22: "cpe:a", 80: "cpe:b"})
        self.assertEqual(set(results), {22, 80})
        self.assertTrue(all(r.ok for r in results.values()))


class CVSSFallbackTests(unittest.TestCase):
    def entry(self, score, vector, type_="Primary"):
        return {"type": type_, "cvssData": {"baseScore": score, "vectorString": vector}}

    def test_prefers_newest_version(self):
        metrics = {
            "cvssMetricV2": [self.entry(5.0, "v2")],
            "cvssMetricV31": [self.entry(9.8, "v31")],
            "cvssMetricV40": [self.entry(8.0, "v40")],
        }
        self.assertEqual(_pick_cvss(metrics), (8.0, "v40"))
        del metrics["cvssMetricV40"]
        self.assertEqual(_pick_cvss(metrics), (9.8, "v31"))

    def test_falls_back_to_v30_then_v2(self):
        self.assertEqual(_pick_cvss({"cvssMetricV30": [self.entry(7.0, "v30")]}), (7.0, "v30"))
        self.assertEqual(_pick_cvss({"cvssMetricV2": [self.entry(7.5, "v2")]}), (7.5, "v2"))

    def test_prefers_primary_entry(self):
        metrics = {"cvssMetricV31": [self.entry(3.0, "sec", "Secondary"),
                                     self.entry(9.0, "nvd", "Primary")]}
        self.assertEqual(_pick_cvss(metrics), (9.0, "nvd"))

    def test_none_when_absent(self):
        self.assertEqual(_pick_cvss({}), (None, None))


class RateLimiterTests(unittest.TestCase):
    def test_blocks_when_window_is_full(self):
        clock = [0.0]
        sleeps = []

        def fake_sleep(seconds):
            sleeps.append(seconds)
            clock[0] += seconds

        with mock.patch.object(cve_mod.time, "monotonic", lambda: clock[0]), \
             mock.patch.object(cve_mod.time, "sleep", fake_sleep):
            limiter = RateLimiter(max_calls=2, period=30.0)
            limiter.wait()
            limiter.wait()
            self.assertEqual(sleeps, [])
            limiter.wait()  # third call must wait for the first to expire
            self.assertEqual(sleeps, [30.0])


if __name__ == "__main__":
    unittest.main()
