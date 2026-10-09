---
title: Phase 0 - Fix What Makes Results Wrong or Crashes
tags: [tusk, phase-0]
created: 2026-10-09
status: complete
baseline: 979f5e7
---

# Phase 0

> [!summary] Why Phase 0 existed
> Every CPE Tusk built was wrong for NVD, so real CVEs almost never came back. A clean report meant nothing. Phase 0 fixes what makes results wrong or crashes.

## Checklist

- [x] 1. NVD vendor/product names → [[#1 NVD vendor and product names]]
- [x] 2. OpenSSH patch level → [[#2 OpenSSH patch level]]
- [x] 3. NVD failure is not "no vulnerabilities" → [[#3 NVD failures]]
- [x] 4. API key, rate limit, retries → [[#4 API key rate limiting and retries]]
- [x] 5. CVSS v4/v3.0/v2 fallback → [[#5 CVSS fallback]]
- [x] 6. IPv6 in every probe → [[#6 IPv6 probes]]
- [x] 7. `getaddrinfo` instead of `gethostbyname` → [[#7 and 8 Resolve with getaddrinfo once]]
- [x] 8. Resolve once → same section
- [x] 9. Probe by behavior → [[#9 Probe by behavior]]
- [x] 10. Close the TLS socket → [[#10 Close the TLS socket]]
- [x] 11. Debug-level logging → [[#11 Debug logging]]
- [x] 12. Package-relative ruleset → [[#12 Ruleset path]]
- [x] 13. Catch `RuleEngineError` → [[#13 RuleEngineError]]
- [x] 14. Exit codes → [[#Exit codes]]
- [x] 15. Port validation and ranges → [[#15 Port parsing]]
- [x] 16. URL in `-u` → [[#16 URL targets]]
- [x] 17. Honest `--top-ports` → [[#17 top-ports]]
- [x] 18. HTTP analyzer on every web port → [[#18 HTTP analyzer]]
- [x] 19. No global urllib3 silencing → [[#19 urllib3 warnings]]


---

## Part 1: CVE matching
Files: `discovery/fingerprints.py`, `discovery/versions.py`, `intelligence/cpe.py`, `intelligence/cve.py`, `core/scanner.py`, `cli.py`

### 1 NVD vendor and product names

NVD only matches CPEs from its own dictionary. Tusk used the banner text (`apache:apache`), which never matches.

| Software | Before | After |
|---|---|---|
| OpenSSH | `openssh:openssh` | `openbsd:openssh` |
| Apache | `apache:apache` | `apache:http_server` |
| nginx | `nginx:nginx` | `f5:nginx` |
| vsftpd | `vsftpd:vsftpd` | `beasts:vsftpd` |

The dead `vendors` map in `CPEGenerator` is deleted. Its keys were capitalized (`"OpenSSH"`) but looked up with a lowercased product, so it could never match.

`discovery/fingerprints.py`:

```python
# before
    confidence: float = 0.5

# after
    confidence: float = 0.5
    nvd_vendor: str = ""    # vendor as it appears in the NVD CPE dictionary
    nvd_product: str = ""   # product as it appears in the NVD CPE dictionary
```

```python
Fingerprint(
    id="openssh",
    vendor="OpenSSH",
    product="OpenSSH",
    nvd_vendor="openbsd",
    nvd_product="openssh",
    ...
)
```

`discovery/versions.py` passes both fields through `candidate` and `extract_version`. `product` stays the display name (the CLI prints it).

`intelligence/cpe.py` now takes `(vendor, product, version)` from the `nvd_*` fields and returns `None` if any is unknown.

> [!tip] Escaping
> Values are backslash-escaped for CPE 2.3 special characters (anything except `a-z 0-9 . _ -`). A version like `1.2.3-beta` is safe; a `:` would no longer corrupt the string.

### 2 OpenSSH patch level

NVD stores `8.9p1` as version `8.9`, update `p1`.

```python
_OPENSSH_PATCH = re.compile(r"^(\d+(?:\.\d+)*)(p\d+)$", re.IGNORECASE)

update = "*"
if product == "openssh":
    m = _OPENSSH_PATCH.match(version)
    if m:
        version, update = m.group(1), m.group(2)
```

```text
8.9p1  ->  cpe:2.3:a:openbsd:openssh:8.9:p1:*:*:*:*:*:*
```

### 3 NVD failures

Before, `CVELookup.lookup` returned `[]` on timeout, 403 and 429 alike, and cached the `[]`. The report then said "No vulnerabilities found."

```python
@dataclass
class LookupResult:
    ok: bool
    vulns: List[dict] = field(default_factory=list)
    error: Optional[str] = None
```

- `lookup` returns a `LookupResult`; only `ok` results are cached.
- `core/scanner.py` unpacks `lookup_all`, and for each failed port appends `ScanError(stage="cve_lookup", ...)`.
- `cli.py` prints the failure instead of the all-clear:

```python
# before
if not found:
    print("No vulnerabilities found.")

# after
lookup_errors = [e for e in target.errors if e.stage == "cve_lookup"]
if lookup_errors:
    for e in lookup_errors:
        print(f"CVE lookup failed: {e.message}")
elif not found:
    print("No vulnerabilities found.")
```

A failed lookup also makes the exit code 3 (see [[#Exit codes]]).

### 4 API key, rate limiting and retries

- `nvd_api_key` flows `config` → `Scanner(nvd_api_key=...)` → `CVELookup(api_key=...)` and is sent as the `apiKey` header on a `requests.Session`.
- `RateLimiter` is a thread-safe sliding window: **5 requests per 30 s without a key, 50 with one**.
- Retries: 403, 429, 503 up to 3 times, sleeping `2**attempt` seconds, or `Retry-After` when the server sends it.

```python
class RateLimiter:
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
```

> [!note]
> Without a key, a scan with many CPEs is slow by design. Set `nvd_api_key` in `~/.config/tusk/config.toml` or `TUSK_NVD_API_KEY`.

### 5 CVSS fallback

```python
METRIC_KEYS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")

def _pick_cvss(metrics):
    for key in METRIC_KEYS:
        entries = metrics.get(key)
        if not entries:
            continue
        entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        data = entry["cvssData"]
        return data.get("baseScore"), data.get("vectorString")
    return None, None
```

Old CVEs that only have a v2 score no longer show severity `Unknown`. `models.severity_band(score)` needed no change.

---

## Part 2: Network layer
Files: `core/utils.py`, `core/logger.py`, `core/scanner.py`, `discovery/banners.py`

### 6 IPv6 probes

`_probe_ssh`, `_probe_ftp`, `_probe_smtp`, `_probe_smtps_implicit_tls` and the raw fallback hard-coded `AF_INET`.

```python
# before
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    sock.settimeout(self.timeout)
    sock.connect((host, port))

# after
sock = self._create_connection(host, port)
try:
```

No `AF_INET` is left in `banners.py`.

### 7 and 8 Resolve with getaddrinfo once

`gethostbyname` is IPv4-only, and `scan_port` called `getaddrinfo` once per port (65,535 lookups on `--full`). One cached lookup fixes both.

```python
@lru_cache(maxsize=256)
def _resolve_cached(host):
    try:
        infos = socket.getaddrinfo(host, 0, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError):
        return ()
    ...

def get_all_addresses(host, port):
    return [
        (family, socktype, proto, canon, (sockaddr[0], port, *sockaddr[2:]))
        for family, socktype, proto, canon, sockaddr in _resolve_cached(host)
    ]
```

- `(sockaddr[0], port, *sockaddr[2:])` works for IPv4 `(ip, port)` and IPv6 `(ip, port, flow, scope)`.
- Callers still pass the **hostname**, so the HTTP `Host:` header and TLS SNI stay correct. That is why the address list is cached instead of passing a raw IP down.
- `UnicodeError` is caught because a hostname like `"a" * 300` raises it, not `gaierror`.

### 9 Probe by behavior

Probes were chosen by port number, so HTTP on 8080 or SSH on 2222 got nothing. Now:

```python
def grab_banner(self, host, port):
    # Probes that must send something to get a full banner.
    if port == 465:
        return self._try(self._probe_smtps_implicit_tls, host, port)
    if port in (25, 587):
        return self._try(self._probe_smtp, host, port)
    if port == 21:
        return self._try(self._probe_ftp, host, port)

    banner = self._try(self._probe_passive, host, port)      # SSH, FTP, SMTP speak first
    if banner:
        return banner
    banner = self._try(self._probe_http, host, port)          # silent port: try HTTP
    if banner.startswith("HTTP/"):
        return banner
    return self._try(self._probe_https, host, port)           # then TLS
```

> [!warning] Cost
> A quiet or closed port can now use up to three connections, so `--banner-timeout` matters more.

### 10 Close the TLS socket

```python
# before: finally closed only `sock`
# after
finally:
    for s in (tls_sock, sock):
        if s:
            try:
                s.close()
            except Exception:
                pass
```

Applied to `_probe_https` and `_probe_smtps_implicit_tls`. `tls_sock = None` is set before `try` so a failed handshake still closes the raw socket.

### 11 Debug logging

A closed or quiet port is normal, so it no longer prints `[ERR] Banner grab error`.

```python
class Logger:
    verbose = False   # set by Scanner(debug=...)

    @staticmethod
    def debug(message):
        if Logger.verbose:
            print(f"[DBG] {message}")
```

`Scanner.__init__` sets `Logger.verbose = debug`, so `-v` shows these lines.

---

## Part 3: CLI and packaging
Files: `cli.py`, `discovery/analyzers/http_analyzer.py`, `core/config/config_manager.py`, `setup.py`, `rulesets/__init__.py`

### 12 Ruleset path

`rulesets/default` was relative to the current directory and not packaged, so `--http-headers` crashed outside the repo and after `pip install`.

```python
# config_manager.py
"ruleset_path": "",   # empty = ruleset bundled with Tusk

# http_analyzer.py
# <root>/discovery/analyzers/http_analyzer.py -> <root>/rulesets/default
DEFAULT_RULESET = Path(__file__).resolve().parents[2] / "rulesets" / "default"
...
self.ruleset_path = ruleset_path or DEFAULT_RULESET
```

Packaging needs both pieces:

```python
# setup.py
packages=find_packages(),
package_data={"rulesets": ["default/*.yaml"]},
```

plus an empty `rulesets/__init__.py`, otherwise `find_packages()` skips the directory.

> [!success] Verified
> Built a wheel, installed it in a clean venv, ran `tusk scan ... --http-headers` from `/`. The wheel contains `rulesets/default/*.yaml`.

### 13 RuleEngineError

```python
try:
    analyzer = HttpAnalyzer(...)
    http_headers_result = analyzer.analyze(target.host, target.open_ports, target.banners)
except RuleEngineError as e:
    Logger.error(f"Ruleset error: {e}")
    return 2
```

```text
[ERR] Ruleset error: Ruleset directory not found: /nonexistent
```

One line and exit code 2. See [[#Exit codes]].

### 15 Port parsing

```python
def parse_ports(spec):
    """'1-1024,8080' -> sorted unique list; raises ValueError on bad input."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = (int(x) for x in part.split("-", 1))
            if lo > hi:
                raise ValueError(f"reversed range: {part}")
            ports.update(range(lo, hi + 1))
        else:
            ports.add(int(part))
    if not ports or min(ports) < 1 or max(ports) > 65535:
        raise ValueError("ports must be within 1-65535")
    return sorted(ports)
```

Bad input is rejected at the CLI edge with `parser.error` (exit 2) instead of failing later as "Port discovery failed".

### 16 URL targets

```python
def parse_target(raw):
    """'https://host:8443/x' -> ('host', 8443); bare 'host' -> ('host', None)."""
    raw = raw.strip()
    if "://" in raw:
        parsed = urlparse(raw)
        return parsed.hostname, parsed.port
    return raw, None
```

- `-u https://host:8443/` scans `host`. If no `-p`, `--top-ports` or `--full` is given, it scans the URL's port.
- `--target` is an alias for `-u/--url`.
- Bare `::1` has no scheme, so it is passed through untouched.

### 17 top-ports

`TOP_PORTS` holds 100 entries, so `--top-ports 1000` silently scanned 100. Now:

```python
if not 1 <= args.top_ports <= len(TOP_PORTS):
    parser.error(f"--top-ports must be between 1 and {len(TOP_PORTS)}")
```

> [!todo]
> A real top-1000 list (nmap `nmap-services` frequencies) would replace the cap later.

### 18 HTTP analyzer

It only looked at ports 80 and 443. Now it probes every open port that looks like web:

```python
HTTP_PORTS = {80, 81, 443, 3000, 5000, 8000, 8008, 8080, 8081, 8443, 8888}
HTTPS_FIRST = {443, 8443}

for port in open_ports:
    if port not in HTTP_PORTS and not banners.get(port, "").startswith("HTTP/"):
        continue
    schemes = ("https", "http") if port in HTTPS_FIRST else ("http", "https")
    for scheme in schemes:
        found = self._collect_evidence(host, port, scheme)
        if found:
            evidence.extend(found)
            break
```

The banner from [[#9 Probe by behavior]] lets it catch web servers on unusual ports.

HSTS only applies over HTTPS:

```python
if name == "Strict-Transport-Security" and scheme != "https":
    continue
```

The analyzer timeout now comes from `config.get("cve_timeout")` instead of `args.cve_timeout or 10`.

### 19 urllib3 warnings

The module-level `urllib3.disable_warnings(...)` is gone. It now runs inside `analyze()` only when `--insecure` is set, next to the existing `Logger.warning`.

---

## Exit codes

| Code | Meaning | Examples |
|---|---|---|
| 0 | Clean scan | no findings, no errors |
| 1 | Findings | at least one CVE returned |
| 2 | Usage or input error | bad port, bad `--top-ports`, DNS failure, bad ruleset |
| 3 | Scan error | port discovery failed, CVE lookup failed, output file could not be written |
| 130 | Interrupted | Ctrl+C |

3 beats 1: a scan that errored cannot honestly claim to be clean or to have complete findings.

```python
if target.errors:
    return 3
if any(target.findings.values()):
    return 1
return 0
```

```python
if __name__ == "__main__":
    sys.exit(main())
```

"Port discovery failed" returns 3 right after `scanner.run`, so no report is printed.

CI usage:

```bash
tusk scan -u staging.example.com --top-ports 100
case $? in
  0) echo clean ;;
  1) echo "findings, fail the build" ; exit 1 ;;
  *) echo "scan did not complete" ; exit 1 ;;
esac
```

---

## Automated tests

Run from the repo root. They use only the standard library (`unittest`), need no network, and take about 2 seconds.

```bash
python -m unittest discover -s tests -t .
```

| File | Covers |
|---|---|
| `tests/test_cpe.py` | NVD names, OpenSSH `8.9p1` → `8.9:p1`, unknown parts, escaping |
| `tests/test_cve.py` | success caching, 403/429/503 retries, timeouts not cached, `Retry-After`, API key, rate limiter, CVSS v4/v3.1/v3.0/v2 fallback |
| `tests/test_network.py` | IPv4 and IPv6 resolve, one DNS lookup per host, banners on non-standard ports (SSH, HTTP, IPv6), closed port is silent, no `AF_INET` left |
| `tests/test_cli.py` | `parse_ports`, `parse_target`, every exit code, "CVE lookup failed" message, URL target, `--target` |
| `tests/test_http_analyzer.py` | HSTS only on HTTPS, every web port probed, scheme fallback, urllib3 not silenced, package-relative ruleset, one-line ruleset error, packaging files |
| `tests/test_scanner.py` | failed NVD lookup becomes a `ScanError`, API key reaches the lookup, `-v` sets the logger |

> [!note]
> Tests start throwaway local sockets on `127.0.0.1` and `::1`. The IPv6 tests skip themselves if the machine has no IPv6 loopback.

## Manual testing recipes

How each Phase 0 fix was checked.

### CPE output

```bash
python -c "
from intelligence.cpe import CPEGenerator as G
from discovery.versions import VersionDetector as V
d = V().detect_versions({22:'SSH-2.0-OpenSSH_8.9p1 Ubuntu', 80:'Server: Apache/2.4.41',
                         443:'Server: nginx/1.18.0', 21:'220 (vsFTPd 3.0.3)'})
for p, c in G().generate_cpes(d).items(): print(p, c)"
```

Expected:

```text
22 cpe:2.3:a:openbsd:openssh:8.9:p1:*:*:*:*:*:*
80 cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*
443 cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*
21 cpe:2.3:a:beasts:vsftpd:3.0.3:*:*:*:*:*:*:*
```

### NVD failure and CVSS fallback

Mock `CVELookup._session.get` to return a 429 and check `result.ok is False` and that nothing was cached. Return a body with only `cvssMetricV2` and check `vulns[0]["cvss"] == 7.5`.

### Banners

Start small servers and probe them:

- SSH-style banner on a non-standard port (2222)
- same on IPv6 `[::1]`
- plain HTTP server (8099)
- TLS HTTP server (`openssl req -x509 ...`)
- a closed port, which must return `""` without an `[ERR]` line

Then `tusk scan -u ::1 -p 2223` must not print "DNS lookup failed".

### CLI

```bash
tusk scan -u 127.0.0.1 -p 70000        ; echo $?   # 2
tusk scan -u 127.0.0.1 -p 9-1          ; echo $?   # 2
tusk scan -u 127.0.0.1 --top-ports 1000; echo $?   # 2
tusk scan -u nope.invalid -p 80        ; echo $?   # 2
tusk scan -u http://127.0.0.1:8099/    ; echo $?   # scans 8099
TUSK_RULESET_PATH=/nonexistent tusk scan -u 127.0.0.1 -p 8099 --http-headers ; echo $?  # 2
```

### Packaging

Build in a scratch copy so the repo stays clean:

```bash
pip wheel . --no-deps -w ../whl
unzip -l ../whl/*.whl | grep rulesets
python -m venv venv && venv/bin/pip install ../whl/*.whl
cd / && venv/bin/tusk scan -u 127.0.0.1 -p 8098 --http-headers
```

> [!note]
> Scans that find an nginx or Apache banner call the real NVD API, so they are slow without a key and can fail on rate limits. That is expected.

---

## Known leftovers

> [!warning] Not in the Phase 0 list
> - `ServiceDetector` still guesses the service from the port number, so the SERVICE column says `unknown` for non-standard ports.
> - `--cvss` runs the CVSS 3.1 calculator only; v2/v4 vectors print "unavailable".
> - `_probe_ssh` in `banners.py` is now unused (the passive probe replaced it).
> - Tracked `__pycache__/*.pyc` files and `Tusk.egg-info/` should be untracked and added to `.gitignore`.
> - `TODO.md` and `notes.md` are still stale.
