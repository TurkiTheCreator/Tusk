# Tusk Development Notes

## Phase 0: Stabilize the Core

**Priority:** Critical  
**Recommended sequence position:** 1 of 12  
**Status:** Planned  
**Classification:** Confidential - Internal Engineering Use

**Scope:** Complete these changes before major feature work. Phase 0 hardens the network boundary, validates intelligence data before it reaches NVD, and makes scanner failures diagnosable without losing partial results. The snippets below are implementation plans; source code has not been modified by this document.

**Phase 0 goals:**

- Replace IPv4-only socket assumptions with address-family-aware connections.
- Support IPv4, IPv6, and dual-stack hostname resolution.
- Verify HTTPS certificates by default and make insecure mode explicit.
- Reject, normalize, and validate CPE fields before CVE lookup.
- Preserve partial scan results while identifying the failed pipeline stage.
- Add structured scan errors and a debug/verbose error mode.
- Keep one authoritative application entry point and a reproducible baseline.

## Phase 0 Required Changes

### 0.1 Replace IPv4-Only Socket Handling

**Files:** `discovery/ports.py`, `discovery/banners.py`, `core/utils.py`

**Current code:**

```python
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(self.timeout)

try:
    result = sock.connect_ex((host, port))
```

**Proposed code:**

```python
for family, socktype, proto, _, address in socket.getaddrinfo(
    host, port, type=socket.SOCK_STREAM
):
    sock = socket.socket(family, socktype, proto)
    sock.settimeout(self.timeout)
    try:
        if sock.connect_ex(address) == 0:
            return port
    finally:
        sock.close()

return None
```

**Explanation:**

`AF_INET` hard-codes IPv4 and fails for IPv6-only targets. `getaddrinfo()` returns all usable address families and the complete address tuple required by IPv4 and IPv6 sockets. The implementation must try each resolved address, close every socket, and treat a successful connection to any address as an open port. Banner probes must use the same address-family-aware connection helper so discovery and banner stages cannot disagree about reachability.

**Required behavior:**

- IPv4 literal and IPv4 hostname targets work.
- IPv6 literals and IPv6-only hostnames work.
- Dual-stack hosts try both families.
- Failed addresses do not prevent later addresses from being tried.
- Every socket is closed on success, refusal, timeout, and unexpected error.

**Required tests:**

```python
def test_scanner_tries_ipv4_and_ipv6_addresses(monkeypatch):
    # Return one failing address followed by one successful address.
    # Assert both address tuples are attempted and the socket is closed.
    ...
```

Add integration coverage using local IPv4 and IPv6 loopback listeners where IPv6 is available. Skip only the IPv6 test when the host environment does not provide an IPv6 loopback interface.

### 0.2 Make HTTPS Certificate Verification Explicit

**Files:** `discovery/analyzers/http_analyzer.py`, `cli.py`

**Current code:**

```python
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

response = requests.get(
    url,
    timeout=self.timeout,
    verify=False,
    allow_redirects=True,
)
```

**Proposed code:**

```python
class HttpAnalyzer:
    def __init__(
        self,
        timeout: float = 10,
        ruleset_path: str = "rulesets/default",
        insecure: bool = False,
    ):
        self.timeout = timeout
        self.ruleset_path = ruleset_path
        self.insecure = insecure

response = requests.get(
    url,
    timeout=self.timeout,
    verify=not self.insecure,
    allow_redirects=True,
)
```

**CLI addition:**

```python
parser.add_argument(
    "--insecure",
    action="store_true",
    help="Disable HTTPS certificate verification (use only for authorized testing)",
)
```

**Use at the call site:**

```python
analyzer = HttpAnalyzer(
    timeout=args.cve_timeout if args.cve_timeout else 10,
    ruleset_path=config.get("ruleset_path"),
    insecure=args.insecure,
)
```

**Explanation:**

Certificate verification must be enabled by default. Suppressing warnings globally and always using `verify=False` hides a security-relevant condition. When `--insecure` is present, emit a visible warning before probing HTTPS, such as `HTTPS certificate verification is disabled`. The warning must not appear during normal verified scans.

**Required tests:**

- A certificate signed by the configured trust store succeeds with default settings.
- A self-signed or invalid certificate fails or returns no HTTPS evidence by default.
- `insecure=True` allows the self-signed test server and emits the warning.
- HTTP port 80 behavior is unchanged.

### 0.3 Validate and Normalize CPE Generation

**File:** `intelligence/cpe.py`

**Current code:**

```python
vendor = self.vendors.get(
    product,
    product.lower()
)

return (
    f"cpe:2.3:a:{vendor}:"
    f"{product.lower()}:{version}:*:*:*:*:*:*:*"
)
```

**Proposed code:**

```python
def generate_cpe(self, product, version, vendor=None):
    product = self._normalize_field(product)
    version = self._normalize_field(version)
    vendor = self._normalize_field(vendor or self.vendors.get(product, product))

    if product == "unknown" or version == "unknown":
        return None

    cpe = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
    self._validate_cpe(cpe)
    return cpe

def generate_cpes(self, versions):
    cpes = {}
    for port, info in versions.items():
        cpe = self.generate_cpe(
            info.get("product", "unknown"),
            info.get("version", "unknown"),
            info.get("vendor"),
        )
        if cpe is not None:
            cpes[port] = cpe
    return cpes
```

**Explanation:**

The CPE stage must reject both unknown products and unknown versions. Vendor, product, and version values should be trimmed, normalized, and escaped according to the CPE 2.3 formatted-string rules before construction. Validation must happen at this boundary, so malformed CPEs cannot reach `CVELookup.lookup()`.

`generate_cpe()` should raise a dedicated validation error for malformed non-unknown fields or return `None` for intentionally incomplete detections. The caller must never silently convert an invalid value into an NVD request.

**Required tests:**

```python
def test_unknown_product_and_version_are_rejected():
    assert CPEGenerator().generate_cpes({80: {
        "product": "unknown",
        "version": "unknown",
    }}) == {}


def test_generated_cpe_has_expected_fields():
    cpe = CPEGenerator().generate_cpes({22: {
        "vendor": "OpenSSH",
        "product": "OpenSSH",
        "version": "8.9p1",
    }})[22]
    assert cpe.startswith("cpe:2.3:a:")
    assert ":unknown:" not in cpe
```

### 0.4 Add Stage-Aware Scanner Errors

**Files:** `core/scanner.py`, `core/models.py`

**Current code:**

```python
        except Exception as e:
            Logger.error(f"Internal scan error: {e}")
            if not hasattr(target, "findings") or target.findings is None:
                target.findings = {}
```

**Proposed code:**

```python
        except KeyboardInterrupt:
            raise
        except Exception as error:
            target.errors.append(
                ScanError(
                    stage=stage,
                    message=str(error),
                    exception_type=type(error).__name__,
                    traceback=traceback.format_exc() if self.debug else None,
                )
            )
            Logger.error(f"{stage} stage failed: {error}")
            if self.debug:
                Logger.error(traceback.format_exc())
```

**Supporting model:**

```python
@dataclass
class ScanError:
    stage: str
    message: str
    exception_type: str
    traceback: Optional[str] = None
```

**Target initialization:**

```python
self.errors = []
```

**Explanation:**

One broad handler currently hides which pipeline stage failed and gives callers no machine-readable failure information. Each stage should run with an explicit stage name, append a `ScanError`, and preserve all fields populated before the failure. Debug output may include a traceback; normal output should include only the stage, exception type, and safe message. Keyboard interrupts remain separate so cancellation is not mislabeled as an internal defect.

The JSON report must include serialized scan errors without exposing secrets, request headers, API keys, or unnecessary traceback data unless debug mode was explicitly enabled.

**Required tests:**

- A mocked port-stage failure records `stage="port_discovery"` and preserves an empty but valid result.
- A banner-stage failure preserves discovered ports and services.
- A CVE-stage failure preserves CPEs and records the CVE stage error.
- Debug mode includes traceback data; normal mode does not.
- Ctrl+C is re-raised to the CLI interrupt handler.

### 0.5 Add Debug / Verbose Error Mode

**Files:** `cli.py`, `core/scanner.py`

**Current code:**

```python
except Exception as e:
    Logger.error(f"Scan failed: {e}")
    return
```

**Proposed code:**

```python
parser.add_argument(
    "-v",
    "--verbose",
    action="store_true",
    help="Show stage details and tracebacks for debugging",
)

scanner = Scanner(
    threads=config.get("threads"),
    port_timeout=config.get("port_timeout"),
    banner_timeout=config.get("banner_timeout"),
    cve_timeout=config.get("cve_timeout"),
    cve_workers=config.get("cve_workers"),
    debug=args.verbose,
)
```

**Explanation:**

Normal users need concise, actionable errors. Developers need stage context and tracebacks when diagnosing failures. The mode must be opt-in, must not change the scan result semantics, and must not log credentials or API keys. Help output, README usage, and JSON report behavior must document the option.

## Phase 0 Verification Matrix

| Area | Verification | Required result |
| --- | --- | --- |
| IPv4 | Local IPv4 listener scan | Port is found and banner is captured |
| IPv6 | Local IPv6 listener scan where supported | Port is found and banner is captured |
| Dual stack | Hostname resolving to both families | Both families are attempted without duplicate failures |
| HTTPS | Trusted certificate | Evidence is collected by default |
| HTTPS | Self-signed certificate | Rejected by default; accepted only with `--insecure` |
| CPE | Unknown product/version | No CPE and no CVE request |
| CPE | Normal product/version | Validated CPE is passed to lookup |
| Errors | Failure in each pipeline stage | Stage-aware structured error and partial result |
| Debug | `--verbose` | Traceback available without leaking secrets |

## Phase 0 Exit Criteria

- [ ] All socket paths use address-family-aware resolution.
- [ ] IPv4, IPv6, and dual-stack tests pass or unsupported IPv6 environments are explicitly skipped.
- [ ] HTTPS verification defaults to enabled.
- [ ] `--insecure` is explicit and visibly warned about.
- [ ] Valid and invalid certificate tests pass.
- [ ] Unknown CPE fields are rejected.
- [ ] Generated CPEs are validated before NVD lookup.
- [ ] Scanner errors identify their pipeline stage.
- [ ] Partial scan data survives later-stage failures.
- [ ] Structured errors are included in reports.
- [ ] `--verbose` enables diagnostic tracebacks without secret leakage.
- [ ] Existing compile, CLI help, localhost scan, installation, and Docker checks still pass.

## Change 1: Remove Legacy Empty Modules

**Files:** `main.py`, `main_fixed.py`, `modules/__init__.py`, `modules/ports.py`, `modules/services.py`, `modules/banner_grab.py`

**Current code:**

```python
# main.py

# main_fixed.py

# modules/ports.py
# modules/services.py
# modules/banner_grab.py
```

**Proposed change:**

```text
Delete main.py and main_fixed.py.
Delete the empty modules/ package.
Keep cli.py as the console entry point.
```

**Explanation:**

These files contain no implementation and are not imported by the active scanner. Their names overlap with the architecture described in the old README, so they create ambiguity about which code is authoritative. Removing them makes the actual layout explicit and prevents future work from being added to dead files.

**Verification:**

```powershell
python -m compileall .
python cli.py --help
python cli.py scan -u localhost --top-ports 10
```

## Change 2: Reject Unknown Versions Before CPE Generation

**File:** `intelligence/cpe.py`

**Current code:**

```python
        for port, info in versions.items():

            product = info["product"]
            version = info["version"]

            if product != "unknown":

                cpes[port] = self.generate_cpe(
                    product,
                    version
                )
```

**Proposed change:**

```python
        for port, info in versions.items():
            product = str(info.get("product", "unknown")).strip()
            version = str(info.get("version", "unknown")).strip()

            if product == "unknown" or version == "unknown":
                continue

            cpes[port] = self.generate_cpe(product, version)
```

**Explanation:**

A detected product without a usable version cannot produce a meaningful version-specific CPE. The current implementation filters only unknown products, allowing values such as `...:apache:unknown:*...` to reach NVD lookup. This change also uses `.get()` so incomplete detector records do not cause a `KeyError`.

**Verification:**

```powershell
python -c "from intelligence.cpe import CPEGenerator; assert CPEGenerator().generate_cpes({80: {'product': 'Apache', 'version': 'unknown'}}) == {}; print('CPE_UNKNOWN_VERSION_OK')"
```

## Change 3: Declare Supported Python Versions

**File:** `setup.py`

**Current code:**

```python
setup(
    name="Tusk",
    version="0.1",
    description="Lightweight vulnerability scanner",

    py_modules=["cli"],
    packages=find_packages(),
```

**Proposed change:**

```python
setup(
    name="Tusk",
    version="0.1",
    description="Lightweight vulnerability scanner",
    python_requires=">=3.11",

    py_modules=["cli"],
    packages=find_packages(),
```

**Explanation:**

`core/config/config_manager.py` uses `tomllib` when available and falls back to `tomli` for older Python versions, while the Docker image targets Python 3.13. Declaring the supported range makes installation behavior explicit. Python 3.11 is the conservative minimum for the current implementation because `tomllib` is included in the standard library there.

**Verification:**

```powershell
python -m pip install -e .
python -c "import importlib.metadata; print(importlib.metadata.metadata('Tusk')['Requires-Python'])"
```

## Change 4: Synchronize the README With the Active Tree

**File:** `README.md`

**Current code/documentation:**

```text
├── modules/
│   ├── ports.py
│   ├── banners.py
│   ├── versions.py
│   ├── cpe.py
│   └── cve_lookup.py
```

**Proposed change:**

```text
├── cli.py
├── core/
│   ├── config/
│   ├── engine/
│   ├── models.py
│   ├── scanner.py
│   └── target.py
├── discovery/
│   ├── analyzers/
│   ├── banners.py
│   ├── fingerprints.py
│   ├── ports.py
│   ├── services.py
│   └── versions.py
├── intelligence/
│   ├── cpe.py
│   ├── cve.py
│   └── cve_cache.py
├── rulesets/default/
├── scoring/cvss.py
├── requirements.txt
├── setup.py
└── Dockerfile
```

**Explanation:**

The README currently describes a `modules/` layout that is not the active implementation. Updating the structure in Phase 0 prevents developers from editing empty legacy files and documents the real pipeline. The usage section should also include the currently supported `--cvss`, `--http-headers`, timeout, worker, and `config init` options.

**Verification:**

```powershell
python cli.py --help
python cli.py config init
```

## Change 5: Replace Blank TODO Items With Trackable Work

**File:** `TODO.md`

**Current code:**

```markdown
## Priority 1 — Error Handling

- [ ]
- [ ]
- [ ]
- [ ]
- [ ]
- [ ]
- [ ]
```

**Proposed change:**

```markdown
## Phase 0 — Baseline

- [ ] Remove empty legacy entry points and modules.
- [ ] Reject unknown versions before CPE generation.
- [ ] Declare the supported Python version.
- [ ] Synchronize README structure and command examples.
- [ ] Add baseline automated tests.

## Priority 1 — Error Handling

- [ ] Return structured errors for failed scanner stages.
- [ ] Distinguish NVD failures from empty CVE results.
- [ ] Validate target, port, thread, and timeout values.
```

**Explanation:**

Blank checklist items cannot be assigned, reviewed, or verified. Replacing them with concrete work items gives Phase 0 an auditable completion condition and keeps the existing roadmap aligned with the actual code.

## Change 6: Add a Minimal Test Baseline

**New file:** `tests/test_baseline.py`

**Current code:**

```text
No test directory or automated test files exist.
```

**Proposed change:**

```python
from core.target import Target
from discovery.versions import VersionDetector
from intelligence.cpe import CPEGenerator


def test_target_starts_empty():
    target = Target("localhost")
    assert target.open_ports == []
    assert target.cves == {}


def test_unknown_banner_does_not_create_cpe():
    versions = VersionDetector().detect_versions({80: ""})
    assert CPEGenerator().generate_cpes(versions) == {}
```

**Explanation:**

These tests cover the initial object contract and the most important Phase 0 data-quality rule. They do not contact external systems, so they remain fast and deterministic. Later phases should add socket, CLI, HTTP, cache, CVSS, and NVD failure-path tests.

**Verification:**

```powershell
python -m pytest -q
```

## Change 7: Clean Generated Artifacts From the Source Tree

**Files:** generated `__pycache__/` directories and `*.pyc` files

**Current code:**

```text
__pycache__/
core/__pycache__/
discovery/__pycache__/
*.pyc
```

**Proposed change:**

```text
Remove generated bytecode from the working tree and keep it excluded through .gitignore.
```

**Explanation:**

Bytecode is environment-generated output, not source. It can make recursive audits noisy and can obscure whether a clean checkout is reproducible. The existing `.dockerignore` excludes these files for builds, but a repository-level `.gitignore` should also exclude them.

**Verification:**

```powershell
git status --short
python -m compileall .
```

## Phase 0 Completion Checklist

- [ ] Empty legacy files removed.
- [ ] Only `cli.py` remains the documented CLI entry point.
- [ ] Unknown product/version data cannot create CPEs.
- [ ] Python compatibility is declared in package metadata.
- [ ] README matches the actual tree and CLI.
- [ ] TODO.md contains actionable items.
- [ ] Baseline tests pass.
- [ ] Generated artifacts are excluded from source control.
- [ ] `python -m compileall .` passes.
- [ ] `python cli.py --help` passes.
- [ ] A safe localhost scan passes.

## What Was Changed In This Step

Only this file, `development_notes.md`, was created. No source code, configuration, README, TODO, or generated files were modified.

## Next Phase

After Phase 0 is approved and applied, Phase 1 should address scanner correctness and safety: dual-stack IPv4/IPv6 handling, target and numeric-argument validation, structured stage errors, HTTPS verification policy, and NVD rate-limit/failure semantics.
