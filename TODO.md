# TODO

## Phase 0 — Stabilize the Core

- [ ] Replace IPv4-only socket implementation (discovery/ports.py, discovery/banners.py)
- [ ] Add IPv6 and dual-stack support with getaddrinfo()
- [ ] Fix HTTPS certificate verification (discovery/analyzers/http_analyzer.py)
- [ ] Add --insecure and --verbose CLI options
- [ ] Reject unknown product/version in CPE generation
- [ ] Add stage-aware structured scanner errors
- [ ] Implement partial result preservation
- [ ] Add test coverage for Phase 0 changes

## Priority 2 — Performance

- [X]  Improve thread management.
- [X]  Reduce socket timeout.
- [X]  Optimize port scanning.

## Priority 3 — Parallelization

- [ ]  Parallel banner grabbing.
- [ ]  Parallel version detection.
