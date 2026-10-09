# TODO

## Phase 0 — Stabilize the Core

- [x] Replace IPv4-only socket implementation (discovery/ports.py, discovery/banners.py)
- [x] Add IPv6 and dual-stack support with getaddrinfo()
- [x] Fix HTTPS certificate verification (discovery/analyzers/http_analyzer.py)
- [x] Add --insecure and --verbose CLI options
- [x] Reject unknown product/version in CPE generation
- [x] Add stage-aware structured scanner errors
- [x] Implement partial result preservation
- [x] Add test coverage for Phase 0 changes

## Priority 2 — Performance

- [X]  Improve thread management.
- [X]  Reduce socket timeout.
- [X]  Optimize port scanning.

## Priority 3 — Parallelization

- [ ]  Parallel banner grabbing.
- [ ]  Parallel version detection.
