# TODO

## Priority 1 — Error Handling

- [ ] 1) Wrap `scanner.run()` and printing in `cli.py` with clean error handling (no tracebacks)
- [ ] 2) Add `KeyboardInterrupt` handling (Ctrl+C) in `cli.py`
- [ ] 3) Validate DNS resolution in `cli.py` using `core.utils.resolve_host`
- [ ] 4) Add defensive exception handling in `core/scanner.py`
- [ ] 5) Add port validation + defensive socket handling in `modules/ports.py`
- [ ] 6) Improve network error handling cleanliness in `modules/cve.py` (specific requests exceptions)
- [ ] 7) Re-run manual verification: `tusk scan invalidhost.com` and Ctrl+C

