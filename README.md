# Secure Code Lab

Small vulnerable-by-design examples, corrected implementations, and regression tests maintained by **Rohit Dixit — Cybersecurity Researcher**.

This repository is a local defensive teaching lab. Vulnerable functions are explicitly named and must never be copied into production. Tests use temporary directories, synthetic inputs, and reserved IP ranges; they do not attack or contact third-party systems.

## Covered controls

- path traversal containment
- ZIP Slip prevention
- subprocess argument separation
- SSRF-resistant URL validation
- constant-time token comparison
- file-upload size, name, and signature validation

Run: `python -m pytest -q`. See [AUTOMATION.md](AUTOMATION.md) for scheduled behavior.

## Author

Rohit Dixit — Cybersecurity Researcher · [rohitdixit.dev](https://rohitdixit.dev)

## License

MIT
