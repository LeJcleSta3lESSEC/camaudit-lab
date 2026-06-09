# CamAudit OPSEC Notes

CamAudit is intended for authorized local audits. Treat generated artifacts as sensitive by default.

## Do not commit

- Public IP addresses in cleartext
- Full MAC addresses
- Serial numbers
- UIDs
- Email addresses
- Screenshots
- Packet capture files: `.pcap`, `.pcapng`, `.cap`
- Raw scan outputs under `results/raw/`
- Generated reports under `results/reports/`
- Camera feed data, still images, or video
- Secrets, tokens, credentials, `.env` files, and private key material

## Commit-safe material

- Sanitized examples under `examples/`
- Unit tests and sanitized fixtures under `tests/fixtures/`
- Templates, source code, and documentation that do not contain live audit data

## Storage pattern

Real discovery, scan, and fingerprint artifacts are written under a run-specific directory:

```text
results/raw/<run_id>/...
```

This avoids overwriting prior audit data and helps keep live outputs separate from sanitized examples.
