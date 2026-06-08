# CamAudit Lab

**Defensive, local-only IoT camera audit toolkit and teaching lab.**

CamAudit Lab helps authorized users assess whether IP cameras on their own LAN expose unsafe services such as unauthenticated RTSP, ONVIF, UPnP, local web/API panels, weak TLS configurations, or accidental public exposure.

This repository starts from a real authorized home-lab camera audit and turns it into a reproducible, safe, report-generating portfolio project.

## Safety boundaries

CamAudit Lab is **not** a camera hacking tool.

It must never implement or encourage:

- brute force
- credential stuffing
- default-password spraying
- exploit execution
- persistence
- stealth
- settings modification
- camera feed capture
- PTZ movement
- unauthorised public-IP scanning

Default scan targets must be limited to RFC1918 private networks:

- `10.0.0.0/8`
- `172.16.0.0/12`
- `192.168.0.0/16`

All scan commands must require an explicit authorization flag.

## Current status

This is a **starter scaffold** for Codex-driven development.

Included:

- Python package skeleton
- CLI placeholders
- authorization guard
- redaction utilities
- report templates
- tests
- GitHub Actions CI
- Dependabot config
- pre-coding security discipline
- Codex prompts
- sanitized report placeholders
- original case-study document placeholder/copy

## Quickstart

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
pytest
camaudit --help
```

## Demo mode goal

The first usable public feature should be:

```bash
camaudit demo
```

It should load `examples/sanitized_session.json` and generate a safe sample report without scanning any network.

## Development principles

Read these before coding:

- [`docs/pre_coding_security.md`](docs/pre_coding_security.md)
- [`CODEX_START_HERE.md`](CODEX_START_HERE.md)
- [`docs/codex_prompts.md`](docs/codex_prompts.md)
- [`SECURITY.md`](SECURITY.md)

## Portfolio positioning

> Built CamAudit Lab, a Python-based defensive IoT security audit toolkit that automates local network discovery, camera service fingerprinting, RTSP/ONVIF/UPnP checks, TLS analysis, evidence redaction, and professional report generation under strict authorization guardrails.
