# CamAudit Lab — Codex Instructions

You are working on CamAudit Lab, a defensive, local-only IoT camera audit toolkit.

## Non-negotiable safety rules

- This is a defensive cybersecurity project.
- Do not add brute force, credential stuffing, password spraying, exploit execution, stealth, persistence, authentication bypass, or camera feed capture.
- Do not implement code that retrieves, stores, screenshots, or displays private camera video.
- Default scanning must only allow RFC1918 private ranges:
  - 10.0.0.0/8
  - 172.16.0.0/12
  - 192.168.0.0/16
- All scan/audit commands must require explicit authorization flags.
- Public IP exposure checking must be disabled by default and must require explicit ownership confirmation.
- Prefer safe fingerprinting: Nmap discovery, safe port checks, TLS certificate extraction, HTTP headers, RTSP OPTIONS only, UDP discovery checks.
- Do not mutate device state.

## Dependency discipline

- Do not add npm/Node dependencies unless explicitly asked.
- This is a Python-first project.
- Do not install new packages casually.
- Before adding any dependency, explain:
  1. why it is necessary,
  2. why the standard library is insufficient,
  3. package maturity,
  4. security risk,
  5. alternative options.
- Never add abandoned, obscure, typosquatted, or unmaintained packages.
- Prefer Typer, Rich, Pydantic, Jinja2, pytest, ruff, and mypy only if already in the project plan.

## Build discipline

- Make small, testable changes.
- After each meaningful change, run relevant tests.
- Keep parser logic unit-tested with sanitized fixtures.
- Keep redaction tests strict.
- Do not remove safety checks to make tests pass.
- Do not hide errors.
- Do not overclaim findings.

## Product goal

Build CamAudit Lab as a serious GitHub portfolio project:
- CLI
- safe authorization guardrails
- local network detection
- Nmap/curl/tshark wrappers where appropriate
- parsing
- camera candidate classification
- severity engine
- redaction
- report generation
- demo mode
- tests
- clear documentation