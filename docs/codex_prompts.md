# Codex Prompts

Use these prompts sequentially. Do not skip the security foundation.

## Prompt 1 — Verify and complete safe project skeleton

You are building CamAudit Lab, a defensive local-only IoT camera audit toolkit in Python.

Complete the existing scaffold using Python 3.12, Typer, Rich, Pydantic, Jinja2, pytest, ruff, and mypy.

Requirements:
- CLI command group: `camaudit`
- Commands: `init`, `check-env`, `discover`, `scan-host`, `audit`, `report`, `redact`, `demo`
- Keep `src/` layout
- Keep tests passing
- Do not add offensive functionality
- Do not implement brute force, credential stuffing, exploit execution, stealth, persistence, camera feed capture, or settings modification
- Default scans must only allow RFC1918 private IP ranges
- Any scan command must require `--i-am-authorized`

Return changed files only.

## Prompt 2 — Authorization and private target guard

Implement `src/camaudit/auth_guard.py` fully.

Requirements:
- `is_private_target(target: str) -> bool`
- Accept CIDR ranges and single IPs
- Allow only:
  - `10.0.0.0/8`
  - `172.16.0.0/12`
  - `192.168.0.0/16`
  - localhost only for tests/demo
- Reject public IPs unless a future exposure mode explicitly passes `--i-own-this-ip`
- All scan commands must refuse to run unless `--i-am-authorized` is passed
- Add helpful error messages
- Add pytest tests for private IPs, public IPs, invalid IPs, CIDR ranges, and missing authorization
- Do not add any offensive functionality

## Prompt 3 — Redaction engine

Implement `src/camaudit/redact.py`.

Requirements:
- Redact public IPs
- Redact full MAC addresses to OUI prefix only
- Redact emails
- Redact serial-like strings and UID-like tokens
- Redact camera feed filenames if any appear
- Preserve private LAN IPs by default
- Provide strict mode that also redacts private IPs
- Add tests

## Prompt 4 — Environment checker

Implement `src/camaudit/envcheck.py` and wire it to `camaudit check-env`.

Detect:
- OS
- Python version
- nmap availability and version
- curl availability
- tshark availability
- wireshark availability if detectable
- VLC availability if detectable

Use subprocess safely with timeouts. Mock subprocess in tests.

## Prompt 5 — Network detection

Implement `src/camaudit/network.py`.

Requirements:
- Detect local IPv4 address
- Detect default gateway where possible
- Detect subnet/CIDR where possible
- Support Windows, Linux, macOS best-effort
- Warn when target network does not match active network
- Warn for likely phone hotspot drift: active IP in `172.20.10.0/28` while target is `192.168.x.x`
- Return structured Pydantic model
- Add parsing tests with fixtures

## Prompt 6 — Nmap discovery parser

Implement `src/camaudit/discovery.py`.

Command:
`nmap -sn TARGET`

Requirements:
- Run only after auth guard approval
- Use subprocess with timeout
- Save raw output to `results/raw/nmap_discovery.txt`
- Parse IP, hostname, MAC, vendor, latency if available
- Redact full MAC by default into OUI prefix
- Return `list[DiscoveredHost]`
- Add tests using sanitized fixtures

## Prompt 7 — Camera candidate classifier

Implement `src/camaudit/classifier.py`.

Input:
- DiscoveredHost
- optional open ports
- optional TLS certificate metadata
- optional hostname

Output:
- candidate_score 0-100
- candidate_type: `camera_candidate`, `router`, `console`, `phone_or_randomized`, `unknown`
- reasons list

Rules:
- TP-Link, Hikvision, Dahua, Axis, Reolink, Uniview, Amcrest, EZVIZ, Tapo-like vendors increase score
- Open RTSP/ONVIF/web camera ports increase score
- Known console/router/laptop vendors reduce score
- Randomized MAC should be labeled uncertain, not camera by default
- Do not overclaim
- Add tests

## Prompt 8 — Safe port scanner

Implement `src/camaudit/scanner.py`.

Command template:
`nmap -Pn -n -T3 --max-retries 2 --host-timeout 45s --open -p PORTS TARGET`

Requirements:
- Default camera/IoT port list:
  `80,81,443,554,8000,8080,8081,8554,8899,5000,37777,34567,8443,8800,2020,10443,50443`
- Safe timeouts
- Parse open ports
- Save raw output
- Return PortScanResult
- No aggressive OS detection by default
- No `--version-all` by default
- Add optional `--version-light` mode only
- Add parser tests

## Prompt 9 — Safe fingerprinting

Implement `src/camaudit/fingerprint.py`.

Allowed probes:
- TLS certificate extraction through Nmap `ssl-cert` for TLS ports
- HTTP HEAD and GET `/` using curl with timeout
- HTTP headers only
- RTSP OPTIONS only for RTSP ports, no DESCRIBE/SETUP/PLAY
- UDP discovery checks for 1900, 3702, 5353 using `nmap -sU`

Requirements:
- Never send credentials
- Never attempt default passwords
- Never retrieve or store camera feeds
- Never change settings
- Store raw outputs
- Parse status code, content type, header hints, TLS CN/org/key bits/validity, CSeq presence, ONVIF/UPnP/mDNS status
- Add tests for sample outputs from the lab

## Prompt 10 — Severity engine

Implement `src/camaudit/severity.py`.

Input:
- host classification
- open ports
- fingerprint results
- exposure mode results
- CVE mapping results

Output:
- findings list with title, severity, evidence, explanation, remediation

Rules:
- Unauthenticated feed confirmed: Critical
- Camera port exposed on public IP: High
- Port forwarding to camera: High
- DMZ to camera: Critical
- UPnP enabled on router: Medium
- Local API open but auth-gated: Info/Low
- 1024-bit self-signed TLS cert: Low
- RTSP 554/8554 closed: Positive
- ONVIF/UPnP/mDNS closed: Positive
- Unknown custom service with no data leakage: Info

Add tests for each rule.

## Prompt 11 — Report generator

Implement `src/camaudit/report.py` using Jinja2.

Generate Markdown report with:
1. Scope and authorization
2. Executive summary
3. Network context
4. Device inventory
5. Camera candidates
6. Open services
7. Fingerprinting results
8. RTSP/ONVIF/UPnP findings
9. TLS findings
10. CVE mapping
11. Severity table
12. Remediation checklist
13. Evidence appendix
14. Redaction log

Include sanitized sample output in `examples/sanitized_report.md`.

## Prompt 12 — Demo mode

Implement `camaudit demo`.

Requirements:
- Load `examples/sanitized_session.json`
- Display what a scan would look like without running Nmap/curl
- Generate a demo report
- Useful for GitHub reviewers who cannot scan a real network
- Add README section: Try demo mode first
