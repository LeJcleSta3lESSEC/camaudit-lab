# Pre-Coding Security Discipline

This project is security tooling, so the engineering process must be more disciplined than a normal hobby repo.

## 1. Threat model the tool itself

CamAudit will eventually execute local commands like `nmap`, `curl`, and possibly `tshark`. That creates risks:

- command injection if target strings are not validated
- accidental public-IP scanning
- storing sensitive evidence
- leaking MAC addresses, public IPs, serials, UIDs, emails, or camera images
- overclaiming findings
- Codex adding unsafe functionality because the task wording is vague

Rule: every external command must use list-style subprocess arguments, never shell string concatenation.

Good:

```python
subprocess.run(["nmap", "-sn", target], ...)
```

Bad:

```python
subprocess.run(f"nmap -sn {target}", shell=True)
```

## 2. Authorization gate before scanner code

Before implementing discovery or scanning, implement:

- target validation
- private-range enforcement
- `--i-am-authorized` requirement
- public-IP refusal by default
- tests for all of the above

No scanning module should run without passing the guard.

## 3. Dependency discipline

### Python

Use a small dependency set:

- Typer
- Rich
- Pydantic
- Jinja2
- pytest / ruff / mypy for development

Before adding any new package, answer:

1. Can the standard library do it?
2. Is the package actively maintained?
3. Is the package widely used?
4. Does it execute code during install?
5. Is the name at risk of typosquatting?
6. Is the license compatible?
7. Is the dependency worth its transitive dependency tree?

### Node/npm

Do not add npm unless explicitly needed.

If a frontend is eventually created:

- prefer no framework at first
- avoid random UI libraries
- avoid packages with install scripts unless absolutely necessary
- use lockfiles
- use `npm ci` instead of casual `npm install`
- inspect scripts before installing
- run vulnerability and provenance checks where available

Useful commands:

```bash
npm config get ignore-scripts
npm audit
npm audit signatures
npm ls -g --depth=0
```

Do not assume `npm audit` proves safety. It checks known vulnerabilities, not unknown malware.

## 4. Evidence handling

Never store:

- camera feeds
- camera screenshots
- account emails
- public IPs in cleartext
- full MAC addresses
- serial numbers
- QR codes
- authentication tokens

Reports should default to safe redaction.

## 5. Findings discipline

Use conservative language.

Good:

> TCP/8800 is open and returned a `CSeq` header to an HTTP probe, suggesting an RTSP-like or proprietary camera protocol. No unauthenticated feed access was confirmed.

Bad:

> Port 8800 is vulnerable.

## 6. Git hygiene

Before every commit:

```bash
pytest
ruff check .
mypy src
```

Before pushing:

```bash
git status
git diff --cached
```

Never commit `.env`, raw scans with sensitive data, screenshots, packet captures, public IPs, secrets, tokens, or camera images.
