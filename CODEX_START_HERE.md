# Codex Start Here

You are building **CamAudit Lab**, a defensive, local-only IoT camera audit toolkit and teaching lab.

## Non-negotiable security rules

1. Do not add offensive functionality.
2. Do not implement brute force, credential stuffing, default-password attempts, exploit execution, stealth, persistence, camera feed capture, PTZ control, or settings modification.
3. Do not scan public IPs by default.
4. All scan commands must require `--i-am-authorized`.
5. Default targets must be limited to RFC1918 private networks.
6. Redact full MAC addresses, public IPs, emails, serials, UIDs, tokens, and feed images from reports.
7. Keep everything reproducible, testable, and boringly safe.

## Package discipline

This is a Python project. Do not introduce Node/npm unless explicitly asked.

If a frontend is later added:

- Do not run `npm install <package>` casually.
- Prefer zero/low-dependency vanilla UI first.
- Explain why each package is needed.
- Check package age, maintainer, downloads, repository, install scripts, and transitive dependencies.
- Prefer `npm ci --ignore-scripts` for reproducible installs.
- Never install packages with suspicious typosquatting names.

## First Codex task

Start with Prompt 1 in `docs/codex_prompts.md`.

Implement only the minimal safe skeleton and tests first. Do not build scanning features until authorization guards and redaction tests pass.