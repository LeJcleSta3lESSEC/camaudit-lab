# Lesson 03 — Nmap for IoT

IoT devices often hang on aggressive scans.

Prefer:

```bash
nmap -Pn -n -T3 --max-retries 2 --host-timeout 45s --open -p 80,443,554,8554,8443,8800 TARGET
```

Avoid by default:

```bash
--version-all
-O
-A
```

Use timeouts. Save raw output. Redact before sharing.
