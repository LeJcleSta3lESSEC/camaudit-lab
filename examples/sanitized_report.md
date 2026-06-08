# CamAudit Lab — Sanitized Sample Report

## Scope

Authorized local audit of `192.168.1.0/24`.

## Executive summary

Camera candidates were discoverable on the LAN. Local proprietary services were reachable, but no unauthenticated feed access was confirmed. Standard RTSP ports were closed.

## Findings

| Finding | Severity | Evidence |
|---|---:|---|
| Local camera service exposure | Info/Low | TCP/443 and TCP/8800 reachable from LAN |
| RTSP standard ports closed | Positive | TCP/554 and TCP/8554 closed |

## Remediation checklist

- Keep camera firmware updated.
- Disable RTSP unless needed.
- Disable UPnP on router where possible.
- Use a guest/IoT network for cameras.
- Do not expose camera services to the internet.
