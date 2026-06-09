# CamAudit Lab Report

## 1. Scope and authorization

Scope: `192.168.1.0/24 authorized family-owned LAN`

Authorization confirmed: **yes**

## 2. Executive summary

Camera candidates were discoverable on the LAN. Local proprietary services were reachable, but no unauthenticated feed access was confirmed. Standard RTSP ports were closed.

## 3. Network context

| Field | Value |
|---|---|
| subnet_cidr | 192.168.1.0/24 |
| note | Sanitized sample context |

## 4. Device inventory

| IP | Hostname | Vendor | MAC OUI | Notes |
|---|---|---|---|---|
| 192.168.1.38 |  | TP-Link Systems | 5C:E9:31 | Local HTTPS JSON API observed; RTSP standard ports closed |
| 192.168.1.87 |  | Sony Interactive Entertainment | 70:66:2A | Not a camera candidate |

## 5. Camera candidates

| IP | Type | Score | Reasons |
|---|---:|---:|---|
| 192.168.1.38 | camera_candidate | 85 | TP-Link/Tapo-like device; local camera service ports |

## 6. Open services

| IP | Port | Protocol | Service |
|---|---:|---|---|
| 192.168.1.38 | 443 | tcp | https |
| 192.168.1.38 | 8443 | tcp | https-alt |
| 192.168.1.38 | 8800 | tcp | rtsp-like proprietary service |

## 7. Fingerprinting results

| IP | Type | Port | Evidence |
|---|---|---:|---|
| 192.168.1.38 | http | 443 | HTTP service required authentication; headers only recorded. |
| 192.168.1.38 | rtsp_options | 8800 | CSeq-like header observed in sanitized lab output. |

## 8. RTSP/ONVIF/UPnP findings

| Title | Severity | Evidence |
|---|---|---|
| RTSP standard ports closed | Positive | TCP/554 and TCP/8554 closed |

## 9. TLS findings

| Title | Severity | Evidence |
|---|---|---|
| TLS certificate reviewed | Info | Sanitized certificate metadata only |

## 10. CVE mapping

| Component | CVE | Status | Notes |
|---|---|---|---|
| Camera firmware |  | Not matched | No CVE claim made from sanitized sample data. |

## 11. Severity table

| Finding | Severity | Evidence |
|---|---|---|
| Local camera service exposure | Info | TCP/443 and TCP/8800 reachable from LAN |
| RTSP standard ports closed | Positive | TCP/554 and TCP/8554 closed |

## 12. Remediation checklist

- Keep camera firmware updated.
- Disable RTSP unless needed.
- Disable UPnP on router where possible.
- Use a guest/IoT network for cameras.
- Do not expose camera services to the internet.

## 13. Evidence appendix

| Item | Source | Notes |
|---|---|---|
| Nmap discovery | results/raw/nmap_discovery.txt | Sanitized sample output only. |
| Port scan | results/raw/nmap_port_scan.txt | Sanitized sample output only. |

## 14. Redaction log

- Full MAC addresses are reduced to OUI prefixes.
- Public IPs, emails, serials, UIDs, tokens, and media filenames are redacted.
- No camera feed images or video are stored in this sample.
