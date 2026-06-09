# CamAudit Lab Report

## 1. Scope and authorization

Scope: `192.168.1.0/24 authorized family-owned LAN`

Authorization confirmed: **yes**

## 2. Executive summary

CamAudit reviewed 2 discovered host(s), 1 camera candidate(s), and 5 finding(s) within the authorized scope. No unauthenticated camera feed access was confirmed.

## 3. Network context

| Field | Value |
|---|---|
| subnet_cidr | 192.168.1.0/24 |
| default_gateway | 192.168.1.1 |
| note | Sanitized demo context; no live network commands are run in demo mode. |

## 4. Device inventory

| IP | Hostname | Vendor | MAC OUI | Notes |
|---|---|---|---|---|
| 192.168.1.38 |  | TP-Link Systems | 5C:E9:31 | Local HTTPS JSON API observed; TPRI-DEVICE self-signed TLS certificate observed; 1024-bit RSA certificate parameter observed; RTSP standard ports closed |
| 192.168.1.87 |  | Sony Interactive Entertainment | 70:66:2A | Not a camera candidate |

## 5. Camera candidates

| IP | Type | Score | Reasons |
|---|---:|---:|---|
| 192.168.1.38 | camera_candidate | 88 | TP-Link/Tapo-like vendor hint; Open TCP/443 and TCP/8443 local HTTPS services; Open TCP/8800 CSeq/RTSP-like service |

## 6. Open services

| IP | Port | Protocol | Service |
|---|---:|---|---|
| 192.168.1.38 | 443 | tcp | https-json-api |
| 192.168.1.38 | 8443 | tcp | https-alt-json-api |
| 192.168.1.38 | 8800 | tcp | rtsp-like-cseq |

## 7. Fingerprinting results

| IP | Type | Port | Evidence |
|---|---|---:|---|
| 192.168.1.38 | http | 443 | HTTPS JSON API returned 404/405-style behavior to safe header/root checks; no response body or feed was stored. |
| 192.168.1.38 | tls | 443 | TPRI-DEVICE self-signed TLS certificate observed with RSA 1024-bit public key. |
| 192.168.1.38 | rtsp_options | 8800 | Port 8800 returned a CSeq header / RTSP-like response to a safe OPTIONS-style probe. |

## 8. RTSP/ONVIF/UPnP findings

| Title | Severity | Evidence |
|---|---|---|
| RTSP standard ports closed | Positive | TCP/554 and TCP/8554 were not reported open. |
| UPnP/ONVIF/mDNS not observed | Info | UDP/1900, UDP/3702, and UDP/5353 were closed or not observed in sanitized evidence. |
| Port 8800 CSeq / RTSP-like response | Info | TCP/8800 returned a CSeq header in sanitized lab evidence. |

## 9. TLS findings

| Title | Severity | Evidence |
|---|---|---|
| Weak self-signed local TLS certificate | Low | TPRI-DEVICE self-signed certificate with RSA 1024-bit public key. |

## 10. CVE mapping

| Component | CVE | Status | Notes |
|---|---|---|---|
| TP-Link/Tapo-like camera firmware |  | not matched | No CVE claim is made from sanitized demo evidence. |

## 11. Severity table

| Finding | Severity | Evidence |
|---|---|---|
| Local HTTPS JSON API reachable | Info | TCP/443 and TCP/8443 returned HTTPS JSON API 404/405-style behavior. |
| Weak self-signed local TLS certificate | Low | TPRI-DEVICE self-signed certificate with RSA 1024-bit public key. |
| Port 8800 CSeq / RTSP-like response | Info | TCP/8800 returned a CSeq header in sanitized lab evidence. |
| RTSP standard ports closed | Positive | TCP/554 and TCP/8554 were not reported open. |
| UPnP/ONVIF/mDNS not observed | Info | UDP/1900, UDP/3702, and UDP/5353 were closed or not observed in sanitized evidence. |

## 12. Remediation checklist

- Keep camera firmware updated.
- Keep camera services restricted to trusted LAN or IoT VLAN segments.
- Disable RTSP unless needed.
- Disable UPnP on the router where possible.
- Do not expose camera services to the internet.

## 13. Evidence appendix

| Item | Source | Notes |
|---|---|---|
| Nmap discovery | results/raw/nmap_discovery.txt | Sanitized demo output only. |
| Safe port scan | results/raw/nmap_port_scan.txt | Sanitized demo output only. |
| TLS and header fingerprinting | results/raw/ | Headers and certificate metadata only; no feed data. |

## 14. Redaction log

- Full MAC addresses are reduced to OUI prefixes.
- Public IPs, emails, serials, UIDs, tokens, and media filenames are redacted.
- No camera feed images or video are stored in this demo.
