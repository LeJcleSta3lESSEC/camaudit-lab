# Camera Security Audit Lab — Complete Record & Teaching Document

> **Scope**: Authorized security research on a family-owned residential network.  
> **Target**: TP-Link cameras on `192.168.1.0/24`, Marrakech house.  
> **Attacker model**: Local Wi-Fi attacker with no camera credentials.  
> **Authorized actions**: Discovery, enumeration, unauthenticated access checks, CVE mapping.  
> **Prohibited**: Brute force, credential stuffing, exploit execution, persistence, stealth, settings modification.  
> **Date**: 2026-06-02

---

## Table of Contents

1. [What This Lab Is And Why It Exists](#1-what-this-lab-is-and-why-it-exists)
2. [Core Concepts You Need First](#2-core-concepts-you-need-first)
3. [Lab Environment & Tooling](#3-lab-environment--tooling)
4. [Phase 0 — Preparation & Rules of Engagement](#4-phase-0--preparation--rules-of-engagement)
5. [Phase 1 — Identify Your Network Range](#5-phase-1--identify-your-network-range)
6. [Phase 2 — Passive Discovery with Wireshark](#6-phase-2--passive-discovery-with-wireshark)
7. [Phase 3 — Active LAN Discovery with Nmap](#7-phase-3--active-lan-discovery-with-nmap)
8. [Phase 4 — Port Scanning Camera Candidates](#8-phase-4--port-scanning-camera-candidates)
9. [Phase 5 — Service Fingerprinting](#9-phase-5--service-fingerprinting)
10. [Phase 6 — Testing Unauthenticated Access with curl](#10-phase-6--testing-unauthenticated-access-with-curl)
11. [Phase 7 — Web Browser Check](#11-phase-7--web-browser-check)
12. [Phase 8 — RTSP Feed Check with VLC](#12-phase-8--rtsp-feed-check-with-vlc)
13. [Phase 9 — ONVIF & UDP Discovery](#13-phase-9--onvif--udp-discovery)
14. [Phase 10 — Wireshark During Active App Use](#14-phase-10--wireshark-during-active-app-use)
15. [Phase 11 — Router-Side Audit](#15-phase-11--router-side-audit)
16. [Phase 12 — Internet Exposure Check](#16-phase-12--internet-exposure-check)
17. [Phase 13 — CVE Research Workflow](#17-phase-13--cve-research-workflow)
18. [Errors Made & What They Teach](#18-errors-made--what-they-teach)
19. [Final Findings & Severity Classification](#19-final-findings--severity-classification)
20. [What Comes Next](#20-what-comes-next)
21. [Full Command Reference](#21-full-command-reference)

---

## 1. What This Lab Is And Why It Exists

### The research question

> **Can someone connected to the house Wi-Fi discover, identify, and access the camera feeds without having camera credentials?**

This is not "can I guess passwords" and not "can I root the camera." The first valid artifact is **unauthenticated exposure mapping** — what can a stranger who joined your Wi-Fi actually see or touch?

### Why this matters

Most people assume home cameras are safe because they're "inside the house." That assumption is wrong for at least three reasons:

- Any guest, neighbor, or person who knows your Wi-Fi password is on your LAN.
- Many cameras expose local services that predate proper auth implementation.
- IoT devices are systematically under-patched and poorly audited.

The specific risk model: a person connected to the same Wi-Fi, with zero camera credentials, who knows basic network tools. Can they see your feeds?

### Why do this on your own network

Testing on your own authorized devices is how you learn real skills without legal exposure. The techniques here are identical to what a professional penetration tester does in a commissioned engagement. The only difference is authorization.

---

## 2. Core Concepts You Need First

### 2.1 How home Wi-Fi cameras actually work

Most cameras use one or both of two architectures:

```
Architecture A — Cloud-mediated (most modern cameras)

Phone App → TP-Link/Tapo Cloud → Camera
Camera → TP-Link/Tapo Cloud → Phone App
```

The camera and the phone never talk directly. Everything routes through the vendor's cloud servers. The feed leaves your house, goes to a data center, and comes back. Implication: from the LAN side, you may see almost nothing because the feed isn't on your local network at all.

```
Architecture B — Local LAN path (common in enterprise cameras, some consumer)

Phone App → Camera IP directly (local)
Camera → Phone App directly (local)
```

The phone and camera talk directly over Wi-Fi. This is faster (lower latency), uses less bandwidth, and doesn't depend on cloud availability. But it means the camera is actively running local services that can be scanned and probed.

Many modern Tapo/TP-Link cameras use **Architecture A** by default but also maintain **local API services** on the LAN for initial setup, local control, and (optionally) direct RTSP access if a camera account is created.

### 2.2 What protocols cameras expose

| Protocol | Port(s) | What it does |
|---|---|---|
| HTTP/HTTPS | 80, 443, 8080, 8443 | Web admin panel or local API |
| RTSP | 554, 8554 | Real-Time Streaming Protocol — raw video stream |
| ONVIF | 3702 (UDP), sometimes 2020 (TCP) | Standard camera control/discovery protocol |
| UPnP/SSDP | 1900 (UDP) | Device auto-discovery; "I exist on this network" |
| mDNS | 5353 (UDP) | Local name resolution; advertises device names |
| Dahua proprietary | 37777, 34567 | Dahua/Imou-specific services |
| Hikvision proprietary | 8000 | Hikvision/EZVIZ-specific services |

### 2.3 What ports mean

A port is a numbered door on a device. Each door corresponds to a service. Scanning ports tells you which doors exist and what's behind them.

- **Open**: Something is listening; it will respond to connections.
- **Closed**: No service on that port; the device is reachable but actively refuses.
- **Filtered**: The device doesn't respond at all — firewall dropping packets, or device unreachable.

### 2.4 What IP addresses mean

Your home network is a private LAN. Devices on it get private IPs, typically in one of these ranges:

```
192.168.0.0/16
10.0.0.0/8
172.16.0.0/12
```

The `/24` notation (CIDR) means the network covers 256 addresses. `192.168.1.0/24` means `192.168.1.0` through `192.168.1.255`. Usable device IPs are `.1` through `.254`. Your router usually sits at `.1` or `.254`.

The `/28` notation means only 16 addresses (`172.20.10.0` through `172.20.10.15`). This appeared during the lab when the machine accidentally switched to a phone hotspot — a much smaller subnet with no cameras on it.

### 2.5 What MAC addresses mean

A MAC address is a hardware identifier burned into a network adapter. The first 3 bytes (the OUI — Organizationally Unique Identifier) identify the manufacturer. This is how Nmap tells you "this device is TP-Link" or "this device is Sony" without even scanning its ports. Tools like Wireshark have vendor databases built in.

```
5C:E9:31:xx:xx:xx → TP-Link Systems
40:33:06:xx:xx:xx → Taicang T&W Electronics (router hardware)
70:66:2A:xx:xx:xx → Sony Interactive Entertainment
70:54:B4:xx:xx:xx → Vestel Elektronik (TV/appliance)
```

### 2.6 What TLS/HTTPS means on a local device

When a device runs HTTPS locally, it needs a certificate to encrypt the connection. Real certificates are issued by trusted Certificate Authorities and are browser-trusted. IoT devices typically use **self-signed certificates** — they generate their own, trust it themselves, but no browser recognizes it.

When Chrome says "Vous n'êtes pas en lieu sûr" or "Your connection is not private," it is telling you the certificate isn't from a trusted CA. On a local IoT device, this is **expected and normal**. It does not mean the device is hacked. It means the device has a local TLS service that browsers don't trust by default.

The `TPRI-DEVICE` certificate found on the cameras has:
- **Self-signed** (issuer = subject = TPRI-DEVICE)
- **RSA 1024-bit key**: weak by modern standards (2048 is minimum recommended, 4096 is common now)
- **Validity: 2001-01-01 to 2070-12-31**: intentionally long "forever" window, typical of embedded devices that don't have reliable clocks during provisioning and don't want expiry to break the device

### 2.7 What RTSP is

RTSP (Real-Time Streaming Protocol) is a protocol for delivering live video. Think of it as HTTP but for video streams. A camera running RTSP exposes a URL like:

```
rtsp://192.168.1.X:554/stream1
```

A client like VLC connects, negotiates (OPTIONS → DESCRIBE → SETUP → PLAY), and receives the video. If the camera requires authentication, it returns a 401 Unauthorized before providing anything. If it doesn't, the feed plays immediately — that's a critical vulnerability.

### 2.8 What ONVIF is

ONVIF is an industry standard for IP cameras that lets different clients (NVRs, VMS software, ONVIF Device Manager) discover and control cameras from any vendor. If a camera supports ONVIF, a generic ONVIF client can find it, get its stream URI, and potentially view the feed. This is intentional for interoperability, but misconfigured ONVIF can expose feeds without login.

### 2.9 What UPnP/SSDP is and why it's dangerous

Universal Plug and Play (UPnP) lets devices on a network announce themselves and request services from routers automatically. A camera might say to the router: "Please open port 8080 on your public internet interface and forward it to me." If the router complies, your camera is now reachable from the entire internet — without you doing anything.

UPnP is designed for convenience but is systematically abused. A camera opening its own port forwarding via UPnP is a common path to internet exposure.

---

## 3. Lab Environment & Tooling

### System

- **OS**: Windows (CMD used throughout)
- **Machine IP**: `192.168.1.140`
- **Network**: `192.168.1.0/24`
- **Gateway/router**: `192.168.1.254` (Taicang T&W Electronics DSL device)

### Tools used

| Tool | Purpose | Install |
|---|---|---|
| **Nmap** | Network scanner, port scanner, script engine | [nmap.org](https://nmap.org) — Windows installer adds to PATH |
| **Wireshark** | Packet capture and protocol analysis | [wireshark.org](https://wireshark.org) |
| **curl** | Command-line HTTP client for probing services | Ships with Windows 10+ |
| **VLC** | Media player that can open RTSP streams | [videolan.org](https://videolan.org) |
| **ONVIF Device Manager** | GUI tool for ONVIF camera discovery | Windows freeware |
| **Browser (Chrome)** | Manual HTTPS endpoint check | — |

### Verifying Nmap is installed and in PATH

```cmd
nmap --version
```

If you get `'nmap' is not recognized`, either:
1. Nmap isn't installed — download and run the Windows installer from nmap.org.
2. Nmap is installed but not in PATH — either reinstall with "add to PATH" checked, or navigate to `C:\Program Files (x86)\Nmap\` and run it from there.

---

## 4. Phase 0 — Preparation & Rules of Engagement

Before running any tools, establish the audit's scope and create a documentation structure.

### Folder structure

```
camera_audit_marrakech/
├── notes.md
├── nmap/
├── wireshark/
├── screenshots_redacted/
├── cve_research/
└── final_report.md
```

Create it in CMD:

```cmd
mkdir camera_audit_marrakech
mkdir camera_audit_marrakech\nmap
mkdir camera_audit_marrakech\wireshark
mkdir camera_audit_marrakech\cve_research
```

### notes.md header

```
Date: 2026-06-02
Network name: [house Wi-Fi SSID]
Your device: 192.168.1.140
Tools used: Nmap 7.99, Wireshark, curl, browser
Authorization: authorized testing on family-owned devices
Goal: Determine whether cameras are accessible without credentials from LAN
Scope: 192.168.1.0/24, family cameras only
Out-of-scope: brute force, credential stuffing, exploit execution, persistent access, external targets
```

This establishes researcher-grade documentation from the start.

### What to always redact before sharing

```
Public IP address
Full MAC addresses (keep first 3 bytes / vendor prefix only)
Serial numbers and UIDs
QR codes
Account emails
Any camera feed images or video
```

### What is always fine to keep

```
Private LAN IPs (192.168.x.x, 172.16.x.x, 10.x.x.x)
Open port numbers
Service names and banners
Vendor names
Firmware version strings
```

---

## 5. Phase 1 — Identify Your Network Range

Before scanning anything, you need to know what network you're on and what its range is.

### Windows

```cmd
ipconfig
```

**What was actually seen:**

```
Carte réseau sans fil Wi-Fi :
   Adresse IPv4 . . . . . . . . . . . : 192.168.1.140
   Masque de sous-réseau . . . . . . : 255.255.255.0
   Passerelle par défaut . . . . . . : 192.168.1.254

Carte réseau sans fil Connexion au réseau local* 1 :
   Statut du média : Média déconnecté

Carte réseau sans fil Connexion au réseau local* 10 :
   Statut du média : Média déconnecté
```

**How to read this:**

| Field | Value | Meaning |
|---|---|---|
| Adresse IPv4 | 192.168.1.140 | Your machine's IP on this network |
| Masque de sous-réseau | 255.255.255.0 | Defines network size = /24 = 256 addresses |
| Passerelle par défaut | 192.168.1.254 | Your router — traffic to the internet goes here |
| Connexion au réseau local* N | Disconnected | Virtual Wi-Fi Direct / hotspot adapters — ignore |

Your scan target is therefore `192.168.1.0/24`.

### Linux equivalent

```bash
ip route
```

```
default via 192.168.1.254 dev wlan0
192.168.1.0/24 dev wlan0
```

### Why the subnet mask matters

`255.255.255.0` in binary means the first 24 bits are the network, the last 8 bits are hosts. That gives `2^8 = 256` addresses. In CIDR notation: `/24`. Your device range is `192.168.1.1` to `192.168.1.254`.

A `/28` mask (`255.255.255.240`) gives only 16 addresses. This is what appeared mid-lab when the machine accidentally joined a phone hotspot (`172.20.10.0/28`). Important to catch this — see [Section 18](#18-errors-made--what-they-teach).

---

## 6. Phase 2 — Passive Discovery with Wireshark

Before active scanning (which generates traffic), listen to what the network says on its own. Devices constantly broadcast and multicast to announce themselves.

### Open Wireshark

1. Launch Wireshark.
2. Select the active Wi-Fi interface (the one with traffic).
3. Start capture.

### Key display filters and what they show

```
arp
```
ARP (Address Resolution Protocol) traffic. Devices ask "Who has 192.168.1.X?" to translate IPs to MAC addresses. Watch this to see which devices are communicating.

```
bootp
```
DHCP traffic (the protocol that assigns IPs). When a device joins the network, it broadcasts a DHCP request. You may see device hostnames in these packets.

```
mdns
```
Multicast DNS — devices advertise their local name. Cameras often advertise names like `Tapo_C200.local`, `IPC_xxxx.local`.

```
udp.port == 1900
```
SSDP/UPnP traffic. Many IoT devices announce: "I'm a [device type] at [IP]." You may see full device descriptions in these packets.

```
udp.port == 3702
```
WS-Discovery, the ONVIF discovery mechanism. If cameras use ONVIF, they'll announce on this port.

```
rtsp
```
RTSP traffic. If any feed is being actively streamed (by an app or client), you'll see RTSP protocol packets here.

```
http
```
Unencrypted HTTP traffic. Most IoT web admin panels historically ran on plain HTTP.

### What was actually seen in Wireshark

```
Destination: TaicangT&WEl_2f:98:f6 (40:33:06:2f:98:f6)  → Router hardware
Src: Intel_6d:80:58 (a8:64:f1:6d:80:58)                  → Your laptop's Wi-Fi card
Src: VestelElektr_c3:a0:71 (70:54:b4:c3:a0:71)           → Vestel device (TV/decoder)
Dst: IPv4mcast_7f:ff:fa (01:00:5e:7f:ff:fa)               → Multicast traffic (normal discovery)
```

**Interpreting these:**

- `TaicangT&WEl` = the MAC vendor for Taicang T&W Electronics, which makes router/DSL hardware. This is the gateway/router.
- `Intel_6d:80:58` = your laptop's Intel Wi-Fi card. The `a8:64:f1` OUI prefix identifies Intel.
- `VestelElektr` = Vestel Elektronik, a Turkish electronics manufacturer making smart TVs and set-top boxes. Not a camera.
- `IPv4mcast_7f:ff:fa` = the SSDP multicast address. Devices broadcasting UPnP announcements go here. Normal network behavior.

**Important limitation of Wireshark on a normal Wi-Fi network:**

On a standard WPA2 Wi-Fi network, your laptop's Wi-Fi card operates in *managed mode*, not *monitor mode*. You only see:
- Your own traffic (unicast to/from your IP)
- Broadcast traffic (sent to 255.255.255.255)
- Multicast traffic (sent to multicast groups)

You do **not** see unicast traffic between other devices (e.g., phone talking to camera). That traffic is encrypted at the Wi-Fi layer and addressed to other MACs. To see all Wi-Fi traffic, you'd need a card capable of monitor mode and promiscuous capture — which is out of scope here.

---

## 7. Phase 3 — Active LAN Discovery with Nmap

Now actively scan the network to find all live devices.

### Command

```cmd
nmap -sn 192.168.1.0/24
```

**Flags explained:**

| Flag | Meaning |
|---|---|
| `nmap` | The scanner |
| `-sn` | Ping scan only — sends ARP/ICMP/TCP to check if hosts are alive, no port scan |
| `192.168.1.0/24` | The entire /24 subnet |

This does not open any ports, read any services, or attempt any access. It simply asks "which devices respond?"

### What was actually found

```
Nmap scan report for 192.168.1.3
Host is up (0.094s latency).
MAC Address: B2:4E:26:B2:E4:BE (Unknown)

Nmap scan report for 192.168.1.38
Host is up (0.065s latency).
MAC Address: 5C:E9:31:E0:56:D9 (TP-Link Systems)

Nmap scan report for 192.168.1.74
Host is up (0.078s latency).
MAC Address: 5C:E9:31:E0:5F:83 (TP-Link Systems)

Nmap scan report for 192.168.1.79
Host is up (0.13s latency).
MAC Address: 5C:E9:31:41:15:0A (TP-Link Systems)

Nmap scan report for 192.168.1.87
Host is up (0.12s latency).
MAC Address: 70:66:2A:58:34:52 (Sony Interactive Entertainment)

Nmap scan report for dsldevice.lan (192.168.1.254)
Host is up (0.0070s latency).
MAC Address: 40:33:06:2F:98:F6 (Taicang T&W Electronics)

Nmap scan report for 192.168.1.140
Host is up.

Nmap done: 256 IP addresses (7 hosts up) scanned in 6.55 seconds
```

### Classification of discovered devices

| IP | Vendor | Identity | Camera candidate? |
|---|---|---|---|
| 192.168.1.3 | Unknown (randomized MAC?) | Could be phone, IoT, or TP-Link WAP | Investigate |
| 192.168.1.38 | TP-Link Systems | Possible Tapo camera/smart device | **Yes** |
| 192.168.1.74 | TP-Link Systems | Possible Tapo camera/smart device | **Yes** |
| 192.168.1.79 | TP-Link Systems | Possible Tapo camera/smart device | **Yes** |
| 192.168.1.87 | Sony Interactive Entertainment | PlayStation — not a camera | No |
| 192.168.1.254 | Taicang T&W Electronics | Router/DSL box (hostname: dsldevice.lan) | No |
| 192.168.1.140 | No MAC (= your own machine) | Your laptop | No |

**Why .140 shows no MAC**: Your machine doesn't ARP itself — Nmap sees its own IP without needing to resolve a MAC address.

**Why randomized MACs appear**: Modern phones and Windows 10+ randomize their MAC addresses by default to prevent tracking across networks. `B2:4E:26:B2:E4:BE` has the locally-administered bit set (bit 1 of the first byte being `1`), which signals it's a randomized/local MAC, not a burned-in manufacturer MAC. This is why the vendor shows as Unknown.

### Saving output to file

```cmd
nmap -sn 192.168.1.0/24 -oN camera_audit_marrakech\nmap\lan_discovery.txt
```

`-oN` saves in "normal" format (human-readable). Other formats: `-oX` for XML, `-oG` for greppable, `-oA` for all three.

---

## 8. Phase 4 — Port Scanning Camera Candidates

For each suspected camera, scan the ports commonly used by IP camera services.

### Command

```cmd
nmap -sV -p 80,81,443,554,8000,8080,8081,8554,8899,5000,37777,34567 192.168.1.38
```

**Flags explained:**

| Flag | Meaning |
|---|---|
| `-sV` | Service/version detection — Nmap probes each open port to identify the service and version |
| `-p ...` | Comma-separated port list to check (no spaces) |
| `192.168.1.38` | Target IP |

### Why these specific ports

| Port | Protocol/Service | Camera relevance |
|---|---|---|
| 80 | HTTP web admin | Login panel |
| 81 | Alt HTTP admin | Some DVRs use this |
| 443 | HTTPS admin/API | Encrypted admin panel or local API |
| 554 | RTSP | Standard live video stream port |
| 8554 | RTSP alternate | Some cameras use this instead |
| 8000 | Hikvision service | EZVIZ/Hikvision-specific |
| 8080 | HTTP alt | Common alternate web panel port |
| 8081 | HTTP alt | Less common alternate |
| 8899 | IoT service | Common in generic Chinese IP cameras |
| 5000 | App/API | Various IoT use cases |
| 37777 | Dahua service | Dahua/Imou-specific |
| 34567 | DVR service | Generic DVR/IP camera service |

### What was actually found — all four suspects

**192.168.1.3:**
```
80/tcp    open   http    TP-LINK TD-W8968 http admin
81/tcp    closed
443/tcp   closed
554/tcp   closed
[all others closed]
MAC Address: B2:4E:26:B2:E4:BE (Unknown)
Service Info: Device: WAP; CPE: cpe:/h:tp-link:td-w8968
```
→ **TP-Link TD-W8968 wireless access point/router**. Not a camera. The `WAP` device type and `td-w8968` model confirm this is networking infrastructure.

**192.168.1.38:**
```
80/tcp    closed
443/tcp   open   ssl/https?
554/tcp   closed
[all others closed]
MAC Address: 5C:E9:31:E0:56:D9 (TP-Link Systems)
```

**192.168.1.74:**
```
80/tcp    closed
443/tcp   open   ssl/https?
554/tcp   closed
[all others closed]
MAC Address: 5C:E9:31:E0:5F:83 (TP-Link Systems)
```

**192.168.1.79:**
```
80/tcp    closed
443/tcp   open   ssl/https?
554/tcp   closed
[all others closed]
MAC Address: 5C:E9:31:41:15:0A (TP-Link Systems)
```

### Key interpretation

The most important result for cameras was:

```
554/tcp  closed  rtsp
8554/tcp closed  rtsp-alt
```

**No open RTSP ports on any camera candidate.**

This means: standard unauthenticated video stream ports are not exposed. A quick attacker who just tries `rtsp://192.168.1.X:554/` won't get anything.

All three do expose `443`. This is the TP-Link local API service. It is not a video feed — it's the control/app layer.

### Saving output

```cmd
nmap -sV -p 80,81,443,554,8000,8080,8081,8554,8899,5000,37777,34567 -oN camera_audit_marrakech\nmap\candidates_initial.txt 192.168.1.38 192.168.1.74 192.168.1.79
```

Note: you can pass multiple IPs at the end, space-separated.

---

## 9. Phase 5 — Service Fingerprinting

After finding open ports, go deeper on those specific ports to identify exactly what's running.

### Step 5a — TLS certificate and HTTP headers (Nmap scripts)

```cmd
nmap -p443 --script ssl-cert,http-title,http-headers 192.168.1.38
nmap -p443 --script ssl-cert,http-title,http-headers 192.168.1.74
nmap -p443 --script ssl-cert,http-title,http-headers 192.168.1.79
```

**Flags explained:**

| Flag | Meaning |
|---|---|
| `--script ssl-cert` | Extract and display the TLS certificate details |
| `--script http-title` | Try to fetch the page title from the HTTP response |
| `--script http-headers` | Show the raw HTTP response headers |

### What was actually found on 192.168.1.38

```
PORT    STATE SERVICE
443/tcp open  https
|_http-title: Site doesn't have a title.
| http-headers:
|   Connection: close
|   Cache-Control: no-cache
|_  (Request type: GET)
| ssl-cert: Subject: commonName=TPRI-DEVICE/organizationName=TPRI/countryName=US
| Issuer: commonName=TPRI-DEVICE/organizationName=TPRI/countryName=US
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2001-01-01T00:00:00
| Not valid after:  2070-12-31T23:59:59
| MD5:     998a ffe7 ...
| SHA-1:   4c12 93ad ...
|_SHA-256: 93c2 5b48 ...
MAC Address: 5C:E9:31:E0:56:D9 (TP-Link Systems)
```

Same certificate pattern on .74 and .79. Note: .74 and .79 have **different SHA fingerprints** from .38, confirming they are separate physical devices (each generates its own cert), but the same product family.

### What the certificate tells us

| Field | Value | Meaning |
|---|---|---|
| commonName | TPRI-DEVICE | TP-Link Tapo internal device identifier |
| organizationName | TPRI | TP-Link's internal product division identifier |
| Self-signed | issuer = subject | No CA involved; device signs its own cert |
| RSA 1024-bit | Public Key bits: 1024 | Weak by 2024+ standards (≥2048 recommended) |
| Validity 2001–2070 | unrealistic dates | Baked-in cert; device doesn't manage cert lifecycle |

The browser warning ("Vous n'êtes pas en lieu sûr") is caused entirely by this self-signed cert. It does **not** mean hacked, vulnerable, or feed-exposed. It means: "this certificate isn't from a trusted CA."

### Step 5b — Deeper scan with fast timeout flags

The basic `-sV` scan hanged during the lab when `--version-all` was used. Explanation:

```cmd
nmap -sV -O --version-all -p 443 192.168.1.74
```

This is **too aggressive for IoT devices**. `--version-all` sends every possible probe to identify the service version. IoT HTTPS APIs are not standard web servers — they often ignore unknown probes, causing Nmap to wait for responses that never come.

**Corrected approach — fast scan with timeout:**

```cmd
nmap -Pn -n -T3 --max-retries 2 --host-timeout 45s -p 443,2020,8443,8800,10443,50443,554,8554,80,8080 --open 192.168.1.74
```

**Every new flag explained:**

| Flag | Meaning |
|---|---|
| `-Pn` | Don't ping first — assume host is up (avoids wasted ARP time) |
| `-n` | No DNS resolution — don't try to look up the hostname |
| `-T3` | Normal timing (0=paranoid, 1=sneaky, 2=polite, 3=normal, 4=aggressive, 5=insane) |
| `--max-retries 2` | Try each port max 2 times before giving up |
| `--host-timeout 45s` | Abandon the whole host if it takes more than 45 seconds |
| `--open` | Only show open ports (cleaner output) |

### What the fast scan actually found

**192.168.1.74:**
```
443/tcp  open  https
8443/tcp open  https-alt
8800/tcp open  sunwebadmin
```

**192.168.1.38:**
```
443/tcp  open  https
8443/tcp open  https-alt
8800/tcp open  sunwebadmin
```

**192.168.1.79:**
```
443/tcp  open  https
8800/tcp open  sunwebadmin
```

Note `.79` doesn't have `8443` open. This likely means a different model or firmware version within the Tapo family.

### What "sunwebadmin" means on port 8800

Nmap labels ports based on a historical port database. `8800/sunwebadmin` is just the historical name Nmap has for port 8800. **It does not mean this is Sun WebAdmin**. It means something is listening on TCP 8800. The actual service is TP-Link/Tapo-specific — determined by the CSeq response in Phase 6.

### Script scan on all confirmed open ports

```cmd
nmap -Pn -n -p443,8443,8800 --script ssl-cert,http-title,http-headers --host-timeout 45s 192.168.1.38
nmap -Pn -n -p443,8443,8800 --script ssl-cert,http-title,http-headers --host-timeout 45s 192.168.1.74
nmap -Pn -n -p443,8800 --script ssl-cert,http-title,http-headers --host-timeout 45s 192.168.1.79
```

**Results for .79 (showed http-headers this time):**
```
443/tcp open  https
| ssl-cert: [TPRI-DEVICE cert]
|_http-title: Site doesn't have a title.
| http-headers:
|   Connection: close
|   Cache-Control: no-cache
|_  (Request type: GET)
8800/tcp open  sunwebadmin
```

The `Cache-Control: no-cache` and no page title are consistent with an API endpoint, not a human web panel.

---

## 10. Phase 6 — Testing Unauthenticated Access with curl

curl is a command-line HTTP(S) client. Use it to probe services more precisely than a browser — you control exactly what request is made and can see the raw response.

### What curl flags mean

| Flag | Meaning |
|---|---|
| `-k` | Ignore TLS certificate errors (essential for self-signed IoT certs) |
| `-I` | HEAD request — asks for headers only, not body |
| `-v` | Verbose — shows the full request/response exchange |
| `--connect-timeout 5` | Give up trying to connect after 5 seconds |
| `--max-time 10` | Give up the whole request after 10 seconds |
| `-k -I` | Combined: ignore cert + headers only |

### Port 443 — Testing the HTTPS API

```cmd
curl -k -I --connect-timeout 5 --max-time 10 https://192.168.1.74
```

**Actual result:**
```
HTTP/1.1 405 Method Not Allowed
Connection: close
Cache-Control: no-cache
Content-Type: application/json;charset=UTF-8
Content-Length: 23
```

```cmd
curl -k -v --connect-timeout 5 --max-time 10 https://192.168.1.74
```

**Actual result:**
```
* Trying 192.168.1.74:443...
* schannel: disabled automatic use of client certificate
* schannel: using IP address, SNI is not supported by OS.
* ALPN: curl offers http/1.1
* ALPN: server did not agree on a protocol. Uses default.
* Established connection to 192.168.1.74 (192.168.1.74 port 443) from 192.168.1.140 port 46645
> GET / HTTP/1.1
> Host: 192.168.1.74
< HTTP/1.1 404 Not Found
< Connection: close
< Cache-Control: no-cache
* schannel: server closed abruptly (missing close_notify)
curl: (56) schannel: server closed abruptly (missing close_notify)
```

**What this means piece by piece:**

- `405 Method Not Allowed` on HEAD: The service explicitly rejects the HEAD method. This means it's opinionated about what methods it accepts — indicative of an API, not a web server.
- `Content-Type: application/json`: The service speaks JSON. It is a REST/JSON API, not a human web dashboard.
- `404 Not Found` on GET /: The root path (`/`) doesn't exist as a valid API endpoint. The API has specific paths not guessable without documentation.
- `schannel: using IP address, SNI is not supported by OS`: Windows curl (schannel) doesn't send Server Name Indication when connecting to a bare IP. SNI is normally used to indicate which domain you're connecting to in a TLS handshake — irrelevant here since we're using an IP.
- `schannel: server closed abruptly (missing close_notify)`: The IoT device doesn't send a proper TLS close notification. Minor sloppiness, not a vulnerability.
- **No feed. No config. No credentials returned.** The API gate is intact.

### Port 8443 — TLS handshake failure

```cmd
curl -k -I https://192.168.1.74:8443
```

**Actual result:**
```
curl: (35) schannel: next InitializeSecurityContext failed: 
SEC_E_ILLEGAL_MESSAGE (0x80090326) - This error usually occurs when a 
fatal SSL/TLS alert is received (e.g. handshake failed).
```

**What this means:**

Port 8443 is open (Nmap confirmed it), but when curl tries to do a TLS handshake, the device immediately alerts with a fatal TLS error. This suggests:

- A proprietary TLS configuration the device only accepts from its own app client
- A TLS cipher or version mismatch between Windows schannel and the device's embedded TLS stack
- Possibly mutual TLS (mTLS) where the device expects a client certificate curl isn't providing
- Non-TLS protocol running on a port Nmap labeled as HTTPS-alt

Either way: **not a feed exposure, not unauthenticated access.**

### Port 8800 — The CSeq fingerprint

```cmd
curl -I --connect-timeout 5 --max-time 10 http://192.168.1.74:8800
```

**Actual result:**
```
HTTP/1.0 400 Bad Request
CSeq: 0
Date: Tue, 02 Jun 2026 17:00:01 UTC
```

```cmd
curl -v --connect-timeout 5 --max-time 10 http://192.168.1.74:8800
```

**Actual result (truncated):**
```
> GET / HTTP/1.1
> Host: 192.168.1.74:8800
< HTTP/1.0 400 Bad Request
< CSeq: 0
< Date: Tue, 02 Jun 2026 17:00:06 UTC
* Operation timed out after 10004 milliseconds with 0 bytes received
curl: (28) Operation timed out after 10015 milliseconds with 0 bytes received
```

**What CSeq means:**

`CSeq` (Command Sequence) is a header used in RTSP protocol to number requests. It is not a standard HTTP header. Its presence in the response to an HTTP request on port 8800 is the most interesting protocol fingerprint in this entire lab. It tells us:

> Port 8800 is running something RTSP-like or a protocol that inherited RTSP conventions.

However, `curl` sent `GET / HTTP/1.1` — a web request. The device replied `400 Bad Request` with `CSeq: 0`, meaning:

> "I received a request I don't understand (because you're speaking HTTP to an RTSP-like service), and here's CSeq: 0 to acknowledge request sequence 0."

Then it hung (10+ second timeout). The device sent the header response but didn't send a body — it's waiting for the client to speak the proper protocol.

**No feed. No config. The service requires the correct client protocol to proceed.**

Also tested HTTPS on 8800:

```cmd
curl -k -I https://192.168.1.74:8800
```

```
curl: (35) schannel: ...SEC_E_INVALID_TOKEN (0x80090308) - Le jeton fourni à 
la fonction n'est pas valide
```

Port 8800 does not speak normal HTTPS either. It is a custom protocol.

### Curl interpretation table

| Response | Meaning |
|---|---|
| `401 Unauthorized` | Auth gate working — good |
| `403 Forbidden` | Blocked — good |
| `404 Not Found` | Service exists, root path invalid |
| `405 Method Not Allowed` | API exists, wrong method |
| `400 Bad Request` | Service exists, wrong protocol |
| `Empty reply / timeout` | Service closed connection or expects different client |
| TLS handshake failure | Service expects specific TLS config |
| JSON response with data | API exists and returned something — check what |
| HTML page without login | Possible finding — document |
| Any feed/config content | **Critical finding** — stop and document |

---

## 11. Phase 7 — Web Browser Check

Open the suspected camera IPs in a browser as a quick visual check.

```
https://192.168.1.38
https://192.168.1.74
https://192.168.1.79
```

**What was seen:** Chrome showed "Vous n'êtes pas en lieu sûr" (the self-signed cert warning) on all three. Proceeding past the warning (click Advanced → Proceed) shows either a blank page or no content — consistent with the API-only behavior confirmed by curl.

**Decision matrix:**

| Browser shows | Meaning | Action |
|---|---|---|
| Login page | Auth-gated (normal) | Document, don't enter credentials |
| Blank / refused | No web panel | Document |
| JSON error | API endpoint at root | Document, note Content-Type |
| Live camera feed | **Critical** | Stop, document, report |
| Settings panel | **Critical** | Stop, document, report |
| Certificate warning only | Self-signed cert (normal IoT) | Proceed with caution, only on local IPs |

**Do not** enter any passwords during this test. The only question being answered is: can a zero-credential visitor see anything?

---

## 12. Phase 8 — RTSP Feed Check with VLC

If port 554 or 8554 were open, this would be the next step. They were closed in this lab, so this is documented for completeness and for replication on other networks.

### When to do this

Only when Nmap shows:
```
554/tcp open rtsp
```
or
```
8554/tcp open rtsp-alt
```

### How to use VLC

Open VLC → Media → Open Network Stream

Try these URLs (replace IP with your target):

```
rtsp://192.168.1.X:554/
rtsp://192.168.1.X:554/live
rtsp://192.168.1.X:554/stream1
rtsp://192.168.1.X:554/h264
rtsp://192.168.1.X:554/ch0_0.264
rtsp://192.168.1.X:554/channel1
```

For Tapo cameras specifically (if RTSP is enabled via the app):
```
rtsp://username:password@192.168.1.X/stream1
rtsp://username:password@192.168.1.X/stream2
```

**TP-Link's official RTSP format requires a camera account created in the Tapo app first.** RTSP is not active by default — the camera account must be explicitly created, which also sets the RTSP username/password.

### Interpreting VLC results

| VLC shows | Meaning |
|---|---|
| Feed plays without credentials | **Critical: unauthenticated feed exposure** |
| Username/password prompt | Auth gate — good |
| "401 Unauthorized" | Auth gate — good |
| Connection failed | RTSP not available or wrong path |
| "Unsupported path" | Wrong URL path — not a finding yet |

### The RTSP handshake

This is what a normal auth-gated RTSP session looks like at the protocol level:

```
Client → Camera:  OPTIONS rtsp://... RTSP/1.0
Camera → Client:  200 OK (lists supported methods)

Client → Camera:  DESCRIBE rtsp://... RTSP/1.0
Camera → Client:  401 Unauthorized
                  WWW-Authenticate: Digest realm="..." nonce="..."

Client → Camera:  DESCRIBE rtsp://... RTSP/1.0
                  Authorization: Digest username="...", response="..."
Camera → Client:  200 OK (stream description)

Client → Camera:  SETUP rtsp://...
Camera → Client:  200 OK (session setup)

Client → Camera:  PLAY rtsp://...
Camera → Client:  200 OK (stream begins)
```

If you see this in Wireshark while doing the VLC test, the camera is properly auth-gating RTSP.

If the camera skips the 401 step and immediately sends a 200 OK with the stream description — that's the vulnerability.

---

## 13. Phase 9 — ONVIF & UDP Discovery

### UDP discovery ports

```cmd
nmap -sU -p 1900,3702,5353 192.168.1.38
```

**Flags:**

| Flag | Meaning |
|---|---|
| `-sU` | UDP scan (not TCP) |
| `-p 1900,3702,5353` | The three main discovery ports |

### What was actually found

```
1900/udp closed upnp
3702/udp closed ws-discovery
5353/udp closed zeroconf
```

On .38, all three UDP discovery ports returned **closed**. UDP "closed" means the device sent back an ICMP "port unreachable" — it's actively saying those services don't exist.

The scans on .74 and .79 **failed with "failed to determine route"** — the machine had drifted off the camera network onto a hotspot (see [Section 18](#18-errors-made--what-they-teach)).

### Interpretation

| UDP port | Result | Meaning |
|---|---|---|
| 1900 UPnP/SSDP | Closed | No UPnP discovery service active |
| 3702 WS-Discovery/ONVIF | Closed | No ONVIF discovery active |
| 5353 mDNS | Closed | No mDNS advertisement |

The closed UPnP result is a positive security finding: the device isn't advertising itself via UPnP, and isn't potentially requesting port forwards from the router via UPnP.

### ONVIF Device Manager (tool)

For a GUI-based ONVIF check, install ONVIF Device Manager (Windows freeware). Open it and it auto-discovers ONVIF devices on the LAN. Classification:

| Result | Meaning |
|---|---|
| Device detected (no auto-login) | Normal discovery |
| Metadata visible without login | Low/medium exposure |
| Stream URI returned without login | High |
| Live feed without login | Critical |
| PTZ control without login | Critical |

In this lab, with 3702/UDP closed, ONVIF Device Manager would find nothing.

---

## 14. Phase 10 — Wireshark During Active App Use

This is the **highest-value Wireshark step**: observing what happens on the wire while the official camera app is in use.

### Setup

```
Display filter: ip.addr == 192.168.1.38 || ip.addr == 192.168.1.74 || ip.addr == 192.168.1.79
```

Start capture. Then have someone open the official Tapo app on a phone on the same Wi-Fi and view one camera feed for 10–20 seconds.

### What you're trying to determine

> Does the phone talk to the camera directly (LAN path), or does it only communicate through the cloud?

### Filtering strategies during app testing

**See all traffic involving the cameras:**
```
ip.addr == 192.168.1.38 || ip.addr == 192.168.1.74 || ip.addr == 192.168.1.79
```

**See camera traffic on the known service ports:**
```
(ip.addr == 192.168.1.38 || ip.addr == 192.168.1.74 || ip.addr == 192.168.1.79) && (tcp.port == 443 || tcp.port == 8443 || tcp.port == 8800)
```

**See TLS handshakes:**
```
tls
```

**See DNS queries (what domains is the camera contacting?):**
```
dns
```

**See discovery traffic:**
```
mdns || udp.port == 1900 || udp.port == 3702
```

### Interpreting the results

| Observation | Meaning |
|---|---|
| Phone → Camera:443 | Local LAN API/control path active |
| Phone → Camera:8800 | Local proprietary stream/control path active |
| Phone → Camera:554 | Local RTSP path active |
| Phone → only external IPs | Feed is cloud-mediated; no local path during this test |
| Camera → external IPs (always) | Normal cloud keepalive/reporting |
| Camera opens new dynamic port during viewing | Enumerate that port separately |

If the phone talks directly to `192.168.1.X:8800` while viewing the feed, that port 8800 (with its CSeq header and RTSP-like protocol) is the local video channel. The feed would be encrypted (the TLS fingerprint showed the device has a TLS layer), and it requires the app's credentials/authentication to use — but this would confirm the CSeq hypothesis.

**This step was not completed in this lab session.** It is the natural next step.

---

## 15. Phase 11 — Router-Side Audit

This is a critical step that goes beyond the cameras themselves.

### What to check

Log into the router admin panel (here: `http://192.168.1.254`). Check:

- **DHCP client list**: Confirms device names. May show `Tapo_C200`, `Tapo_C310`, etc. — definitively identifies camera models.
- **UPnP status**: If enabled, devices can open external ports automatically without your knowledge.
- **Port forwarding rules**: Any existing rules? Any rules that forward camera ports (554, 8080, 8000) externally?
- **DMZ**: Is any device placed in the DMZ (exposed to all internet traffic)? This would be a critical finding.
- **Remote management**: Is the router admin page accessible from the internet?
- **Guest network**: Are cameras on the same network as personal laptops? Ideally cameras should be isolated on an IoT/guest VLAN.
- **Unknown devices**: Any devices that don't match expected inventory?

### Severity of dangerous findings

| Finding | Severity |
|---|---|
| UPnP enabled | Medium (enables device-initiated port forwarding) |
| Camera appears in port forwarding rules | High (camera service exposed to internet) |
| Port 554 forwarded externally | High (RTSP potentially internet-accessible) |
| DMZ configured to a camera IP | Critical |
| Remote router management enabled | High |
| All devices on same flat LAN with no IoT separation | Medium |

### Why UPnP matters in detail

A TP-Link Tapo camera with UPnP enabled can send this request to the router:

```
"Please create a port forwarding rule: forward external port 8800 → 192.168.1.74:8800"
```

The router obeys. Now port 8800 on your public IP forwards to your camera. Anyone in the world can try to connect to it. This is how cameras that "should be private" end up visible in Shodan (the search engine that indexes internet-exposed devices).

---

## 16. Phase 12 — Internet Exposure Check

Test whether any camera services are reachable from outside the house.

### Step 1: Find your public IP

From inside the house Wi-Fi, search "what is my ip" in a browser. Note the IP.

### Step 2: Test from outside

Disconnect your phone from Wi-Fi and use mobile data (or use a VPN, or use an external port-checking tool).

```bash
nmap -Pn -p 80,443,554,8080,8000,8800,37777 PUBLIC_IP
```

`-Pn` treats the host as online even if ICMP (ping) is blocked — common for home routers.

### Interpreting results

| Result | Meaning |
|---|---|
| All filtered/closed | Good — no camera services internet-exposed |
| 554 open | RTSP potentially internet-accessible — high risk |
| 8080 open | Web panel potentially internet-accessible |
| 8800 open | Tapo-like service potentially internet-accessible |
| 8000/37777 open | Hikvision/Dahua service exposed |
| Router admin page reachable | Bad — router management exposed |

**Do not** attempt to access feeds or settings via the public IP unless explicitly confirming whether a login gate exists. Stop once you've established exposure status.

---

## 17. Phase 13 — CVE Research Workflow

CVE research only becomes meaningful once you have confirmed brand, model, and firmware. Without these, you're searching blindly.

### What to collect before searching

```
Brand:       TP-Link
Product:     Tapo (series)
Model:       [from router DHCP — e.g. C200, C210, C310]
Firmware:    [from app settings or banner]
Open ports:  443, 8443, 8800
Services:    Local HTTPS API (443), proprietary protocol (8800)
RTSP:        Not confirmed active
ONVIF:       Not confirmed active
Cloud:       TP-Link Tapo cloud (tplinkcloud.com family)
```

### Search terms

```
"TP-Link Tapo C200 CVE"
"TP-Link Tapo authentication bypass"
"TP-Link Tapo RTSP vulnerability"
"TP-Link Tapo local API security"
"TPRI-DEVICE vulnerability"
"TP-Link camera command injection"
"Tapo firmware vulnerability"
```

### CVE classification

For each CVE found:

| Field | What to check |
|---|---|
| CVE ID | Note for the report |
| Affected model | Does it match yours exactly? |
| Affected firmware | Is your version in the range? |
| Vulnerability type | Auth bypass, RCE, info disclosure, etc. |
| Attack vector | LAN-only? Internet? Physical? |
| Safe validation | Can you confirm without exploiting? (version match, config check, banner) |
| Don't do | Live exploit on a production device |

**Important**: A Hikvision CVE doesn't apply to a Tapo camera. A Tapo C200 CVE may not apply to a C310. A firmware CVE for version 1.1.x doesn't apply to version 1.3.x. Always confirm model and firmware match before treating a CVE as relevant.

### Safe firmware analysis path (for spare/lab devices only)

If you want to go deeper — not on live production cameras — the safe path is:

1. Download firmware from the vendor's support site
2. Extract with `binwalk`
3. Analyze offline

```bash
binwalk firmware.bin           # Show embedded filesystem structure
binwalk -e firmware.bin        # Extract
strings firmware.bin | less    # Show all readable strings

# Search for interesting patterns in extracted files:
grep -R "rtsp" extracted/
grep -R "password" extracted/
grep -R "admin" extracted/
grep -R "system(" extracted/   # Possible command injection sinks
grep -R "popen" extracted/     # Possible command injection sinks
grep -R "telnet" extracted/    # Debug shell
grep -R "dropbear" extracted/  # SSH daemon
```

This can produce a serious audit artifact without touching a live device.

---

## 18. Errors Made & What They Teach

These are the actual mistakes that occurred during the lab. Each one is a learning opportunity — not embarrassments to omit, but the most realistic teaching material.

### Error 1 — Pasting two commands on one line

**What happened:**
```cmd
nmap -sV -p 80,81... 192.168.1.Xnmap -sV -p 80,81... 192.168.1.254
```

**Error message:**
```
Only 1 -p option allowed, separate multiple ranges with commas.
QUITTING!
```

**Why it happened:** Copy-pasted a command with the placeholder `X` still in it, then immediately pasted another command, so they merged into one line. Nmap saw two `-p` options.

**What it teaches:**
- `192.168.1.X` in documentation is a **placeholder**. Always replace `X` with an actual number like `38`, `74`, etc.
- Nmap allows only one `-p` flag. Multiple port ranges go in a single comma-separated list: `-p 80,443,554`.
- Read error messages. "Only 1 -p option allowed" is completely specific and self-explanatory.

**Correction:**
```cmd
nmap -sV -p 80,81,443,554,8000,8080,8081,8554,8899,5000,37777,34567 192.168.1.38
```

---

### Error 2 — Scanning with `--version-all` on IoT HTTPS

**What happened:**
```cmd
nmap -sV -O --version-all -p 443 192.168.1.74
```

Nmap ran for 60+ seconds with "33.33% done" and didn't complete.

**Why it happened:** `--version-all` sends every possible probe to identify service version. IoT HTTPS devices have embedded TLS stacks that:
- Don't respond to unknown probe types
- Stall connections instead of closing them
- Expect specific client handshakes

Nmap waits for responses that never come.

**What it teaches:**
- `-O` (OS detection) and `--version-all` are aggressive flags that work well on standard servers but poorly on embedded IoT devices.
- Always use `--host-timeout` when scanning IoT: `--host-timeout 45s`
- Use `--version-light` for embedded devices: sends fewer, faster probes
- Use `Ctrl+C` to abort stuck scans

**Correction:**
```cmd
nmap -Pn -n -T3 --max-retries 2 --host-timeout 45s -p 443,8443,8800 --open 192.168.1.74
```

This completed in 2.77 seconds vs infinite hang.

---

### Error 3 — Accidentally switching Wi-Fi networks

**What happened:**

Mid-lab, scans on .74 and .79 started failing with:
```
setup_target: failed to determine route to 192.168.1.74
```

Running `ipconfig` revealed:
```
Adresse IPv4 : 172.20.10.3
Masque : 255.255.255.240
Passerelle : 172.20.10.1
```

**Why it happened:** The machine switched from the house Wi-Fi (`192.168.1.0/24`) to a phone hotspot (`172.20.10.0/28`). This can happen automatically if the phone hotspot was on and the house Wi-Fi signal dropped momentarily.

**What it teaches:**

`172.20.10.x` with a `/28` subnet (255.255.255.240) is the signature IP range of an **iPhone personal hotspot**. The `/28` gives 16 addresses — typical hotspot behavior.

When your machine is on a completely different network, it has no routing path to `192.168.1.x`. The scan attempts fail with "failed to determine route" because your routing table has no entry for that subnet.

The previous scan results are not invalidated — they were obtained while on the correct network. But any scans run while on the wrong network produce meaningless results.

**Diagnosis command:**
```cmd
ipconfig
```
Always check your IP before running scans. Confirm:
```
Adresse IPv4: 192.168.1.xxx  ← correct
Passerelle:   192.168.1.254   ← correct
```

**Recovery:**
1. Reconnect to the house Wi-Fi
2. Run `ipconfig` to confirm you're back on `192.168.1.x`
3. Ping the targets: `ping 192.168.1.74`
4. Rerun the discovery: `nmap -sn 192.168.1.0/24`

**What `arp -a` can help with:**

If you're not sure whether you're on the right network, `arp -a` shows devices your machine has recently communicated with. If you see `192.168.1.38` in the ARP table, your machine has had that route recently.

---

### Error 4 — Browser "not secure" warning misread as a vulnerability

**What happened:** Visiting `https://192.168.1.38` in Chrome showed "Vous n'êtes pas en lieu sûr." This was momentarily interpreted as evidence of a security problem.

**Why it happens:** The browser is warning that the TLS certificate isn't from a trusted CA. This is by design for local IoT devices — they use self-signed certificates.

**What it teaches:**
- A browser security warning on a **local IP** (192.168.x.x, 10.x.x.x, 172.16.x.x) is almost always a self-signed certificate, not an attack.
- The same warning on a **public domain** (e.g., `https://bankofamerica.com`) would be alarming.
- Self-signed ≠ hacked. Self-signed = "I issued my own certificate instead of getting one from DigiCert/Let's Encrypt."
- The RSA 1024-bit key in the TPRI cert is genuinely weak by modern standards, but it's a local-only service — the threat model is different from a public HTTPS server.

---

### Error 5 — Misreading Nmap's port service labels

**What happened:** Nmap labeled port 8800 as `sunwebadmin`, causing initial confusion about what the service was.

**What it teaches:** Nmap's port service database is historical. Port numbers were assigned to specific services decades ago, but any service can run on any port. The label `sunwebadmin` just means "port 8800 was historically used by Sun WebAdmin." It tells you nothing about what's actually running there. The `CSeq` header in the curl response told us far more than the Nmap label.

Always probe the service yourself — the label is a starting hypothesis, not a fact.

---

## 19. Final Findings & Severity Classification

### Device inventory

| IP | Vendor | Open ports | Identity | Role |
|---|---|---|---|---|
| 192.168.1.3 | TP-Link (randomized MAC) | 80 (thttpd) | TD-W8968 WAP | Access point/router |
| 192.168.1.38 | TP-Link Systems | 443, 8443, 8800 | Tapo camera candidate | Camera |
| 192.168.1.74 | TP-Link Systems | 443, 8443, 8800 | Tapo camera candidate | Camera |
| 192.168.1.79 | TP-Link Systems | 443, 8800 | Tapo camera candidate | Camera |
| 192.168.1.87 | Sony Interactive | — | PlayStation | Console |
| 192.168.1.254 | Taicang T&W | 80 (thttpd) | DSL router | Gateway |

### Findings

**Finding 1 — Local Discovery and Device Identification**

Three TP-Link devices at .38, .74, and .79 were discovered on the LAN via MAC address vendor identification. Any attacker connected to the same Wi-Fi can enumerate these devices in under 10 seconds with a ping scan.

Severity: **Info** — Device discovery is expected behavior; mitigated by requiring Wi-Fi credentials to be on the LAN.

---

**Finding 2 — Proprietary Local Service Exposure**

All three devices expose TCP/443 (local HTTPS JSON API) and TCP/8800 (RTSP-like proprietary protocol). Two also expose TCP/8443 (proprietary TLS service). These services are reachable from any device on the LAN.

Severity: **Info/Low** — Services are exposed but require authentication. No unauthenticated access was confirmed.

---

**Finding 3 — Weak TLS Certificate Configuration**

All three devices present self-signed TLS certificates identifying as `TPRI-DEVICE/TPRI` with 1024-bit RSA keys and unrealistic validity windows (2001–2070).

Severity: **Low** — The weak key size and long validity period are informational security hygiene issues for local services. No practical exploit path was identified from this alone during this engagement.

---

**Non-finding — RTSP not exposed**

TCP/554 (RTSP) and TCP/8554 (RTSP-alt) were closed on all three camera candidates. Standard unauthenticated video stream paths are not available.

Severity: **None / positive** — This is the expected secure configuration.

---

**Non-finding — ONVIF/UPnP not exposed**

UDP/1900 (UPnP/SSDP), UDP/3702 (WS-Discovery/ONVIF), and UDP/5353 (mDNS) were closed or non-responsive on tested devices.

Severity: **None / positive** — No discovery protocol exposure.

---

**Not yet tested (pending)**

- RTSP/ONVIF behavior when a camera account is enabled in the Tapo app
- Wireshark traffic during active app-to-camera session
- Router UPnP status and port forwarding rules
- Internet exposure check (external scan of public IP)
- Camera model confirmation via router DHCP list

### Summary severity table

| Finding | Severity | Description |
|---|---|---|
| LAN device discovery | Info | Cameras identifiable by MAC vendor |
| HTTPS API exposed on 443 | Info/Low | Auth-gated, JSON API only |
| Port 8800 CSeq service | Info/Low | Proprietary protocol, no feed confirmed |
| 1024-bit RSA cert | Low | Weak TLS hygiene, local service |
| RTSP 554/8554 closed | ✅ Positive | Standard feed ports not exposed |
| UPnP/ONVIF/mDNS closed | ✅ Positive | No discovery protocol exposure |

---

## 20. What Comes Next

The natural continuation of this lab in priority order:

**1. Wireshark during active app session**
Filter on camera IPs while someone opens the Tapo app and views a feed. Confirm whether:
- Phone talks to camera directly (LAN path on 443/8800)
- Or only cloud IPs are involved (pure cloud relay)
This determines whether the local services on 443 and 8800 are the actual feed channel.

**2. Router audit**
Log into `192.168.1.254`, check UPnP status, port forwarding, device names. The DHCP device name list will confirm whether the three TP-Link IPs are actually labeled as cameras by the router.

**3. Internet exposure check**
From mobile data: `nmap -Pn -p 80,443,554,8080,8800 [PUBLIC_IP]`

**4. Enable RTSP via Tapo app and retest**
In the Tapo app: create a camera account (separate from the main Tapo account). Once done, 554/TCP should open and the RTSP URL becomes:
```
rtsp://[camera_user]:[camera_pass]@192.168.1.38/stream1
```
Test in VLC — confirm auth is required.

**5. Model confirmation and CVE research**
Get model numbers from the app or router DHCP. Run targeted CVE searches.

---

## 21. Full Command Reference

All commands used in this lab, organized by purpose.

### Network identification

```cmd
ipconfig                          # Windows: show your IP, subnet, gateway
ip route                          # Linux: show routing table
arp -a                            # Show ARP table (IPs + MACs your machine knows)
```

### Fallback discovery if Nmap not available

```cmd
for /L %i in (1,1,254) do @ping -n 1 -w 50 192.168.1.%i >nul
arp -a
```
Pings every address in the /24 to populate the ARP table, then lists results.

### Nmap — host discovery

```cmd
nmap -sn 192.168.1.0/24
nmap -sn 192.168.1.0/24 -oN camera_audit_marrakech\nmap\lan_discovery.txt
```

### Nmap — camera port scan

```cmd
nmap -sV -p 80,81,443,554,8000,8080,8081,8554,8899,5000,37777,34567 192.168.1.38
nmap -sV -p 80,81,443,554,8000,8080,8081,8554,8899,5000,37777,34567 -oN output.txt 192.168.1.38
```

### Nmap — fast scan with timeout (IoT safe)

```cmd
nmap -Pn -n -T3 --max-retries 2 --host-timeout 45s -p 443,2020,8443,8800,10443,50443,554,8554,80,8080 --open 192.168.1.38
```

### Nmap — TLS certificate and headers

```cmd
nmap -p443 --script ssl-cert,http-title,http-headers 192.168.1.38
nmap -Pn -n -p443,8443,8800 --script ssl-cert,http-title,http-headers --host-timeout 45s 192.168.1.38
```

### Nmap — UDP discovery

```cmd
nmap -sU -p 1900,3702,5353 192.168.1.38
```

### Nmap — RTSP/ONVIF check

```cmd
nmap -Pn -n -p2020,554,8554 --open 192.168.1.38
```

### Nmap — internet exposure

```cmd
nmap -Pn -p 80,443,554,8080,8000,8800,37777 [PUBLIC_IP]
```

### curl — HTTPS probe

```cmd
curl -k -I --connect-timeout 5 --max-time 10 https://192.168.1.74
curl -k -v --connect-timeout 5 --max-time 10 https://192.168.1.74
curl -k -I --connect-timeout 5 --max-time 10 https://192.168.1.74:8443
curl -k -v --connect-timeout 5 --max-time 10 https://192.168.1.74:8443
```

### curl — non-HTTPS probe (port 8800)

```cmd
curl -I --connect-timeout 5 --max-time 10 http://192.168.1.74:8800
curl -v --connect-timeout 5 --max-time 10 http://192.168.1.74:8800
```

### VLC — RTSP test (when 554 is open)

```
rtsp://192.168.1.X:554/
rtsp://192.168.1.X:554/live
rtsp://192.168.1.X:554/stream1
rtsp://192.168.1.X:554/h264
rtsp://[user]:[pass]@192.168.1.X/stream1   ← Tapo authenticated format
```

### Wireshark display filters

```
arp                          # ARP traffic
bootp                        # DHCP
mdns                         # mDNS device announcements
udp.port == 1900             # UPnP/SSDP
udp.port == 3702             # WS-Discovery/ONVIF
rtsp                         # RTSP sessions
http                         # Unencrypted web
tls                          # TLS handshakes

ip.addr == 192.168.1.74      # All traffic to/from one camera

ip.addr == 192.168.1.38 || ip.addr == 192.168.1.74 || ip.addr == 192.168.1.79
                             # All camera traffic

(ip.addr == 192.168.1.38 || ip.addr == 192.168.1.74 || ip.addr == 192.168.1.79) && (tcp.port == 443 || tcp.port == 8443 || tcp.port == 8800)
                             # Camera traffic on confirmed open ports

tcp.port == 554              # RTSP traffic
dns                          # DNS lookups (what domains are cameras contacting?)
```

---

*Document compiled from lab session 2026-06-02. All testing conducted on authorized, family-owned equipment on a private residential LAN.*
