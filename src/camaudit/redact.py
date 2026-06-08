from __future__ import annotations

import ipaddress
import re

MAC_RE = re.compile(r"\b([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
TOKEN_RE = re.compile(
    r"\b(?:UID|UUID|SN|SERIAL|TOKEN|AUTH|API[-_]?KEY|KEY)\b\s*[:=_-]?\s*[A-Za-z0-9_-]{6,}\b",
    re.I,
)
SERIAL_RE = re.compile(r"\b[A-Z]{2,}[-_]?\d{4,}[-_]?[A-Z0-9]{2,}\b")
FEED_FILE_RE = re.compile(r"\b[^\s/\\]+\.(?:jpg|jpeg|png|mp4|mov|avi|mkv)\b", re.I)

RFC1918_NETWORKS = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)


def _redact_mac(match: re.Match[str]) -> str:
    mac = match.group(0).replace("-", ":").upper()
    return ":".join(mac.split(":")[:3]) + ":XX:XX:XX"


def _is_rfc1918_ip(ip: str) -> bool:
    try:
        address = ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    return any(address in network for network in RFC1918_NETWORKS)


def redact_text(text: str, *, strict: bool = False) -> str:
    text = MAC_RE.sub(_redact_mac, text)
    text = EMAIL_RE.sub("[REDACTED_EMAIL]", text)
    text = TOKEN_RE.sub("[REDACTED_TOKEN_OR_SERIAL]", text)
    text = SERIAL_RE.sub("[REDACTED_TOKEN_OR_SERIAL]", text)
    text = FEED_FILE_RE.sub("[REDACTED_MEDIA_FILE]", text)

    def ip_repl(match: re.Match[str]) -> str:
        ip = match.group(0)
        try:
            ipaddress.IPv4Address(ip)
        except ValueError:
            return ip
        if strict:
            return "[REDACTED_IP]"
        return ip if _is_rfc1918_ip(ip) else "[REDACTED_PUBLIC_IP]"

    return IP_RE.sub(ip_repl, text)
