from __future__ import annotations

import ipaddress
import re

MAC_RE = re.compile(r"\b([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
TOKEN_RE = re.compile(r"\b(?:UID|SN|SERIAL|TOKEN|AUTH|KEY)[-_:= ]?[A-Za-z0-9_-]{6,}\b", re.I)
FEED_FILE_RE = re.compile(r"\b[^\s/\\]+\.(?:jpg|jpeg|png|mp4|mov|avi|mkv)\b", re.I)


def _redact_mac(match: re.Match[str]) -> str:
    mac = match.group(0).replace("-", ":").upper()
    return ":".join(mac.split(":")[:3]) + ":XX:XX:XX"


def _is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def redact_text(text: str, *, strict: bool = False) -> str:
    text = MAC_RE.sub(_redact_mac, text)
    text = EMAIL_RE.sub("[REDACTED_EMAIL]", text)
    text = TOKEN_RE.sub("[REDACTED_TOKEN_OR_SERIAL]", text)
    text = FEED_FILE_RE.sub("[REDACTED_MEDIA_FILE]", text)

    def ip_repl(match: re.Match[str]) -> str:
        ip = match.group(0)
        if strict:
            return "[REDACTED_IP]"
        return ip if _is_private_ip(ip) else "[REDACTED_PUBLIC_IP]"

    return IP_RE.sub(ip_repl, text)
