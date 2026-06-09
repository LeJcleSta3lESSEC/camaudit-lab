from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from camaudit.models import DiscoveredHost, OpenPort

CandidateType = Literal["camera_candidate", "router", "console", "phone_or_randomized", "unknown"]

CAMERA_VENDOR_HINTS = (
    "hikvision",
    "dahua",
    "axis",
    "reolink",
    "uniview",
    "amcrest",
    "ezviz",
    "tapo",
    "tp-link",
    "tplink",
)
ROUTER_VENDOR_HINTS = ("netgear", "ubiquiti", "mikrotik", "avm", "fritz", "cisco", "juniper")
CONSOLE_VENDOR_HINTS = ("sony interactive", "nintendo", "xbox", "microsoft")
PHONE_OR_LAPTOP_HINTS = ("apple", "samsung", "intel", "dell", "lenovo", "hewlett", "hp inc")

CAMERA_PORT_WEIGHTS = {
    554: 25,
    8554: 25,
    8899: 20,
    37777: 20,
    34567: 20,
    8800: 18,
    8000: 12,
    8080: 10,
    8081: 10,
    8443: 10,
    10443: 10,
    50443: 10,
    80: 5,
    81: 8,
    443: 5,
    5000: 6,
    2020: 6,
}


class ClassificationResult(BaseModel):
    candidate_score: int = Field(ge=0, le=100)
    candidate_type: CandidateType
    reasons: list[str] = Field(default_factory=list)


def _lower_joined(*values: str | None) -> str:
    return " ".join(value for value in values if value).lower()


def _is_randomized_or_local_mac(mac_oui: str | None) -> bool:
    if not mac_oui:
        return False
    first_octet = mac_oui.split(":", 1)[0]
    try:
        return bool(int(first_octet, 16) & 0b10)
    except ValueError:
        return False


def classify_camera_candidate(
    host: DiscoveredHost,
    *,
    open_ports: list[OpenPort] | None = None,
    tls_certificate: dict[str, str | int | None] | None = None,
    hostname: str | None = None,
) -> ClassificationResult:
    ports = open_ports or []
    names = _lower_joined(host.vendor, host.hostname, hostname)
    cert_text = ""
    if tls_certificate:
        cert_text = _lower_joined(
            str(tls_certificate.get("common_name") or ""),
            str(tls_certificate.get("organization") or ""),
        )

    score = 0
    reasons: list[str] = []
    randomized_mac = _is_randomized_or_local_mac(host.mac_oui)

    if randomized_mac:
        reasons.append(
            "MAC OUI appears locally administered or randomized; classification is uncertain."
        )

    if any(hint in names or hint in cert_text for hint in CAMERA_VENDOR_HINTS):
        score += 35
        reasons.append("Vendor, hostname, or certificate contains a camera-family hint.")

    if "tapo" in names or "tapo" in cert_text:
        score += 15
        reasons.append("Tapo-like product hint increases camera likelihood.")

    for port in ports:
        weight = CAMERA_PORT_WEIGHTS.get(port.port)
        if weight:
            score += weight
            reasons.append(
                f"Open port {port.port}/{port.proto} is commonly seen on cameras or IoT devices."
            )

    if any(hint in names for hint in CONSOLE_VENDOR_HINTS):
        score = max(0, score - 45)
        reasons.append("Known game-console vendor reduces camera likelihood.")
        return ClassificationResult(
            candidate_score=min(score, 100),
            candidate_type="console",
            reasons=reasons,
        )

    if any(hint in names for hint in ROUTER_VENDOR_HINTS):
        score = max(0, score - 35)
        reasons.append("Known router/network infrastructure vendor reduces camera likelihood.")
        return ClassificationResult(
            candidate_score=min(score, 100),
            candidate_type="router",
            reasons=reasons,
        )

    if randomized_mac or any(hint in names for hint in PHONE_OR_LAPTOP_HINTS):
        score = min(score, 45)
        if any(hint in names for hint in PHONE_OR_LAPTOP_HINTS):
            reasons.append("Phone or laptop vendor hint keeps classification uncertain.")
        return ClassificationResult(
            candidate_score=score,
            candidate_type="phone_or_randomized",
            reasons=reasons,
        )

    score = min(score, 100)
    if score >= 50:
        return ClassificationResult(
            candidate_score=score,
            candidate_type="camera_candidate",
            reasons=reasons,
        )

    if not reasons:
        reasons.append(
            "No strong camera, router, console, phone, or randomized-MAC evidence found."
        )
    return ClassificationResult(candidate_score=score, candidate_type="unknown", reasons=reasons)
