from __future__ import annotations

from typing import Any

from camaudit.classifier import ClassificationResult
from camaudit.fingerprint import HostFingerprintResult
from camaudit.models import Finding, OpenPort, Severity

CAMERA_PORTS = {80, 81, 443, 554, 8000, 8080, 8081, 8554, 8899, 5000, 37777, 34567, 8443, 8800}
RTSP_PORTS = {554, 8554}
DISCOVERY_PORT_NAMES = {1900: "UPnP", 3702: "ONVIF/WS-Discovery", 5353: "mDNS"}


def _has_open_port(open_ports: list[OpenPort], port: int) -> bool:
    return any(item.port == port for item in open_ports)


def _exposure_enabled(exposure: dict[str, Any] | None, key: str) -> bool:
    return bool((exposure or {}).get(key))


def evaluate_severity(
    *,
    classification: ClassificationResult,
    open_ports: list[OpenPort],
    fingerprints: HostFingerprintResult | None = None,
    exposure: dict[str, Any] | None = None,
    cve_findings: list[Finding] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []

    if _exposure_enabled(exposure, "unauthenticated_feed_confirmed"):
        findings.append(
            Finding(
                title="Unauthenticated camera feed confirmed",
                severity=Severity.critical,
                evidence="Exposure mode indicated an unauthenticated feed was confirmed.",
                explanation=(
                    "A camera feed reachable without authentication is a critical privacy exposure."
                ),
                remediation="Disable unauthenticated streaming and require strong authentication.",
            )
        )

    if _exposure_enabled(exposure, "dmz_to_camera"):
        findings.append(
            Finding(
                title="DMZ forwards traffic to camera",
                severity=Severity.critical,
                evidence="Exposure mode indicated DMZ routing to a camera candidate.",
                explanation=(
                    "DMZ exposure can publish multiple camera services to untrusted networks."
                ),
                remediation="Remove the camera from DMZ and restrict inbound access.",
            )
        )

    if _exposure_enabled(exposure, "camera_port_public"):
        findings.append(
            Finding(
                title="Camera service exposed on public IP",
                severity=Severity.high,
                evidence="Exposure mode indicated a camera-related port reachable on a public IP.",
                explanation=(
                    "Public camera service exposure increases remote attack and privacy risk."
                ),
                remediation="Remove public exposure and use a VPN for remote access.",
            )
        )

    if _exposure_enabled(exposure, "port_forward_to_camera"):
        findings.append(
            Finding(
                title="Port forwarding to camera",
                severity=Severity.high,
                evidence="Exposure mode indicated router port forwarding to a camera candidate.",
                explanation="Port forwarding can expose local camera services beyond the LAN.",
                remediation="Disable camera port forwarding unless there is a documented need.",
            )
        )

    if fingerprints:
        upnp = next((item for item in fingerprints.udp_discovery if item.port == 1900), None)
        if upnp and upnp.state.startswith("open"):
            findings.append(
                Finding(
                    title="UPnP discovery enabled",
                    severity=Severity.medium,
                    evidence=f"UDP/1900 reported {upnp.state}.",
                    explanation=(
                        "UPnP can enable automatic network exposure if router policy permits it."
                    ),
                    remediation="Disable UPnP on routers unless explicitly required.",
                )
            )

        closed_discovery = [
            name
            for item in fingerprints.udp_discovery
            if item.state == "closed" and (name := DISCOVERY_PORT_NAMES.get(item.port))
        ]
        if closed_discovery:
            findings.append(
                Finding(
                    title="Local discovery protocols closed",
                    severity=Severity.positive,
                    evidence=", ".join(closed_discovery) + " reported closed.",
                    explanation="Closed discovery services reduce local enumeration surface.",
                    remediation=None,
                )
            )

        for tls in fingerprints.tls:
            if tls.public_key_bits == 1024:
                findings.append(
                    Finding(
                        title="1024-bit TLS certificate key",
                        severity=Severity.low,
                        evidence=f"TCP/{tls.port} certificate reports a 1024-bit public key.",
                        explanation="1024-bit TLS keys are weak by modern standards.",
                        remediation=(
                            "Regenerate or replace the device certificate with a stronger key."
                        ),
                    )
                )

    closed_rtsp = [port for port in RTSP_PORTS if not _has_open_port(open_ports, port)]
    if len(closed_rtsp) == len(RTSP_PORTS):
        findings.append(
            Finding(
                title="RTSP standard ports closed",
                severity=Severity.positive,
                evidence="TCP/554 and TCP/8554 were not reported open.",
                explanation="Standard RTSP feed paths were not exposed by the safe port scan.",
                remediation=None,
            )
        )

    api_ports = [
        port.port for port in open_ports if port.port in {443, 8443, 8800, 8000, 8080, 8081}
    ]
    if classification.candidate_type == "camera_candidate" and api_ports:
        api_evidence = ", ".join(f"TCP/{port}" for port in api_ports)
        findings.append(
            Finding(
                title="Local API reachable but auth-gated",
                severity=Severity.info,
                evidence=f"Local service ports observed: {api_evidence}.",
                explanation=(
                    "Camera-like local services are reachable, but no unauthenticated access "
                    "was confirmed."
                ),
                remediation=(
                    "Keep firmware updated and restrict camera services to trusted LAN segments."
                ),
            )
        )

    unknown_ports = [
        port.port
        for port in open_ports
        if port.port not in CAMERA_PORTS and classification.candidate_type == "unknown"
    ]
    if unknown_ports:
        unknown_evidence = ", ".join(f"TCP/{port}" for port in unknown_ports)
        findings.append(
            Finding(
                title="Unknown custom service with no data leakage",
                severity=Severity.info,
                evidence=f"Unclassified service ports observed: {unknown_evidence}.",
                explanation="The service is reachable locally, but no data leakage was confirmed.",
                remediation="Document the service owner and close it if it is unnecessary.",
            )
        )

    findings.extend(cve_findings or [])
    return findings
