from pathlib import Path

from camaudit.classifier import ClassificationResult
from camaudit.fingerprint import (
    HostFingerprintResult,
    TlsCertificateFingerprint,
    UdpDiscoveryFingerprint,
)
from camaudit.models import Finding, OpenPort, Severity
from camaudit.severity import evaluate_severity

CAMERA = ClassificationResult(
    candidate_score=85,
    candidate_type="camera_candidate",
    reasons=["camera-like vendor and ports"],
)
UNKNOWN = ClassificationResult(candidate_score=0, candidate_type="unknown", reasons=["no evidence"])


def _titles(findings: list[Finding]) -> set[str]:
    return {finding.title for finding in findings}


def _finding(findings: list[Finding], title: str) -> Finding:
    return next(finding for finding in findings if finding.title == title)


def test_unauthenticated_feed_confirmed_is_critical():
    findings = evaluate_severity(
        classification=CAMERA,
        open_ports=[],
        exposure={"unauthenticated_feed_confirmed": True},
    )

    assert any(finding.severity == Severity.critical for finding in findings)
    assert "Unauthenticated camera feed confirmed" in _titles(findings)


def test_camera_port_exposed_on_public_ip_is_high():
    findings = evaluate_severity(
        classification=CAMERA,
        open_ports=[OpenPort(port=554)],
        exposure={"camera_port_public": True},
    )

    assert "Camera service exposed on public IP" in _titles(findings)
    assert _finding(findings, "Camera service exposed on public IP").severity == Severity.high


def test_port_forwarding_to_camera_is_high():
    findings = evaluate_severity(
        classification=CAMERA,
        open_ports=[OpenPort(port=443)],
        exposure={"port_forward_to_camera": True},
    )

    assert _finding(findings, "Port forwarding to camera").severity == Severity.high


def test_dmz_to_camera_is_critical():
    findings = evaluate_severity(
        classification=CAMERA,
        open_ports=[OpenPort(port=443)],
        exposure={"dmz_to_camera": True},
    )

    assert _finding(findings, "DMZ forwards traffic to camera").severity == Severity.critical


def test_upnp_enabled_on_router_is_medium():
    fingerprints = HostFingerprintResult(
        target="192.168.1.1",
        udp_discovery=[UdpDiscoveryFingerprint(port=1900, state="open|filtered", service="upnp")],
    )

    findings = evaluate_severity(classification=UNKNOWN, open_ports=[], fingerprints=fingerprints)

    assert _finding(findings, "UPnP discovery enabled").severity == Severity.medium


def test_local_api_open_but_auth_gated_is_info():
    findings = evaluate_severity(classification=CAMERA, open_ports=[OpenPort(port=443)])

    assert _finding(findings, "Local API reachable but auth-gated").severity == Severity.info


def test_1024_bit_tls_cert_is_low():
    fingerprints = HostFingerprintResult(
        target="192.168.1.38",
        tls=[
            TlsCertificateFingerprint(
                port=443,
                public_key_bits=1024,
                raw_output_path=Path("results/raw/tls.txt"),
            )
        ],
    )

    findings = evaluate_severity(classification=CAMERA, open_ports=[], fingerprints=fingerprints)

    assert _finding(findings, "1024-bit TLS certificate key").severity == Severity.low


def test_rtsp_standard_ports_closed_is_positive():
    findings = evaluate_severity(classification=CAMERA, open_ports=[OpenPort(port=443)])

    assert _finding(findings, "RTSP standard ports closed").severity == Severity.positive


def test_onvif_upnp_mdns_closed_is_positive():
    fingerprints = HostFingerprintResult(
        target="192.168.1.38",
        udp_discovery=[
            UdpDiscoveryFingerprint(port=1900, state="closed", service="upnp"),
            UdpDiscoveryFingerprint(port=3702, state="closed", service="ws-discovery"),
            UdpDiscoveryFingerprint(port=5353, state="closed", service="zeroconf"),
        ],
    )

    findings = evaluate_severity(classification=CAMERA, open_ports=[], fingerprints=fingerprints)

    assert _finding(findings, "Local discovery protocols closed").severity == Severity.positive


def test_unknown_custom_service_without_leakage_is_info():
    findings = evaluate_severity(classification=UNKNOWN, open_ports=[OpenPort(port=9999)])

    assert (
        _finding(findings, "Unknown custom service with no data leakage").severity == Severity.info
    )


def test_cve_mapping_findings_are_carried_through():
    cve = Finding(
        title="Known vulnerable firmware",
        severity=Severity.high,
        evidence="Sanitized CVE mapping",
        explanation="A sanitized CVE mapping matched the component.",
    )

    findings = evaluate_severity(classification=UNKNOWN, open_ports=[], cve_findings=[cve])

    assert findings[-1] == cve
