import json
from pathlib import Path

from camaudit.report import render_markdown_report, write_markdown_report


def _session() -> dict:
    return {
        "scope": "192.168.1.0/24 authorized LAN",
        "authorized": True,
        "executive_summary": "Camera candidates were reviewed with safe local probes only.",
        "network_context": {"local_ipv4": "192.168.1.10", "subnet_cidr": "192.168.1.0/24"},
        "hosts": [
            {
                "ip": "192.168.1.38",
                "hostname": "camera-lab",
                "vendor": "TP-Link Systems",
                "mac_oui": "5C:E9:31",
                "notes": ["Sanitized fixture"],
            }
        ],
        "camera_candidates": [
            {
                "ip": "192.168.1.38",
                "candidate_type": "camera_candidate",
                "candidate_score": 85,
                "reasons": ["camera-family hint"],
            }
        ],
        "open_services": [{"ip": "192.168.1.38", "port": 443, "proto": "tcp", "service": "https"}],
        "fingerprinting_results": [
            {"ip": "192.168.1.38", "type": "http", "port": 443, "evidence": "HTTP 401"}
        ],
        "protocol_findings": [
            {
                "title": "RTSP standard ports closed",
                "severity": "Positive",
                "evidence": "554 closed",
            }
        ],
        "tls_findings": [
            {"title": "1024-bit TLS certificate key", "severity": "Low", "evidence": "1024-bit key"}
        ],
        "cve_mapping": [
            {
                "component": "camera firmware",
                "cve": "",
                "status": "not matched",
                "notes": "sanitized",
            }
        ],
        "findings": [
            {
                "title": "Local API reachable but auth-gated",
                "severity": "Info",
                "evidence": "TCP/443",
            }
        ],
        "remediation_checklist": ["Keep firmware updated."],
        "evidence_appendix": [
            {
                "item": "Nmap discovery",
                "source": "results/raw/nmap_discovery.txt",
                "notes": "redacted",
            }
        ],
        "redaction_log": ["Full MAC addresses are reduced to OUI prefixes."],
    }


def test_render_markdown_report_includes_required_sections():
    report = render_markdown_report(_session())

    for section in (
        "## 1. Scope and authorization",
        "## 2. Executive summary",
        "## 3. Network context",
        "## 4. Device inventory",
        "## 5. Camera candidates",
        "## 6. Open services",
        "## 7. Fingerprinting results",
        "## 8. RTSP/ONVIF/UPnP findings",
        "## 9. TLS findings",
        "## 10. CVE mapping",
        "## 11. Severity table",
        "## 12. Remediation checklist",
        "## 13. Evidence appendix",
        "## 14. Redaction log",
    ):
        assert section in report


def test_render_markdown_report_redacts_sensitive_values():
    session = _session()
    session["findings"][0]["evidence"] = "public 8.8.8.8 mac 5C:E9:31:E0:56:D9"

    report = render_markdown_report(session)

    assert "8.8.8.8" not in report
    assert "[REDACTED_PUBLIC_IP]" in report
    assert "5C:E9:31:XX:XX:XX" in report
    assert "E0:56:D9" not in report


def test_write_markdown_report_writes_file():
    output_path = Path("results/reports/test_camaudit_report.md")
    if output_path.exists():
        output_path.unlink()

    try:
        result = write_markdown_report(_session(), output_path)

        assert result == output_path
        assert output_path.exists()
        assert "# CamAudit Lab Report" in output_path.read_text(encoding="utf-8")
    finally:
        if output_path.exists():
            output_path.unlink()


def test_examples_sanitized_session_renders():
    session = json.loads(Path("examples/sanitized_session.json").read_text(encoding="utf-8"))

    report = render_markdown_report(session)

    assert "# CamAudit Lab Report" in report
    assert "192.168.1.0/24 authorized family-owned LAN" in report


def test_demo_report_counts_camera_candidates_from_demo_data():
    session = json.loads(Path("examples/sanitized_session.json").read_text(encoding="utf-8"))

    report = render_markdown_report(session, profile="internal")

    assert any(host.get("candidate_type") == "camera_candidate" for host in session["hosts"])
    assert "1 camera candidate(s)" in report
    assert "0 camera candidate(s)" not in report
    assert "| 192.168.1.38 | camera_candidate | 88 |" in report


def test_demo_report_lists_open_services_when_demo_hosts_have_open_ports():
    session = json.loads(Path("examples/sanitized_session.json").read_text(encoding="utf-8"))

    report = render_markdown_report(session, profile="internal")

    assert any(host.get("open_ports") for host in session["hosts"])
    assert "No open services recorded." not in report
    assert "| 192.168.1.38 | 443 | tcp | https-json-api |" in report
    assert "| 192.168.1.38 | 8443 | tcp | https-alt-json-api |" in report
    assert "| 192.168.1.38 | 8800 | tcp | rtsp-like-cseq |" in report


def test_demo_report_populates_fingerprint_protocol_and_tls_sections():
    session = json.loads(Path("examples/sanitized_session.json").read_text(encoding="utf-8"))

    report = render_markdown_report(session, profile="internal")

    assert session["findings"]
    assert "No fingerprinting results recorded." not in report
    assert "No protocol findings recorded." not in report
    assert "No TLS findings recorded." not in report
    assert "HTTPS JSON API returned 404/405-style behavior" in report
    assert "TPRI-DEVICE self-signed TLS certificate" in report
    assert "RSA 1024-bit public key" in report
    assert "Port 8800 CSeq / RTSP-like response" in report
    assert "RTSP standard ports closed" in report
    assert "UPnP/ONVIF/mDNS not observed" in report
    assert "Weak self-signed local TLS certificate" in report


def test_report_derives_candidates_and_services_from_hosts_when_sections_missing():
    session = {
        "scope": "192.168.1.0/24 authorized LAN",
        "authorized": True,
        "hosts": [
            {
                "ip": "192.168.1.38",
                "candidate_type": "camera_candidate",
                "candidate_score": 70,
                "reasons": ["demo host data"],
                "open_ports": [443, 8800],
            }
        ],
        "findings": [],
    }

    report = render_markdown_report(session)

    assert "1 camera candidate(s)" in report
    assert "No camera candidates recorded." not in report
    assert "No open services recorded." not in report
    assert "| 192.168.1.38 | 443 | tcp |  |" in report
    assert "| 192.168.1.38 | 8800 | tcp |  |" in report


def test_report_routes_protocol_and_tls_findings_when_sections_missing():
    session = {
        "scope": "192.168.1.0/24 authorized LAN",
        "authorized": True,
        "hosts": [],
        "findings": [
            {
                "title": "RTSP standard ports closed",
                "severity": "Positive",
                "evidence": "TCP/554 and TCP/8554 closed",
            },
            {
                "title": "Weak self-signed local TLS certificate",
                "severity": "Low",
                "evidence": "TPRI-DEVICE self-signed certificate with RSA 1024-bit public key.",
            },
        ],
    }

    report = render_markdown_report(session)

    assert "No protocol findings recorded." not in report
    assert "No TLS findings recorded." not in report
    assert "RTSP standard ports closed" in report
    assert "Weak self-signed local TLS certificate" in report


def test_public_profile_removes_private_ips_mac_ouis_gateway_subnet_and_raw_paths():
    session = json.loads(Path("examples/sanitized_session.json").read_text(encoding="utf-8"))

    report = render_markdown_report(session, profile="public")

    assert "192.168.1.38" not in report
    assert "192.168.1.87" not in report
    assert "192.168.1.0/24" not in report
    assert "192.168.1.1" not in report
    assert "5C:E9:31" not in report
    assert "70:66:2A" not in report
    assert "results/raw/" not in report
    assert "HOST-001" in report
    assert "HOST-002" in report
    assert "LAB_SUBNET/24" in report
    assert "LAB_GATEWAY" in report
    assert "MAC_OUI_REDACTED" in report
    assert "REDACTED_ARTIFACT_PATH" in report


def test_internal_profile_preserves_private_ips_for_internal_audit_use():
    session = json.loads(Path("examples/sanitized_session.json").read_text(encoding="utf-8"))

    report = render_markdown_report(session, profile="internal")

    assert "192.168.1.38" in report
    assert "192.168.1.87" in report
    assert "192.168.1.0/24" in report
    assert "5C:E9:31" in report
    assert "HOST-001" not in report
