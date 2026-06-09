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
