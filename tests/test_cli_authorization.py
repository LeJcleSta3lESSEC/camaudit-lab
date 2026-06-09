from typer.testing import CliRunner

from camaudit import cli
from camaudit.cli import app
from camaudit.models import DiscoveredHost
from camaudit.scanner import PortScanResult

runner = CliRunner()


def test_scan_commands_require_authorization_flag():
    for command in ("discover", "scan-host", "audit"):
        result = runner.invoke(app, [command, "192.168.1.0/24"])

        assert result.exit_code != 0
        assert "--i-am-authorized" in result.output


def test_scan_commands_reject_public_targets_even_with_authorization():
    for command in ("discover", "scan-host", "audit"):
        result = runner.invoke(app, [command, "8.8.8.8", "--i-am-authorized"])

        assert result.exit_code != 0
        assert "RFC1918 private range" in result.output


def test_audit_accepts_authorized_private_target_as_placeholder():
    result = runner.invoke(app, ["audit", "192.168.1.0/24", "--i-am-authorized"])

    assert result.exit_code == 0
    assert "placeholder" in result.output.lower()


def test_discover_accepts_authorized_private_target_with_mocked_nmap(monkeypatch):
    calls = []

    def fake_discover_hosts(target, *, i_am_authorized):
        calls.append({"target": target, "i_am_authorized": i_am_authorized})
        return [
            DiscoveredHost(
                ip="192.168.1.38",
                mac_oui="5C:E9:31",
                vendor="TP-Link Systems",
                latency_ms=65,
            )
        ]

    monkeypatch.setattr(cli, "discover_hosts", fake_discover_hosts)

    result = runner.invoke(app, ["discover", "192.168.1.0/24", "--i-am-authorized"])

    assert result.exit_code == 0
    assert "192.168.1.38" in result.output
    assert "5C:E9:31" in result.output
    assert calls == [{"target": "192.168.1.0/24", "i_am_authorized": True}]


def test_scan_host_accepts_authorized_private_target_with_mocked_nmap(monkeypatch):
    calls = []

    def fake_scan_host_ports(target, *, i_am_authorized):
        calls.append({"target": target, "i_am_authorized": i_am_authorized})
        return PortScanResult(
            target=target,
            open_ports=[],
            raw_output_path="results/raw/nmap_port_scan.txt",
            command=["nmap", "-Pn", "-n"],
        )

    monkeypatch.setattr(cli, "scan_host_ports", fake_scan_host_ports)

    result = runner.invoke(app, ["scan-host", "192.168.1.38", "--i-am-authorized"])

    assert result.exit_code == 0
    assert "Open ports" in result.output
    assert calls == [{"target": "192.168.1.38", "i_am_authorized": True}]


def test_demo_mode_uses_sanitized_data_without_scanning(monkeypatch):
    def fail_discover_hosts(*args, **kwargs):
        raise AssertionError("demo must not call discover_hosts")

    def fail_scan_host_ports(*args, **kwargs):
        raise AssertionError("demo must not call scan_host_ports")

    monkeypatch.setattr(cli, "discover_hosts", fail_discover_hosts)
    monkeypatch.setattr(cli, "scan_host_ports", fail_scan_host_ports)
    public_report_path = cli.DEMO_PUBLIC_REPORT_PATH
    internal_report_path = cli.DEMO_INTERNAL_REPORT_PATH
    if public_report_path.exists():
        public_report_path.unlink()
    if internal_report_path.exists():
        internal_report_path.unlink()

    try:
        result = runner.invoke(app, ["demo"])

        assert result.exit_code == 0
        assert "no network scan performed" in result.output
        assert "Discovery" in result.output
        assert "Port scan" in result.output
        assert "Fingerprint" in result.output
        assert public_report_path.exists()
        assert not internal_report_path.exists()
        report = public_report_path.read_text(encoding="utf-8")
        assert "# CamAudit Lab Report" in report
        assert "HOST-001" in report
        assert "192.168.1.38" not in report
        assert "No open services recorded." not in report
        assert "No protocol findings recorded." not in report
        assert "No TLS findings recorded." not in report
        assert "TPRI-DEVICE self-signed TLS certificate" in report
        assert "Port 8800 CSeq / RTSP-like response" in report
        assert "REDACTED_ARTIFACT_PATH" in report
    finally:
        if public_report_path.exists():
            public_report_path.unlink()
        if internal_report_path.exists():
            internal_report_path.unlink()
