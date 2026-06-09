from typer.testing import CliRunner

from camaudit import cli
from camaudit.cli import app
from camaudit.models import DiscoveredHost

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


def test_scan_and_audit_accept_authorized_private_targets_as_placeholders():
    for command in ("scan-host", "audit"):
        result = runner.invoke(app, [command, "192.168.1.0/24", "--i-am-authorized"])

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
