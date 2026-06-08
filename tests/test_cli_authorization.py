from typer.testing import CliRunner

from camaudit.cli import app

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


def test_scan_commands_accept_authorized_private_targets_as_placeholders():
    for command in ("discover", "scan-host", "audit"):
        result = runner.invoke(app, [command, "192.168.1.0/24", "--i-am-authorized"])

        assert result.exit_code == 0
        assert "placeholder" in result.output.lower()
