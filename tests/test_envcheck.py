import subprocess

from typer.testing import CliRunner

from camaudit.cli import app
from camaudit.envcheck import check_environment, check_tool


def test_check_tool_uses_safe_subprocess_arguments(monkeypatch):
    calls = []

    def fake_run(command, *, capture_output, text, timeout, check):
        calls.append(
            {
                "command": command,
                "capture_output": capture_output,
                "text": text,
                "timeout": timeout,
                "check": check,
            }
        )
        return subprocess.CompletedProcess(command, 0, stdout="nmap 7.95\n", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = check_tool(["nmap", "--version"], timeout=1.5)

    assert result.available
    assert result.version == "nmap 7.95"
    assert calls == [
        {
            "command": ["nmap", "--version"],
            "capture_output": True,
            "text": True,
            "timeout": 1.5,
            "check": False,
        }
    ]


def test_check_tool_reports_missing_command(monkeypatch):
    def fake_run(command, *, capture_output, text, timeout, check):
        raise FileNotFoundError

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = check_tool(["tshark", "--version"])

    assert not result.available
    assert result.error == "not found"


def test_check_tool_reports_timeout(monkeypatch):
    def fake_run(command, *, capture_output, text, timeout, check):
        raise subprocess.TimeoutExpired(command, timeout)

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = check_tool(["vlc", "--version"], timeout=0.1)

    assert not result.available
    assert result.error == "timed out"


def test_check_tool_reports_nonzero_exit_with_output(monkeypatch):
    def fake_run(command, *, capture_output, text, timeout, check):
        return subprocess.CompletedProcess(command, 1, stdout="", stderr="bad option\n")

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = check_tool(["wireshark", "--version"])

    assert not result.available
    assert result.version == "bad option"
    assert result.error == "exit code 1"


def test_check_environment_checks_expected_tools(monkeypatch):
    commands = []

    def fake_run(command, *, capture_output, text, timeout, check):
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, stdout=f"{command[0]} version\n", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = check_environment(timeout=2.0)

    assert result.python_version
    assert [tool.name for tool in result.tools] == ["nmap", "curl", "tshark", "wireshark", "vlc"]
    assert commands == [
        ["nmap", "--version"],
        ["curl", "--version"],
        ["tshark", "--version"],
        ["wireshark", "--version"],
        ["vlc", "--version"],
    ]


def test_check_env_cli_renders_status(monkeypatch):
    def fake_run(command, *, capture_output, text, timeout, check):
        return subprocess.CompletedProcess(command, 0, stdout=f"{command[0]} version\n", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    runner = CliRunner()
    result = runner.invoke(app, ["check-env"])

    assert result.exit_code == 0
    assert "OS:" in result.output
    assert "Python:" in result.output
    assert "nmap" in result.output
    assert "available" in result.output
