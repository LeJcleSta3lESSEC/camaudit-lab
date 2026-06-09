import subprocess
from pathlib import Path

import pytest

from camaudit.auth_guard import AuthorizationError
from camaudit.scanner import ScannerError, parse_nmap_port_scan, ports_to_argument, scan_host_ports

FIXTURES = Path(__file__).parent / "fixtures"
TEST_RAW_DIR = Path("results/raw")


def _output_path(name: str) -> Path:
    TEST_RAW_DIR.mkdir(parents=True, exist_ok=True)
    output_path = TEST_RAW_DIR / name
    if output_path.exists():
        output_path.unlink()
    return output_path


def test_parse_nmap_port_scan_fixture():
    output = (FIXTURES / "nmap_port_scan_sanitized.txt").read_text(encoding="utf-8")

    ports = parse_nmap_port_scan(output)

    assert [port.port for port in ports] == [80, 554, 8800]
    assert [port.service for port in ports] == ["http", "rtsp", "sunwebadmin"]


def test_ports_to_argument_validates_range():
    assert ports_to_argument([80, 554]) == "80,554"

    with pytest.raises(ValueError):
        ports_to_argument([0])


def test_scan_host_ports_requires_authorization_before_running_nmap(monkeypatch):
    calls = []
    output_path = _output_path("test_unauthorized_port_scan.txt")

    def fake_run(command, *, capture_output, text, timeout, check):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(AuthorizationError):
        scan_host_ports("192.168.1.38", i_am_authorized=False, output_path=output_path)

    assert calls == []
    assert not output_path.exists()


def test_scan_host_ports_uses_safe_nmap_template_and_saves_output(monkeypatch):
    fixture = (FIXTURES / "nmap_port_scan_sanitized.txt").read_text(encoding="utf-8")
    calls = []
    output_path = _output_path("test_success_port_scan.txt")

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
        return subprocess.CompletedProcess(command, 0, stdout=fixture, stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    try:
        result = scan_host_ports(
            "192.168.1.38",
            i_am_authorized=True,
            ports=[80, 554],
            output_path=output_path,
            timeout=20,
        )

        assert [port.port for port in result.open_ports] == [80, 554, 8800]
        assert output_path.read_text(encoding="utf-8").startswith("Starting Nmap")
        assert calls == [
            {
                "command": [
                    "nmap",
                    "-Pn",
                    "-n",
                    "-T3",
                    "--max-retries",
                    "2",
                    "--host-timeout",
                    "45s",
                    "--open",
                    "-p",
                    "80,554",
                    "192.168.1.38",
                ],
                "capture_output": True,
                "text": True,
                "timeout": 20,
                "check": False,
            }
        ]
    finally:
        if output_path.exists():
            output_path.unlink()


def test_scan_host_ports_version_light_adds_only_light_version_detection(monkeypatch):
    calls = []
    output_path = _output_path("test_version_light_port_scan.txt")

    def fake_run(command, *, capture_output, text, timeout, check):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    try:
        scan_host_ports(
            "192.168.1.38",
            i_am_authorized=True,
            ports=[80],
            output_path=output_path,
            version_light=True,
        )

        assert "-sV" in calls[0]
        assert "--version-light" in calls[0]
        assert "--version-all" not in calls[0]
        assert "-A" not in calls[0]
        assert "-O" not in calls[0]
    finally:
        if output_path.exists():
            output_path.unlink()


def test_scan_host_ports_reports_nmap_failure_after_saving_output(monkeypatch):
    output_path = _output_path("test_failed_port_scan.txt")

    def fake_run(command, *, capture_output, text, timeout, check):
        return subprocess.CompletedProcess(command, 1, stdout="", stderr="scan failed\n")

    monkeypatch.setattr(subprocess, "run", fake_run)

    try:
        with pytest.raises(ScannerError, match="exit code 1"):
            scan_host_ports("192.168.1.38", i_am_authorized=True, output_path=output_path)
        assert output_path.read_text(encoding="utf-8") == "scan failed\n"
    finally:
        if output_path.exists():
            output_path.unlink()
