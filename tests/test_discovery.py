import subprocess
from pathlib import Path

import pytest

from camaudit.auth_guard import AuthorizationError
from camaudit.discovery import DiscoveryError, discover_hosts, parse_nmap_discovery

FIXTURES = Path(__file__).parent / "fixtures"
TEST_RAW_DIR = Path("results/raw")


def _output_path(name: str) -> Path:
    TEST_RAW_DIR.mkdir(parents=True, exist_ok=True)
    output_path = TEST_RAW_DIR / name
    if output_path.exists():
        output_path.unlink()
    return output_path


def test_parse_nmap_discovery_fixture():
    output = (FIXTURES / "nmap_discovery_sanitized.txt").read_text(encoding="utf-8")

    hosts = parse_nmap_discovery(output)

    assert len(hosts) == 3
    assert hosts[0].ip == "192.168.1.38"
    assert hosts[0].hostname is None
    assert hosts[0].mac_oui == "5C:E9:31"
    assert hosts[0].vendor == "TP-Link Systems"
    assert hosts[0].latency_ms == 65
    assert hosts[1].mac_oui == "70:66:2A"
    assert hosts[1].latency_ms == 120
    assert hosts[2].ip == "192.168.1.254"
    assert hosts[2].hostname == "dsldevice.lan"
    assert hosts[2].vendor == "Taicang T&W Electronics"
    assert hosts[2].latency_ms == 7


def test_discover_hosts_requires_authorization_before_running_nmap(monkeypatch):
    calls = []
    output_path = _output_path("test_unauthorized_nmap_discovery.txt")

    def fake_run(command, *, capture_output, text, timeout, check):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(AuthorizationError):
        discover_hosts(
            "192.168.1.0/24",
            i_am_authorized=False,
            output_path=output_path,
        )

    assert calls == []
    assert not output_path.exists()


def test_discover_hosts_rejects_public_targets_before_running_nmap(monkeypatch):
    calls = []
    output_path = _output_path("test_public_nmap_discovery.txt")

    def fake_run(command, *, capture_output, text, timeout, check):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(AuthorizationError):
        discover_hosts(
            "8.8.8.8",
            i_am_authorized=True,
            output_path=output_path,
        )

    assert calls == []
    assert not output_path.exists()


def test_discover_hosts_uses_safe_nmap_command_and_saves_raw_output(monkeypatch):
    fixture = (FIXTURES / "nmap_discovery_sanitized.txt").read_text(encoding="utf-8")
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
        return subprocess.CompletedProcess(command, 0, stdout=fixture, stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    output_path = _output_path("test_success_nmap_discovery.txt")

    try:
        hosts = discover_hosts(
            "192.168.1.0/24",
            i_am_authorized=True,
            output_path=output_path,
            timeout=12.5,
        )

        assert len(hosts) == 3
        assert output_path.read_text(encoding="utf-8").startswith("Nmap scan report")
        assert calls == [
            {
                "command": ["nmap", "-sn", "192.168.1.0/24"],
                "capture_output": True,
                "text": True,
                "timeout": 12.5,
                "check": False,
            }
        ]
    finally:
        if output_path.exists():
            output_path.unlink()


def test_discover_hosts_raises_on_nmap_failure_after_saving_output(monkeypatch):
    def fake_run(command, *, capture_output, text, timeout, check):
        return subprocess.CompletedProcess(command, 2, stdout="", stderr="nmap failed\n")

    monkeypatch.setattr(subprocess, "run", fake_run)
    output_path = _output_path("test_failed_nmap_discovery.txt")

    try:
        with pytest.raises(DiscoveryError, match="exit code 2"):
            discover_hosts(
                "192.168.1.0/24",
                i_am_authorized=True,
                output_path=output_path,
            )

        assert output_path.read_text(encoding="utf-8") == "nmap failed\n"
    finally:
        if output_path.exists():
            output_path.unlink()


def test_discover_hosts_reports_missing_nmap(monkeypatch):
    def fake_run(command, *, capture_output, text, timeout, check):
        raise FileNotFoundError

    monkeypatch.setattr(subprocess, "run", fake_run)
    output_path = _output_path("test_missing_nmap_discovery.txt")

    with pytest.raises(DiscoveryError, match="nmap was not found"):
        discover_hosts(
            "192.168.1.0/24",
            i_am_authorized=True,
            output_path=output_path,
        )

    assert not output_path.exists()
