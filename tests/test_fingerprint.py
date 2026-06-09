import subprocess
from pathlib import Path

import pytest

from camaudit.auth_guard import AuthorizationError
from camaudit.fingerprint import (
    FingerprintError,
    fingerprint_host,
    parse_http_headers,
    parse_rtsp_options,
    parse_tls_certificate,
    parse_udp_discovery,
)

FIXTURES = Path(__file__).parent / "fixtures"
TEST_RAW_DIR = Path("results/raw")


def _raw_dir(name: str) -> Path:
    path = TEST_RAW_DIR / name
    path.mkdir(parents=True, exist_ok=True)
    for child in path.iterdir():
        child.unlink()
    return path


def test_parse_http_headers_fixture():
    output = (FIXTURES / "http_headers_sanitized.txt").read_text(encoding="utf-8")

    result = parse_http_headers(output, port=80, method="HEAD", path=Path("headers.txt"))

    assert result.status_code == 401
    assert result.content_type == "text/html"
    assert any("WWW-Authenticate" in hint for hint in result.header_hints)


def test_parse_tls_certificate_fixture():
    output = (FIXTURES / "nmap_ssl_cert_sanitized.txt").read_text(encoding="utf-8")

    result = parse_tls_certificate(output, port=443, path=Path("tls.txt"))

    assert result.common_name == "camera.local"
    assert result.organization == "TP-Link"
    assert result.public_key_bits == 1024
    assert result.not_valid_before == "2024-01-01T00:00:00"
    assert result.not_valid_after == "2034-01-01T00:00:00"


def test_parse_rtsp_options_fixture():
    output = (FIXTURES / "rtsp_options_sanitized.txt").read_text(encoding="utf-8")

    result = parse_rtsp_options(output, port=554, path=Path("rtsp.txt"))

    assert result.cseq_present
    assert result.status_line == "RTSP/1.0 200 OK"


def test_parse_udp_discovery_fixture():
    output = (FIXTURES / "udp_discovery_sanitized.txt").read_text(encoding="utf-8")

    result = parse_udp_discovery(output)

    assert [item.port for item in result] == [1900, 3702, 5353]
    assert result[0].state == "open|filtered"
    assert result[0].service == "upnp"


def test_fingerprint_host_requires_authorization_before_probing(monkeypatch):
    calls = []

    def fake_run_command(command, *, timeout):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr("camaudit.fingerprint._run_command", fake_run_command)

    with pytest.raises(AuthorizationError):
        fingerprint_host("192.168.1.38", ports=[80], i_am_authorized=False)

    assert calls == []


def test_fingerprint_host_runs_only_allowed_safe_probes(monkeypatch):
    tls_output = (FIXTURES / "nmap_ssl_cert_sanitized.txt").read_text(encoding="utf-8")
    http_output = (FIXTURES / "http_headers_sanitized.txt").read_text(encoding="utf-8")
    rtsp_output = (FIXTURES / "rtsp_options_sanitized.txt").read_text(encoding="utf-8")
    udp_output = (FIXTURES / "udp_discovery_sanitized.txt").read_text(encoding="utf-8")
    calls = []
    raw_dir = _raw_dir("test_fingerprint_success")

    def fake_run_command(command, *, timeout):
        calls.append(command)
        if command[0] == "nmap" and "ssl-cert" in command:
            return subprocess.CompletedProcess(command, 0, stdout=tls_output, stderr="")
        if command[0] == "curl" and command[-1].startswith("rtsp://"):
            return subprocess.CompletedProcess(command, 0, stdout=rtsp_output, stderr="")
        if command[0] == "nmap" and "-sU" in command:
            return subprocess.CompletedProcess(command, 0, stdout=udp_output, stderr="")
        return subprocess.CompletedProcess(command, 0, stdout=http_output, stderr="")

    monkeypatch.setattr("camaudit.fingerprint._run_command", fake_run_command)

    result = fingerprint_host(
        "192.168.1.38",
        ports=[443, 554],
        i_am_authorized=True,
        raw_dir=raw_dir,
        timeout=5,
    )

    assert len(result.tls) == 1
    assert len(result.http) == 2
    assert len(result.rtsp) == 1
    assert len(result.udp_discovery) == 3
    assert result.rtsp[0].cseq_present
    assert any(command[:5] == ["nmap", "-Pn", "-n", "--script", "ssl-cert"] for command in calls)
    assert any(command[0] == "curl" and "--head" in command for command in calls)
    assert any(command[0] == "curl" and "--dump-header" in command for command in calls)
    assert any(command[0] == "nmap" and "-sU" in command for command in calls)
    assert all("DESCRIBE" not in command for command in calls)
    assert all("SETUP" not in command for command in calls)
    assert all("PLAY" not in command for command in calls)
    assert all("--user" not in command for command in calls)
    assert (raw_dir / "http_get_headers_443.txt").exists()


def test_fingerprint_host_rejects_public_target_before_probing(monkeypatch):
    calls = []

    def fake_run_command(command, *, timeout):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr("camaudit.fingerprint._run_command", fake_run_command)

    with pytest.raises(AuthorizationError):
        fingerprint_host("8.8.8.8", ports=[443], i_am_authorized=True)

    assert calls == []


def test_fingerprint_host_reports_missing_tool(monkeypatch):
    def fake_run_command(command, *, timeout):
        raise FileNotFoundError

    monkeypatch.setattr("camaudit.fingerprint._run_command", fake_run_command)

    with pytest.raises(FingerprintError, match="was not found"):
        fingerprint_host("192.168.1.38", ports=[80], i_am_authorized=True)
