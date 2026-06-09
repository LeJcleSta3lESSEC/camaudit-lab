from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from camaudit.auth_guard import require_authorized_private_target

DEFAULT_FINGERPRINT_TIMEOUT_SECONDS = 10.0
DEFAULT_RAW_DIR = Path("results/raw")
TLS_PORTS = {443, 8443, 10443, 50443}
HTTP_PORTS = {80, 81, 443, 8000, 8080, 8081, 8443, 5000, 2020, 10443, 50443}
RTSP_PORTS = {554, 8554, 8800}
UDP_DISCOVERY_PORTS = (1900, 3702, 5353)


class FingerprintError(RuntimeError):
    """Raised when safe fingerprinting cannot complete."""


class HttpFingerprint(BaseModel):
    port: int
    method: Literal["HEAD", "GET"]
    status_code: int | None = None
    content_type: str | None = None
    header_hints: list[str] = Field(default_factory=list)
    raw_output_path: Path


class TlsCertificateFingerprint(BaseModel):
    port: int
    common_name: str | None = None
    organization: str | None = None
    public_key_bits: int | None = None
    not_valid_before: str | None = None
    not_valid_after: str | None = None
    raw_output_path: Path


class RtspFingerprint(BaseModel):
    port: int
    cseq_present: bool
    status_line: str | None = None
    raw_output_path: Path


class UdpDiscoveryFingerprint(BaseModel):
    port: int
    state: str
    service: str | None = None


class HostFingerprintResult(BaseModel):
    target: str
    http: list[HttpFingerprint] = Field(default_factory=list)
    tls: list[TlsCertificateFingerprint] = Field(default_factory=list)
    rtsp: list[RtspFingerprint] = Field(default_factory=list)
    udp_discovery: list[UdpDiscoveryFingerprint] = Field(default_factory=list)


def _run_command(command: list[str], *, timeout: float) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _write_raw(raw_dir: Path, name: str, output: str) -> Path:
    raw_dir.mkdir(parents=True, exist_ok=True)
    path = raw_dir / name
    path.write_text(output, encoding="utf-8")
    return path


def _combined_output(result: subprocess.CompletedProcess[str]) -> str:
    return f"{result.stdout}\n{result.stderr}".strip() + "\n"


def parse_http_headers(
    output: str,
    *,
    port: int,
    method: Literal["HEAD", "GET"],
    path: Path,
) -> HttpFingerprint:
    status_code: int | None = None
    content_type: str | None = None
    hints: list[str] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        status_match = re.match(r"^HTTP/\S+\s+(\d{3})\b", line)
        if status_match:
            status_code = int(status_match.group(1))
            continue
        if line.lower().startswith("content-type:"):
            content_type = line.split(":", 1)[1].strip()
        if line.lower().startswith(("server:", "www-authenticate:", "realm:", "x-")):
            hints.append(line)
    return HttpFingerprint(
        port=port,
        method=method,
        status_code=status_code,
        content_type=content_type,
        header_hints=hints,
        raw_output_path=path,
    )


def parse_tls_certificate(output: str, *, port: int, path: Path) -> TlsCertificateFingerprint:
    common_name: str | None = None
    organization: str | None = None
    key_bits: int | None = None
    not_before: str | None = None
    not_after: str | None = None

    subject_match = re.search(r"Subject: (?P<subject>.+)", output)
    if subject_match:
        subject = subject_match.group("subject")
        cn_match = re.search(r"commonName=([^,/]+)", subject)
        org_match = re.search(r"organizationName=([^,/]+)", subject)
        common_name = cn_match.group(1).strip() if cn_match else None
        organization = org_match.group(1).strip() if org_match else None

    bits_match = re.search(r"Public Key bits:\s*(\d+)", output)
    if bits_match:
        key_bits = int(bits_match.group(1))
    before_match = re.search(r"Not valid before:\s*(.+)", output)
    after_match = re.search(r"Not valid after:\s*(.+)", output)
    not_before = before_match.group(1).strip() if before_match else None
    not_after = after_match.group(1).strip() if after_match else None

    return TlsCertificateFingerprint(
        port=port,
        common_name=common_name,
        organization=organization,
        public_key_bits=key_bits,
        not_valid_before=not_before,
        not_valid_after=not_after,
        raw_output_path=path,
    )


def parse_rtsp_options(output: str, *, port: int, path: Path) -> RtspFingerprint:
    status_line = next((line.strip() for line in output.splitlines() if line.strip()), None)
    return RtspFingerprint(
        port=port,
        cseq_present=bool(re.search(r"^CSeq:", output, re.I | re.M)),
        status_line=status_line,
        raw_output_path=path,
    )


def parse_udp_discovery(output: str) -> list[UdpDiscoveryFingerprint]:
    results: list[UdpDiscoveryFingerprint] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        match = re.match(r"^(?P<port>\d+)/udp\s+(?P<state>\S+)\s*(?P<service>\S+)?", line)
        if not match:
            continue
        results.append(
            UdpDiscoveryFingerprint(
                port=int(match.group("port")),
                state=match.group("state"),
                service=match.group("service") or None,
            )
        )
    return results


def _http_url(target: str, port: int) -> str:
    scheme = "https" if port in TLS_PORTS else "http"
    return f"{scheme}://{target}:{port}/"


def fingerprint_host(
    target: str,
    *,
    ports: list[int],
    i_am_authorized: bool,
    raw_dir: Path = DEFAULT_RAW_DIR,
    timeout: float = DEFAULT_FINGERPRINT_TIMEOUT_SECONDS,
    allow_localhost: bool = False,
) -> HostFingerprintResult:
    require_authorized_private_target(
        target,
        i_am_authorized=i_am_authorized,
        allow_localhost=allow_localhost,
    )

    result = HostFingerprintResult(target=target)

    for port in ports:
        if port in TLS_PORTS:
            command = ["nmap", "-Pn", "-n", "--script", "ssl-cert", "-p", str(port), target]
            tls_result = _safe_run(command, timeout=timeout)
            path = _write_raw(raw_dir, f"tls_ssl_cert_{port}.txt", _combined_output(tls_result))
            result.tls.append(
                parse_tls_certificate(path.read_text(encoding="utf-8"), port=port, path=path)
            )

        if port in HTTP_PORTS:
            url = _http_url(target, port)
            head_command = [
                "curl",
                "--silent",
                "--show-error",
                "--max-time",
                str(timeout),
                "--head",
                url,
            ]
            head_result = _safe_run(head_command, timeout=timeout)
            head_path = _write_raw(raw_dir, f"http_head_{port}.txt", _combined_output(head_result))
            result.http.append(
                parse_http_headers(
                    head_path.read_text(encoding="utf-8"),
                    port=port,
                    method="HEAD",
                    path=head_path,
                )
            )

            get_command = [
                "curl",
                "--silent",
                "--show-error",
                "--max-time",
                str(timeout),
                "--dump-header",
                "-",
                "--output",
                os.devnull,
                url,
            ]
            get_result = _safe_run(get_command, timeout=timeout)
            get_path = _write_raw(
                raw_dir,
                f"http_get_headers_{port}.txt",
                _combined_output(get_result),
            )
            result.http.append(
                parse_http_headers(
                    get_path.read_text(encoding="utf-8"),
                    port=port,
                    method="GET",
                    path=get_path,
                )
            )

        if port in RTSP_PORTS:
            command = [
                "curl",
                "--silent",
                "--show-error",
                "--max-time",
                str(timeout),
                "--request",
                "OPTIONS",
                "--dump-header",
                "-",
                "--output",
                os.devnull,
                f"rtsp://{target}:{port}/",
            ]
            rtsp_result = _safe_run(command, timeout=timeout)
            path = _write_raw(raw_dir, f"rtsp_options_{port}.txt", _combined_output(rtsp_result))
            result.rtsp.append(
                parse_rtsp_options(path.read_text(encoding="utf-8"), port=port, path=path)
            )

    udp_command = [
        "nmap",
        "-Pn",
        "-n",
        "-sU",
        "--max-retries",
        "1",
        "--host-timeout",
        "30s",
        "-p",
        ",".join(str(port) for port in UDP_DISCOVERY_PORTS),
        target,
    ]
    udp_result = _safe_run(udp_command, timeout=timeout)
    udp_path = _write_raw(raw_dir, "udp_discovery.txt", _combined_output(udp_result))
    result.udp_discovery = parse_udp_discovery(udp_path.read_text(encoding="utf-8"))

    return result


def _safe_run(command: list[str], *, timeout: float) -> subprocess.CompletedProcess[str]:
    try:
        return _run_command(command, timeout=timeout)
    except FileNotFoundError as exc:
        raise FingerprintError(f"{command[0]} was not found. Install it or use demo mode.") from exc
    except subprocess.TimeoutExpired as exc:
        raise FingerprintError(f"{command[0]} fingerprint probe timed out.") from exc
    except OSError as exc:
        raise FingerprintError(f"{command[0]} fingerprint probe could not run: {exc}") from exc
