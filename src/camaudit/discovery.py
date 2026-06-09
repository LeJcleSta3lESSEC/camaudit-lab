from __future__ import annotations

import re
import subprocess
from pathlib import Path

from camaudit.artifacts import create_run_id, discovery_output_path
from camaudit.auth_guard import require_authorized_private_target
from camaudit.models import DiscoveredHost

DEFAULT_DISCOVERY_TIMEOUT_SECONDS = 60.0

REPORT_RE = re.compile(r"^Nmap scan report for (?P<subject>.+)$")
IP_IN_PARENS_RE = re.compile(r"^(?P<hostname>.+)\s+\((?P<ip>\d+\.\d+\.\d+\.\d+)\)$")
LATENCY_RE = re.compile(r"Host is up(?: \((?P<seconds>[0-9.]+)s latency\))?\.")
MAC_RE = re.compile(
    r"^MAC Address: (?P<mac>(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})(?: \((?P<vendor>.+)\))?$"
)


class DiscoveryError(RuntimeError):
    """Raised when safe Nmap discovery cannot complete."""


def _mac_to_oui(mac: str) -> str:
    return ":".join(mac.upper().split(":")[:3])


def _host_from_subject(subject: str) -> tuple[str, str | None]:
    match = IP_IN_PARENS_RE.match(subject)
    if match:
        return match.group("ip"), match.group("hostname")
    return subject, None


def parse_nmap_discovery(output: str) -> list[DiscoveredHost]:
    hosts: list[DiscoveredHost] = []
    current: DiscoveredHost | None = None

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        report_match = REPORT_RE.match(line)
        if report_match:
            if current:
                hosts.append(current)
            ip, hostname = _host_from_subject(report_match.group("subject"))
            current = DiscoveredHost(ip=ip, hostname=hostname)
            continue

        if current is None:
            continue

        latency_match = LATENCY_RE.match(line)
        if latency_match and latency_match.group("seconds"):
            current.latency_ms = float(latency_match.group("seconds")) * 1000
            continue

        mac_match = MAC_RE.match(line)
        if mac_match:
            current.mac_oui = _mac_to_oui(mac_match.group("mac"))
            current.vendor = mac_match.group("vendor")

    if current:
        hosts.append(current)
    return hosts


def discover_hosts(
    target: str,
    *,
    i_am_authorized: bool,
    output_path: Path | None = None,
    run_id: str | None = None,
    timeout: float = DEFAULT_DISCOVERY_TIMEOUT_SECONDS,
    allow_localhost: bool = False,
) -> list[DiscoveredHost]:
    require_authorized_private_target(
        target,
        i_am_authorized=i_am_authorized,
        allow_localhost=allow_localhost,
    )
    if output_path is None:
        output_path = discovery_output_path(run_id or create_run_id())

    command = ["nmap", "-sn", target]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise DiscoveryError("nmap was not found. Install nmap or use demo mode.") from exc
    except subprocess.TimeoutExpired as exc:
        raise DiscoveryError(f"nmap discovery timed out after {timeout:g} seconds.") from exc
    except OSError as exc:
        raise DiscoveryError(f"nmap discovery could not run: {exc}") from exc

    raw_output = f"{result.stdout}\n{result.stderr}".strip() + "\n"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(raw_output, encoding="utf-8")

    if result.returncode != 0:
        raise DiscoveryError(f"nmap discovery failed with exit code {result.returncode}.")

    return parse_nmap_discovery(raw_output)
