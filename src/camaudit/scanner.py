from __future__ import annotations

import re
import subprocess
from pathlib import Path

from pydantic import BaseModel, Field

from camaudit.auth_guard import require_authorized_private_target
from camaudit.models import OpenPort

DEFAULT_PORTS = (
    80,
    81,
    443,
    554,
    8000,
    8080,
    8081,
    8554,
    8899,
    5000,
    37777,
    34567,
    8443,
    8800,
    2020,
    10443,
    50443,
)
DEFAULT_SCAN_TIMEOUT_SECONDS = 75.0
DEFAULT_RAW_OUTPUT_PATH = Path("results/raw/nmap_port_scan.txt")
PORT_LINE_RE = re.compile(r"^(?P<port>\d+)/(?:tcp)\s+open\s+(?P<service>\S+)?")


class ScannerError(RuntimeError):
    """Raised when safe port scanning cannot complete."""


class PortScanResult(BaseModel):
    target: str
    open_ports: list[OpenPort] = Field(default_factory=list)
    raw_output_path: Path
    command: list[str]


def ports_to_argument(ports: tuple[int, ...] | list[int]) -> str:
    for port in ports:
        if port < 1 or port > 65535:
            raise ValueError(f"Invalid TCP port: {port}")
    return ",".join(str(port) for port in ports)


def parse_nmap_port_scan(output: str) -> list[OpenPort]:
    open_ports: list[OpenPort] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        match = PORT_LINE_RE.match(line)
        if not match:
            continue
        service = match.group("service") or None
        open_ports.append(OpenPort(port=int(match.group("port")), proto="tcp", service=service))
    return open_ports


def scan_host_ports(
    target: str,
    *,
    i_am_authorized: bool,
    ports: tuple[int, ...] | list[int] = DEFAULT_PORTS,
    output_path: Path = DEFAULT_RAW_OUTPUT_PATH,
    timeout: float = DEFAULT_SCAN_TIMEOUT_SECONDS,
    version_light: bool = False,
    allow_localhost: bool = False,
) -> PortScanResult:
    require_authorized_private_target(
        target,
        i_am_authorized=i_am_authorized,
        allow_localhost=allow_localhost,
    )

    command = [
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
        ports_to_argument(ports),
    ]
    if version_light:
        command.extend(["-sV", "--version-light"])
    command.append(target)

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise ScannerError("nmap was not found. Install nmap or use demo mode.") from exc
    except subprocess.TimeoutExpired as exc:
        raise ScannerError(f"nmap port scan timed out after {timeout:g} seconds.") from exc
    except OSError as exc:
        raise ScannerError(f"nmap port scan could not run: {exc}") from exc

    raw_output = f"{result.stdout}\n{result.stderr}".strip() + "\n"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(raw_output, encoding="utf-8")

    if result.returncode != 0:
        raise ScannerError(f"nmap port scan failed with exit code {result.returncode}.")

    return PortScanResult(
        target=target,
        open_ports=parse_nmap_port_scan(raw_output),
        raw_output_path=output_path,
        command=command,
    )
