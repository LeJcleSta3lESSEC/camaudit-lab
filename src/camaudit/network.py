from __future__ import annotations

import ipaddress
import platform
import re
import subprocess

from pydantic import BaseModel, Field

DEFAULT_TIMEOUT_SECONDS = 3.0
HOTSPOT_NETWORK = ipaddress.IPv4Network("172.20.10.0/28")
RFC1918_192_NETWORK = ipaddress.IPv4Network("192.168.0.0/16")


class NetworkContext(BaseModel):
    local_ipv4: str | None = None
    default_gateway: str | None = None
    subnet_cidr: str | None = None
    interface_name: str | None = None
    warnings: list[str] = Field(default_factory=list)


class ParsedNetworkDetails(BaseModel):
    local_ipv4: str | None = None
    default_gateway: str | None = None
    subnet_cidr: str | None = None
    interface_name: str | None = None


def _run_command(command: list[str], *, timeout: float) -> str:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return ""
    if result.returncode != 0:
        return ""
    return f"{result.stdout}\n{result.stderr}"


def _cidr_from_ip_and_mask(ip: str, mask: str) -> str | None:
    try:
        return str(ipaddress.IPv4Network((ip, mask), strict=False))
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
        return None


def _cidr_from_ip_and_hex_mask(ip: str, hex_mask: str) -> str | None:
    try:
        mask_int = int(hex_mask, 16)
        mask = ipaddress.IPv4Address(mask_int)
    except ValueError:
        return None
    return _cidr_from_ip_and_mask(ip, str(mask))


def parse_windows_ipconfig(output: str) -> ParsedNetworkDetails:
    best = ParsedNetworkDetails()
    current_interface: str | None = None
    current_ip: str | None = None
    current_mask: str | None = None
    current_gateway: str | None = None

    def flush_current() -> None:
        nonlocal best, current_interface, current_ip, current_mask, current_gateway
        if best.local_ipv4 or not current_ip:
            return
        best = ParsedNetworkDetails(
            local_ipv4=current_ip,
            default_gateway=current_gateway,
            subnet_cidr=_cidr_from_ip_and_mask(current_ip, current_mask) if current_mask else None,
            interface_name=current_interface,
        )

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            flush_current()
            current_ip = None
            current_mask = None
            current_gateway = None
            continue
        if line.endswith(":") and not raw_line.startswith((" ", "\t")):
            flush_current()
            current_interface = line[:-1]
            current_ip = None
            current_mask = None
            current_gateway = None
            continue
        if "IPv4 Address" in line:
            current_ip = line.rsplit(":", 1)[-1].strip().removesuffix("(Preferred)").strip()
        elif "Subnet Mask" in line:
            current_mask = line.rsplit(":", 1)[-1].strip()
        elif "Default Gateway" in line:
            gateway = line.rsplit(":", 1)[-1].strip()
            if gateway:
                current_gateway = gateway
    flush_current()
    return best


def parse_linux_ip_addr(output: str) -> ParsedNetworkDetails:
    current_interface: str | None = None
    for raw_line in output.splitlines():
        interface_match = re.match(r"^\d+:\s+([^:@]+)", raw_line)
        if interface_match:
            current_interface = interface_match.group(1)
            continue
        inet_match = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+/\d+)\b", raw_line)
        if not inet_match:
            continue
        cidr = inet_match.group(1)
        ip = cidr.split("/", 1)[0]
        if ip.startswith("127."):
            continue
        subnet_cidr = str(ipaddress.IPv4Network(cidr, strict=False))
        return ParsedNetworkDetails(
            local_ipv4=ip,
            subnet_cidr=subnet_cidr,
            interface_name=current_interface,
        )
    return ParsedNetworkDetails()


def parse_ifconfig(output: str) -> ParsedNetworkDetails:
    current_interface: str | None = None
    for raw_line in output.splitlines():
        if raw_line and not raw_line.startswith(("\t", " ")):
            current_interface = raw_line.split(":", 1)[0]
            continue
        inet_match = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)\b", raw_line)
        if not inet_match:
            continue
        ip = inet_match.group(1)
        if ip.startswith("127."):
            continue
        hex_mask_match = re.search(r"\bnetmask\s+0x([0-9a-fA-F]{8})\b", raw_line)
        dotted_mask_match = re.search(r"\bnetmask\s+(\d+\.\d+\.\d+\.\d+)\b", raw_line)
        subnet_cidr = None
        if hex_mask_match:
            subnet_cidr = _cidr_from_ip_and_hex_mask(ip, hex_mask_match.group(1))
        elif dotted_mask_match:
            subnet_cidr = _cidr_from_ip_and_mask(ip, dotted_mask_match.group(1))
        return ParsedNetworkDetails(
            local_ipv4=ip,
            subnet_cidr=subnet_cidr,
            interface_name=current_interface,
        )
    return ParsedNetworkDetails()


def parse_default_gateway(output: str) -> str | None:
    linux_match = re.search(r"\bdefault\s+via\s+(\d+\.\d+\.\d+\.\d+)\b", output)
    if linux_match:
        return linux_match.group(1)
    mac_match = re.search(r"\bgateway:\s*(\d+\.\d+\.\d+\.\d+)\b", output, re.I)
    if mac_match:
        return mac_match.group(1)
    return None


def _target_network(target: str) -> ipaddress.IPv4Network | None:
    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return None
    if not isinstance(network, ipaddress.IPv4Network):
        return None
    return network


def build_network_context(
    details: ParsedNetworkDetails,
    *,
    target: str | None = None,
) -> NetworkContext:
    warnings: list[str] = []
    active_network = _target_network(details.subnet_cidr) if details.subnet_cidr else None
    target_network = _target_network(target) if target else None

    if target and target_network is None:
        warnings.append("Target network could not be parsed for active-network comparison.")
    if active_network and target_network and not active_network.overlaps(target_network):
        warnings.append("Target network does not match the active local network.")

    local_ip = ipaddress.IPv4Address(details.local_ipv4) if details.local_ipv4 else None
    if (
        local_ip
        and local_ip in HOTSPOT_NETWORK
        and target_network
        and target_network.subnet_of(RFC1918_192_NETWORK)
    ):
        warnings.append(
            "Likely phone hotspot drift: active IP is in 172.20.10.0/28 "
            "while target is in 192.168.0.0/16."
        )

    return NetworkContext(
        local_ipv4=details.local_ipv4,
        default_gateway=details.default_gateway,
        subnet_cidr=details.subnet_cidr,
        interface_name=details.interface_name,
        warnings=warnings,
    )


def detect_network(
    *,
    target: str | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    os_name: str | None = None,
) -> NetworkContext:
    detected_os = os_name or platform.system()
    details = ParsedNetworkDetails()

    if detected_os == "Windows":
        details = parse_windows_ipconfig(_run_command(["ipconfig"], timeout=timeout))
    elif detected_os == "Linux":
        details = parse_linux_ip_addr(_run_command(["ip", "-4", "addr", "show"], timeout=timeout))
        route_output = _run_command(["ip", "route", "show", "default"], timeout=timeout)
        gateway = parse_default_gateway(route_output)
        details.default_gateway = gateway
    elif detected_os == "Darwin":
        details = parse_ifconfig(_run_command(["ifconfig"], timeout=timeout))
        route_output = _run_command(["route", "-n", "get", "default"], timeout=timeout)
        gateway = parse_default_gateway(route_output)
        details.default_gateway = gateway

    context = build_network_context(details, target=target)
    if not context.local_ipv4:
        context.warnings.append("Could not detect an active non-loopback IPv4 address.")
    if not context.subnet_cidr:
        context.warnings.append("Could not detect active subnet/CIDR.")
    return context
