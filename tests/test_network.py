from pathlib import Path

from camaudit.network import (
    build_network_context,
    detect_network,
    parse_default_gateway,
    parse_ifconfig,
    parse_linux_ip_addr,
    parse_windows_ipconfig,
)

FIXTURES = Path(__file__).parent / "fixtures"


def read_fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_parse_windows_ipconfig_fixture():
    details = parse_windows_ipconfig(read_fixture("ipconfig_windows.txt"))

    assert details.local_ipv4 == "192.168.1.38"
    assert details.default_gateway == "192.168.1.1"
    assert details.subnet_cidr == "192.168.1.0/24"
    assert details.interface_name == "Ethernet adapter Ethernet"


def test_parse_linux_ip_addr_and_route_fixtures():
    details = parse_linux_ip_addr(read_fixture("ip_addr_linux.txt"))
    gateway = parse_default_gateway(read_fixture("ip_route_linux.txt"))

    assert details.local_ipv4 == "10.0.0.42"
    assert details.subnet_cidr == "10.0.0.0/24"
    assert details.interface_name == "wlan0"
    assert gateway == "10.0.0.1"


def test_parse_macos_ifconfig_and_route_fixtures():
    details = parse_ifconfig(read_fixture("ifconfig_macos.txt"))
    gateway = parse_default_gateway(read_fixture("route_macos.txt"))

    assert details.local_ipv4 == "172.20.10.4"
    assert details.subnet_cidr == "172.20.10.0/28"
    assert details.interface_name == "en0"
    assert gateway == "172.20.10.1"


def test_warns_when_target_network_does_not_match_active_network():
    details = parse_windows_ipconfig(read_fixture("ipconfig_windows.txt"))

    context = build_network_context(details, target="10.0.0.0/24")

    assert "Target network does not match the active local network." in context.warnings


def test_no_warning_when_target_overlaps_active_network():
    details = parse_windows_ipconfig(read_fixture("ipconfig_windows.txt"))

    context = build_network_context(details, target="192.168.1.0/24")

    assert context.warnings == []


def test_warns_for_likely_phone_hotspot_drift():
    details = parse_ifconfig(read_fixture("ifconfig_macos.txt"))

    context = build_network_context(details, target="192.168.1.0/24")

    assert "Target network does not match the active local network." in context.warnings
    assert any("phone hotspot drift" in warning for warning in context.warnings)


def test_detect_network_uses_safe_local_commands(monkeypatch):
    calls = []

    def fake_run_command(command, *, timeout):
        calls.append({"command": command, "timeout": timeout})
        if command == ["ip", "-4", "addr", "show"]:
            return read_fixture("ip_addr_linux.txt")
        if command == ["ip", "route", "show", "default"]:
            return read_fixture("ip_route_linux.txt")
        return ""

    monkeypatch.setattr("camaudit.network._run_command", fake_run_command)

    context = detect_network(target="10.0.0.0/24", timeout=1.25, os_name="Linux")

    assert context.local_ipv4 == "10.0.0.42"
    assert context.default_gateway == "10.0.0.1"
    assert context.subnet_cidr == "10.0.0.0/24"
    assert context.warnings == []
    assert calls == [
        {"command": ["ip", "-4", "addr", "show"], "timeout": 1.25},
        {"command": ["ip", "route", "show", "default"], "timeout": 1.25},
    ]


def test_detect_network_warns_when_detection_missing(monkeypatch):
    def fake_run_command(command, *, timeout):
        return ""

    monkeypatch.setattr("camaudit.network._run_command", fake_run_command)

    context = detect_network(target="192.168.1.0/24", os_name="Windows")

    assert "Could not detect an active non-loopback IPv4 address." in context.warnings
    assert "Could not detect active subnet/CIDR." in context.warnings
