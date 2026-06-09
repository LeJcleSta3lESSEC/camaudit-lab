from camaudit.classifier import classify_camera_candidate
from camaudit.models import DiscoveredHost, OpenPort


def test_camera_vendor_and_rtsp_ports_classify_as_candidate():
    host = DiscoveredHost(ip="192.168.1.38", vendor="TP-Link Systems", mac_oui="5C:E9:31")
    ports = [OpenPort(port=554, service="rtsp"), OpenPort(port=8800, service="unknown")]

    result = classify_camera_candidate(host, open_ports=ports, hostname="tapo-camera")

    assert result.candidate_type == "camera_candidate"
    assert result.candidate_score >= 70
    assert any("camera-family" in reason for reason in result.reasons)


def test_console_vendor_overrides_camera_port_overclaiming():
    host = DiscoveredHost(
        ip="192.168.1.87",
        vendor="Sony Interactive Entertainment",
        mac_oui="70:66:2A",
    )

    result = classify_camera_candidate(host, open_ports=[OpenPort(port=554, service="rtsp")])

    assert result.candidate_type == "console"
    assert result.candidate_score < 50
    assert any("game-console" in reason for reason in result.reasons)


def test_router_vendor_classifies_as_router():
    host = DiscoveredHost(ip="192.168.1.1", vendor="Netgear", hostname="router.lan")

    result = classify_camera_candidate(host, open_ports=[OpenPort(port=80), OpenPort(port=443)])

    assert result.candidate_type == "router"
    assert result.candidate_score < 50


def test_randomized_mac_is_uncertain_not_camera_by_default():
    host = DiscoveredHost(ip="192.168.1.55", mac_oui="6A:AA:BB")

    result = classify_camera_candidate(host, open_ports=[OpenPort(port=554), OpenPort(port=80)])

    assert result.candidate_type == "phone_or_randomized"
    assert result.candidate_score <= 45
    assert any("randomized" in reason for reason in result.reasons)


def test_unknown_host_stays_unknown_without_strong_evidence():
    host = DiscoveredHost(ip="192.168.1.60", vendor="Unknown")

    result = classify_camera_candidate(host, open_ports=[OpenPort(port=80)])

    assert result.candidate_type == "unknown"
    assert result.candidate_score < 50
