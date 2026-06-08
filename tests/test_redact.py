from camaudit.redact import redact_text


def test_redacts_mac_to_oui():
    text = "MAC Address: 5C:E9:31:E0:56:D9 (TP-Link Systems)"
    assert "5C:E9:31:XX:XX:XX" in redact_text(text)
    assert "E0:56:D9" not in redact_text(text)


def test_preserves_private_but_redacts_public_ip_by_default():
    text = "Camera 192.168.1.38 and 10.0.0.4 and 172.16.2.3 public 8.8.8.8"
    out = redact_text(text)
    assert "192.168.1.38" in out
    assert "10.0.0.4" in out
    assert "172.16.2.3" in out
    assert "[REDACTED_PUBLIC_IP]" in out


def test_redacts_non_rfc1918_ips_by_default():
    text = "Loopback 127.0.0.1 documentation 203.0.113.10 border 172.32.0.1"
    out = redact_text(text)
    assert "127.0.0.1" not in out
    assert "203.0.113.10" not in out
    assert "172.32.0.1" not in out
    assert out.count("[REDACTED_PUBLIC_IP]") == 3


def test_strict_redacts_private_ip_too():
    out = redact_text("Camera 192.168.1.38 public 8.8.8.8", strict=True)
    assert "192.168.1.38" not in out
    assert "8.8.8.8" not in out
    assert out.count("[REDACTED_IP]") == 2


def test_redacts_email_and_tokens():
    out = redact_text("email jade@example.com UID=ABCDEF123456 api_key: abcdef123456")
    assert "[REDACTED_EMAIL]" in out
    assert out.count("[REDACTED_TOKEN_OR_SERIAL]") == 2


def test_redacts_serial_like_strings():
    out = redact_text("serial CAMERA-123456-ABC SN ABCDEF123456 model Tapo")
    assert "CAMERA-123456-ABC" not in out
    assert "ABCDEF123456" not in out
    assert out.count("[REDACTED_TOKEN_OR_SERIAL]") == 2


def test_redacts_camera_feed_filenames():
    out = redact_text("saved snapshot front_door.jpg and clip driveway-rtsp-feed.mp4")
    assert "front_door.jpg" not in out
    assert "driveway-rtsp-feed.mp4" not in out
    assert out.count("[REDACTED_MEDIA_FILE]") == 2


def test_invalid_ip_like_text_is_preserved():
    out = redact_text("bad parser value 999.999.999.999")
    assert "999.999.999.999" in out
