from camaudit.redact import redact_text


def test_redacts_mac_to_oui():
    text = "MAC Address: 5C:E9:31:E0:56:D9 (TP-Link Systems)"
    assert "5C:E9:31:XX:XX:XX" in redact_text(text)
    assert "E0:56:D9" not in redact_text(text)


def test_preserves_private_but_redacts_public_ip_by_default():
    text = "Camera 192.168.1.38 public 8.8.8.8"
    out = redact_text(text)
    assert "192.168.1.38" in out
    assert "[REDACTED_PUBLIC_IP]" in out


def test_strict_redacts_private_ip_too():
    out = redact_text("Camera 192.168.1.38", strict=True)
    assert "[REDACTED_IP]" in out


def test_redacts_email_and_tokens():
    out = redact_text("email jade@example.com UID=ABCDEF123456")
    assert "[REDACTED_EMAIL]" in out
    assert "[REDACTED_TOKEN_OR_SERIAL]" in out
