import pytest

from camaudit.auth_guard import (
    AuthorizationError,
    is_private_target,
    require_authorized_private_target,
)


def test_private_targets_allowed():
    assert is_private_target("192.168.1.0/24")
    assert is_private_target("10.0.0.5")
    assert is_private_target("172.16.1.10")
    assert is_private_target("172.31.255.255")


def test_public_targets_rejected():
    assert not is_private_target("8.8.8.8")
    assert not is_private_target("1.1.1.0/24")
    assert not is_private_target("172.32.0.1")
    assert not is_private_target("192.168.0.0/15")


def test_invalid_targets_rejected():
    assert not is_private_target("not-an-ip")
    assert not is_private_target("192.168.1.999")

    with pytest.raises(AuthorizationError, match="Invalid target"):
        require_authorized_private_target("not-an-ip", i_am_authorized=True)


def test_ipv6_targets_rejected_for_now():
    assert not is_private_target("fe80::1")

    with pytest.raises(AuthorizationError, match="IPv4"):
        require_authorized_private_target("fe80::1", i_am_authorized=True)


def test_localhost_only_allowed_when_explicit():
    assert not is_private_target("127.0.0.1")
    assert is_private_target("127.0.0.1", allow_localhost=True)

    with pytest.raises(AuthorizationError):
        require_authorized_private_target("127.0.0.1", i_am_authorized=True)

    require_authorized_private_target(
        "127.0.0.1",
        i_am_authorized=True,
        allow_localhost=True,
    )


def test_missing_authorization_rejected():
    with pytest.raises(AuthorizationError):
        require_authorized_private_target("192.168.1.0/24", i_am_authorized=False)


def test_public_even_with_authorization_rejected_by_default():
    with pytest.raises(AuthorizationError):
        require_authorized_private_target("8.8.8.8", i_am_authorized=True)
