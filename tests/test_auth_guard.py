import pytest

from camaudit.auth_guard import AuthorizationError, is_private_target, require_authorized_private_target


def test_private_targets_allowed():
    assert is_private_target("192.168.1.0/24")
    assert is_private_target("10.0.0.5")
    assert is_private_target("172.16.1.10")


def test_public_targets_rejected():
    assert not is_private_target("8.8.8.8")
    assert not is_private_target("1.1.1.0/24")


def test_missing_authorization_rejected():
    with pytest.raises(AuthorizationError):
        require_authorized_private_target("192.168.1.0/24", i_am_authorized=False)


def test_public_even_with_authorization_rejected_by_default():
    with pytest.raises(AuthorizationError):
        require_authorized_private_target("8.8.8.8", i_am_authorized=True)
