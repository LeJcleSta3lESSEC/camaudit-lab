from __future__ import annotations

import ipaddress

PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

LOCALHOST_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
]


class AuthorizationError(ValueError):
    """Raised when a scan target or authorization flag is unsafe."""


def _parse_target(target: str) -> ipaddress.IPv4Network:
    try:
        return ipaddress.ip_network(target, strict=False)
    except ValueError as exc:
        raise AuthorizationError(f"Invalid target: {target!r}") from exc


def is_private_target(target: str, *, allow_localhost: bool = False) -> bool:
    network = _parse_target(target)
    allowed = PRIVATE_NETWORKS + (LOCALHOST_NETWORKS if allow_localhost else [])
    return any(network.subnet_of(parent) for parent in allowed)


def require_authorized_private_target(
    target: str,
    *,
    i_am_authorized: bool,
    allow_localhost: bool = False,
) -> None:
    if not i_am_authorized:
        raise AuthorizationError("Refusing to run: pass --i-am-authorized for authorized testing only.")
    if not is_private_target(target, allow_localhost=allow_localhost):
        raise AuthorizationError(
            "Refusing to run: target must be an RFC1918 private range by default. "
            "Public-IP exposure checks require a separate explicit mode."
        )
