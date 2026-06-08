from __future__ import annotations

import ipaddress

PRIVATE_NETWORKS: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)

LOCALHOST_NETWORKS: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.IPv4Network("127.0.0.0/8"),
)


class AuthorizationError(ValueError):
    """Raised when a scan target or authorization flag is unsafe."""


def _parse_target(target: str) -> ipaddress.IPv4Network:
    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError as exc:
        raise AuthorizationError(f"Invalid target: {target!r}") from exc
    if not isinstance(network, ipaddress.IPv4Network):
        raise AuthorizationError("Invalid target: CamAudit default scans accept IPv4 targets only.")
    return network


def is_private_target(target: str, *, allow_localhost: bool = False) -> bool:
    try:
        network = _parse_target(target)
    except AuthorizationError:
        return False
    allowed = PRIVATE_NETWORKS + (LOCALHOST_NETWORKS if allow_localhost else ())
    return any(network.subnet_of(parent) for parent in allowed)


def require_authorized_private_target(
    target: str,
    *,
    i_am_authorized: bool,
    allow_localhost: bool = False,
) -> None:
    if not i_am_authorized:
        raise AuthorizationError(
            "Refusing to run: pass --i-am-authorized for authorized testing only."
        )
    network = _parse_target(target)
    allowed = PRIVATE_NETWORKS + (LOCALHOST_NETWORKS if allow_localhost else ())
    if not any(network.subnet_of(parent) for parent in allowed):
        raise AuthorizationError(
            "Refusing to run: target must be an RFC1918 private range by default. "
            "Public-IP exposure checks require a separate explicit mode."
        )
