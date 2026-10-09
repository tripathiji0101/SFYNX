"""
SFYNX Authorization & Scope Gate.

This module enforces the critical security requirement:
SFYNX must NEVER automatically perform active security testing
against arbitrary unauthorized targets.

Every scan request must pass through this gate before any
scanner is invoked.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    from app.schemas.scan import ScanRequest

logger = logging.getLogger("sfynx.authorization")

# Built-in safe hostnames for the MVP.
# Only localhost / loopback hostnames are permitted by default.
BUILTIN_SAFE_HOSTS: frozenset[str] = frozenset(
    {
        "localhost",
        "localhost.localdomain",
    }
)


class AuthorizationError(Exception):
    """Raised when a scan request fails authorization checks."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def _extract_host(url: str) -> str:
    """Extract the hostname from a URL, handling URLs without a scheme."""
    if "://" not in url:
        url = f"http://{url}"
    parsed = urlparse(url)
    return parsed.hostname or ""


def _is_safe_host(host: str, extra_allowed: frozenset[str] | None = None) -> bool:
    """
    Check if a host is in the safe allowlist.

    A host is considered safe if it is:
    - A built-in safe hostname (e.g., localhost)
    - A valid loopback, private RFC-1918, or link-local IP address
    - Explicitly listed in extra_allowed
    """
    if not host:
        return False

    host_clean = host.strip().lower()

    if extra_allowed and host_clean in extra_allowed:
        return True

    if host_clean in BUILTIN_SAFE_HOSTS:
        return True

    # Validate IP address rigorously to prevent domain-prefix bypasses (e.g. 10.evil.com)
    try:
        ip = ipaddress.ip_address(host_clean)
        return ip.is_loopback or ip.is_private or ip.is_unspecified
    except ValueError:
        # Not a valid IP address — must be an explicitly allowed hostname
        return False



def _is_in_scope(target_host: str, target_port: str | None, scope: list[str]) -> bool:
    """
    Check that the target falls within the declared scope.

    Scope entries can be:
    - "hostname"          → matches any port on that host
    - "hostname:port"     → matches only that host:port
    """
    for scope_entry in scope:
        if ":" in scope_entry:
            scope_host, scope_port = scope_entry.rsplit(":", 1)
        else:
            scope_host = scope_entry
            scope_port = None

        if scope_host != target_host:
            continue

        # If scope entry has no port constraint, any port matches
        if scope_port is None:
            return True

        # If target has no port, match scope entries without ports only
        if target_port is None:
            continue

        if scope_port == target_port:
            return True

    return False


def _is_excluded(target_host: str, target_port: str | None, excluded: list[str]) -> bool:
    """Check if the target falls within the exclusion list."""
    for entry in excluded:
        if ":" in entry:
            ex_host, ex_port = entry.rsplit(":", 1)
        else:
            ex_host = entry
            ex_port = None

        if ex_host != target_host:
            continue

        # Excluded entry without port → entire host is excluded
        if ex_port is None:
            return True

        if target_port and ex_port == target_port:
            return True

    return False


def validate_scan_request(
    request: ScanRequest,
    extra_allowed_hosts: frozenset[str] | None = None,
) -> None:
    """
    Validate a scan request against the Authorization & Scope Gate.

    Raises AuthorizationError if any check fails.
    The scan MUST NOT proceed if this function raises.

    Checks performed:
    1. Authorization flag must be explicitly True
    2. Scope must be non-empty
    3. Target host must be in the safe allowlist
    4. Target must be within declared scope
    5. Target must not be in the exclusion list
    """
    # 1. Explicit authorization required
    if not request.authorization:
        logger.warning(
            "Scan BLOCKED: authorization=False for target=%s",
            request.target,
        )
        raise AuthorizationError(
            "Explicit authorization is required. Set authorization=true to confirm "
            "you are authorized to test this target."
        )

    # 2. Scope must be declared
    if not request.scope:
        logger.warning(
            "Scan BLOCKED: empty scope for target=%s",
            request.target,
        )
        raise AuthorizationError(
            "Scope must be declared. Provide at least one scope entry "
            "(e.g., ['localhost:3000'])."
        )

    # 3. Extract and validate target host
    target_clean = request.target.strip()
    if not target_clean:
        raise AuthorizationError(f"Cannot parse hostname from target: {request.target}")

    if target_clean.startswith("-"):
        raise AuthorizationError("Target cannot start with a hyphen (flag injection protection).")

    if any(c in target_clean for c in ("\r", "\n", "\0")):
        raise AuthorizationError("Target contains invalid control characters.")

    if "://" in target_clean:
        scheme = urlparse(target_clean).scheme.lower()
        if scheme not in ("http", "https"):
            raise AuthorizationError(
                f"Unsupported scheme '{scheme}'. Only http and https targets are permitted."
            )

    target_host = _extract_host(target_clean)
    if not target_host:
        raise AuthorizationError(f"Cannot parse hostname from target: {request.target}")

    # Parse port from target URL
    parsed = urlparse(
        target_clean if "://" in target_clean else f"http://{target_clean}"
    )
    target_port = str(parsed.port) if parsed.port else None

    if not _is_safe_host(target_host, extra_allowed_hosts):
        logger.warning(
            "Scan BLOCKED: target host '%s' is not in the safe allowlist",
            target_host,
        )
        raise AuthorizationError(
            f"Target host '{target_host}' is not in the allowed targets list. "
            f"Only safe/local targets are permitted in the MVP: "
            f"localhost, 127.0.0.1, private networks."
        )

    # 4. Validate scope entries — each scope host must also be safe
    for scope_entry in request.scope:
        scope_host = scope_entry.split(":")[0]
        if not _is_safe_host(scope_host, extra_allowed_hosts):
            raise AuthorizationError(
                f"Scope entry '{scope_entry}' contains host '{scope_host}' "
                f"which is not in the allowed targets list."
            )

    # 5. Target must be within declared scope
    if not _is_in_scope(target_host, target_port, request.scope):
        raise AuthorizationError(
            f"Target '{request.target}' (host={target_host}, port={target_port}) "
            f"is not within the declared scope: {request.scope}"
        )

    # 6. Target must not be in exclusion list
    if request.excluded_scope and _is_excluded(
        target_host, target_port, request.excluded_scope
    ):
        raise AuthorizationError(
            f"Target '{request.target}' is in the exclusion list: {request.excluded_scope}"
        )

    logger.info(
        "Scan AUTHORIZED: target=%s, scope=%s",
        request.target,
        request.scope,
    )
