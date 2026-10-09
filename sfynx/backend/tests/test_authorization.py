"""
Tests for the Authorization & Scope Gate.

This is the most critical security component —
it prevents SFYNX from scanning unauthorized targets.
"""

import pytest

from app.core.authorization import AuthorizationError, validate_scan_request
from app.schemas.scan import ScanRequest

# ─── Authorization flag tests ───────────────────────────────────────────


class TestAuthorizationFlag:
    """Tests for the explicit authorization requirement."""

    def test_missing_authorization_is_blocked(self):
        """Scan MUST be blocked when authorization is False."""
        request = ScanRequest(
            target="http://localhost:3000",
            authorization=False,
            scope=["localhost:3000"],
        )
        with pytest.raises(AuthorizationError, match="authorization is required"):
            validate_scan_request(request)

    def test_default_authorization_is_false(self):
        """Default authorization should be False (safe default)."""
        request = ScanRequest(
            target="http://localhost:3000",
            scope=["localhost:3000"],
        )
        assert request.authorization is False
        with pytest.raises(AuthorizationError):
            validate_scan_request(request)

    def test_explicit_authorization_passes(self):
        """Scan with explicit authorization=True should pass."""
        request = ScanRequest(
            target="http://localhost:3000",
            authorization=True,
            scope=["localhost:3000"],
        )
        # Should not raise
        validate_scan_request(request)


# ─── Scope validation tests ─────────────────────────────────────────────


class TestScopeValidation:
    """Tests for scope declaration and matching."""

    def test_empty_scope_is_blocked(self):
        """Scan MUST be blocked when scope is empty."""
        request = ScanRequest(
            target="http://localhost:3000",
            authorization=True,
            scope=[],
        )
        with pytest.raises(AuthorizationError, match="Scope must be declared"):
            validate_scan_request(request)

    def test_target_outside_scope_is_blocked(self):
        """Scan MUST be blocked when target is not in declared scope."""
        request = ScanRequest(
            target="http://localhost:3000",
            authorization=True,
            scope=["localhost:8080"],  # different port
        )
        with pytest.raises(AuthorizationError, match="not within the declared scope"):
            validate_scan_request(request)

    def test_target_within_scope_passes(self):
        """Scan should pass when target matches scope."""
        request = ScanRequest(
            target="http://localhost:3000",
            authorization=True,
            scope=["localhost:3000"],
        )
        validate_scan_request(request)

    def test_host_only_scope_matches_any_port(self):
        """Scope entry without port should match any port on that host."""
        request = ScanRequest(
            target="http://localhost:3000",
            authorization=True,
            scope=["localhost"],
        )
        validate_scan_request(request)

    def test_multiple_scope_entries(self):
        """Target matching any scope entry should pass."""
        request = ScanRequest(
            target="http://localhost:8080",
            authorization=True,
            scope=["localhost:3000", "localhost:8080"],
        )
        validate_scan_request(request)


# ─── Target allowlist tests ──────────────────────────────────────────────


class TestTargetAllowlist:
    """Tests for the safe target allowlist (MVP restriction)."""

    def test_localhost_is_allowed(self):
        request = ScanRequest(
            target="http://localhost:3000",
            authorization=True,
            scope=["localhost:3000"],
        )
        validate_scan_request(request)

    def test_loopback_127_is_allowed(self):
        request = ScanRequest(
            target="http://127.0.0.1:3000",
            authorization=True,
            scope=["127.0.0.1:3000"],
        )
        validate_scan_request(request)

    def test_private_192_168_is_allowed(self):
        request = ScanRequest(
            target="http://192.168.1.100:8080",
            authorization=True,
            scope=["192.168.1.100:8080"],
        )
        validate_scan_request(request)

    def test_private_10_x_is_allowed(self):
        request = ScanRequest(
            target="http://10.0.0.5:9090",
            authorization=True,
            scope=["10.0.0.5:9090"],
        )
        validate_scan_request(request)

    def test_public_domain_is_blocked(self):
        """Public/external domains MUST be blocked in MVP."""
        request = ScanRequest(
            target="http://example.com",
            authorization=True,
            scope=["example.com"],
        )
        with pytest.raises(AuthorizationError, match="not in the allowed targets"):
            validate_scan_request(request)

    def test_public_ip_is_blocked(self):
        """Public IP addresses MUST be blocked in MVP."""
        request = ScanRequest(
            target="http://93.184.216.34",
            authorization=True,
            scope=["93.184.216.34"],
        )
        with pytest.raises(AuthorizationError, match="not in the allowed targets"):
            validate_scan_request(request)

    def test_arbitrary_domain_is_blocked(self):
        """Arbitrary domains MUST be blocked."""
        request = ScanRequest(
            target="https://target-company.com",
            authorization=True,
            scope=["target-company.com"],
        )
        with pytest.raises(AuthorizationError):
            validate_scan_request(request)

    def test_domain_with_private_ip_prefix_is_blocked(self):
        """Domains mimicking private IP prefixes MUST be blocked (regression test)."""
        spoofed_domains = [
            "10.company.com",
            "192.168.attacker.com",
            "172.16.evil.org",
        ]
        for domain in spoofed_domains:
            request = ScanRequest(
                target=f"http://{domain}:8080",
                authorization=True,
                scope=[f"{domain}:8080"],
            )
            with pytest.raises(AuthorizationError, match="not in the allowed targets"):
                validate_scan_request(request)

    def test_unsupported_schemes_blocked(self):
        """Schemes other than http/https MUST be blocked."""
        for scheme in ["file:///etc/passwd", "ftp://localhost:21", "gopher://127.0.0.1:70"]:
            request = ScanRequest(
                target=scheme,
                authorization=True,
                scope=["localhost"],
            )
            with pytest.raises(AuthorizationError, match="Unsupported scheme"):
                validate_scan_request(request)

    def test_hyphen_argument_injection_blocked(self):
        """Targets starting with a hyphen MUST be blocked."""
        request = ScanRequest(
            target="-v",
            authorization=True,
            scope=["localhost"],
        )
        with pytest.raises(AuthorizationError, match="cannot start with a hyphen"):
            validate_scan_request(request)

    def test_control_characters_blocked(self):
        """Targets containing CRLF or null bytes MUST be blocked."""
        request = ScanRequest(
            target="http://localhost:3000\r\nHost: evil.com",
            authorization=True,
            scope=["localhost"],
        )
        with pytest.raises(AuthorizationError, match="control characters"):
            validate_scan_request(request)

    def test_loopback_variants_allowed(self):
        """Any 127.0.0.0/8 loopback address should be permitted."""
        request = ScanRequest(
            target="http://127.0.0.2:8080",
            authorization=True,
            scope=["127.0.0.2:8080"],
        )
        validate_scan_request(request)



# ─── Exclusion list tests ───────────────────────────────────────────────


class TestExclusionList:
    """Tests for the optional exclusion list."""

    def test_excluded_target_is_blocked(self):
        """Target in exclusion list MUST be blocked."""
        request = ScanRequest(
            target="http://localhost:3000",
            authorization=True,
            scope=["localhost"],
            excluded_scope=["localhost:3000"],
        )
        with pytest.raises(AuthorizationError, match="exclusion list"):
            validate_scan_request(request)

    def test_excluded_host_blocks_all_ports(self):
        """Exclusion entry without port should block all ports."""
        request = ScanRequest(
            target="http://localhost:3000",
            authorization=True,
            scope=["localhost"],
            excluded_scope=["localhost"],
        )
        with pytest.raises(AuthorizationError, match="exclusion list"):
            validate_scan_request(request)

    def test_non_excluded_target_passes(self):
        """Target not in exclusion list should pass."""
        request = ScanRequest(
            target="http://localhost:3000",
            authorization=True,
            scope=["localhost"],
            excluded_scope=["localhost:9090"],
        )
        validate_scan_request(request)


# ─── Edge cases ──────────────────────────────────────────────────────────


class TestEdgeCases:
    """Edge case and malformed input tests."""

    def test_empty_target_fails(self):
        """Empty target string should fail gracefully."""
        request = ScanRequest(
            target="",
            authorization=True,
            scope=["localhost"],
        )
        with pytest.raises(AuthorizationError):
            validate_scan_request(request)

    def test_target_with_path(self):
        """Target with path should still validate the host."""
        request = ScanRequest(
            target="http://localhost:3000/admin/login",
            authorization=True,
            scope=["localhost:3000"],
        )
        validate_scan_request(request)

    def test_target_without_scheme(self):
        """Target without http:// should still be parseable."""
        request = ScanRequest(
            target="localhost:3000",
            authorization=True,
            scope=["localhost:3000"],
        )
        validate_scan_request(request)

    def test_extra_allowed_hosts(self):
        """Extra allowed hosts parameter should extend the allowlist."""
        request = ScanRequest(
            target="http://custom-lab.local:8080",
            authorization=True,
            scope=["custom-lab.local:8080"],
        )
        # Should fail without extra hosts
        with pytest.raises(AuthorizationError):
            validate_scan_request(request)

        # Should pass with extra hosts
        validate_scan_request(
            request,
            extra_allowed_hosts=frozenset({"custom-lab.local"}),
        )
