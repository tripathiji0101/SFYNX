"""
Tests for the Scan API endpoints.

Tests the HTTP interface using FastAPI's test client.
"""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


# ─── Health and root ─────────────────────────────────────────────────────


class TestHealthEndpoints:
    def test_health_check(self):
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "sfynx"

    def test_root(self):
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["service"] == "SFYNX"
        assert "docs" in data


# ─── Scan creation ───────────────────────────────────────────────────────


class TestCreateScan:
    def test_create_scan_authorized(self):
        """Authorized scan should return 201 with queued status."""
        response = client.post(
            "/api/v1/scans",
            json={
                "target": "http://localhost:3000",
                "authorization": True,
                "scope": ["localhost:3000"],
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["status"] == "queued"
        assert "scan_id" in data

    def test_create_scan_unauthorized(self):
        """Unauthorized scan should return 201 but with BLOCKED status."""
        response = client.post(
            "/api/v1/scans",
            json={
                "target": "http://localhost:3000",
                "authorization": False,
                "scope": ["localhost:3000"],
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["status"] == "blocked"
        assert "BLOCKED" in data["message"]

    def test_create_scan_public_target_blocked(self):
        """Public target should be blocked even with authorization."""
        response = client.post(
            "/api/v1/scans",
            json={
                "target": "http://example.com",
                "authorization": True,
                "scope": ["example.com"],
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["status"] == "blocked"

    def test_create_scan_empty_scope_blocked(self):
        """Empty scope should be blocked."""
        response = client.post(
            "/api/v1/scans",
            json={
                "target": "http://localhost:3000",
                "authorization": True,
                "scope": [],
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["status"] == "blocked"

    def test_create_scan_missing_fields(self):
        """Missing required target field should return 422."""
        response = client.post(
            "/api/v1/scans",
            json={},
        )
        assert response.status_code == 422


# ─── Scan retrieval ──────────────────────────────────────────────────────


class TestGetScan:
    def test_get_nonexistent_scan(self):
        """Requesting a scan that doesn't exist should return 404."""
        response = client.get("/api/v1/scans/nonexistent-id")
        assert response.status_code == 404

    def test_get_scan_after_creation(self):
        """Created scan should be retrievable."""
        # Create scan
        create_response = client.post(
            "/api/v1/scans",
            json={
                "target": "http://localhost:3000",
                "authorization": True,
                "scope": ["localhost:3000"],
            },
        )
        scan_id = create_response.json()["scan_id"]

        # Retrieve scan
        get_response = client.get(f"/api/v1/scans/{scan_id}")
        assert get_response.status_code == 200
        data = get_response.json()
        assert data["scan_id"] == scan_id
        assert data["target"] == "http://localhost:3000"


# ─── Scan listing ────────────────────────────────────────────────────────


class TestListScans:
    def test_list_scans(self):
        """List endpoint should return an array."""
        response = client.get("/api/v1/scans")
        assert response.status_code == 200
        assert isinstance(response.json(), list)


# ─── Findings retrieval ─────────────────────────────────────────────────


class TestGetFindings:
    def test_get_findings_nonexistent_scan(self):
        """Findings for nonexistent scan should return 404."""
        response = client.get("/api/v1/scans/nonexistent-id/findings")
        assert response.status_code == 404

    def test_get_findings_after_creation(self):
        """Findings endpoint should return an array for a valid scan."""
        # Create scan
        create_response = client.post(
            "/api/v1/scans",
            json={
                "target": "http://localhost:3000",
                "authorization": True,
                "scope": ["localhost:3000"],
            },
        )
        scan_id = create_response.json()["scan_id"]

        # Get findings (may be empty if tools aren't installed)
        response = client.get(f"/api/v1/scans/{scan_id}/findings")
        assert response.status_code == 200
        assert isinstance(response.json(), list)


# ─── Root /scan compatibility ──────────────────────────────────────────


class TestRootScanRoute:
    def test_post_root_scan(self):
        """POST /scan should work identically to /api/v1/scans."""
        response = client.post(
            "/scan",
            json={
                "target": "http://127.0.0.1:3000",
                "authorization": True,
                "scope": ["127.0.0.1:3000"],
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["status"] == "queued"
        assert "scan_id" in data

        scan_id = data["scan_id"]
        get_res = client.get(f"/scan/{scan_id}")
        assert get_res.status_code == 200
        assert get_res.json()["scan_id"] == scan_id

