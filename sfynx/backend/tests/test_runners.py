"""
Tests for the runner adapters.

Tests parsing logic using known sample outputs
(does NOT require the actual tools to be installed).
"""

import json

from app.runners.httpx_runner import HttpxRunner
from app.runners.nuclei_runner import NucleiRunner
from app.schemas.finding import Confidence, Severity

# ─── httpx parser tests ──────────────────────────────────────────────────


class TestHttpxParser:
    """Test httpx output parsing with sample data."""

    def setup_method(self):
        self.runner = HttpxRunner()

    def test_parse_single_endpoint(self):
        """Parse a single httpx JSON line."""
        raw = json.dumps(
            {
                "url": "http://localhost:3000",
                "status_code": 200,
                "title": "Test Application",
                "webserver": "nginx/1.25",
                "content_type": "text/html",
                "content_length": 1234,
                "tech": ["nginx", "Express"],
                "host": "localhost",
            }
        )
        findings = self.runner._parse_output(raw, "http://localhost:3000", "test-scan-1")

        assert len(findings) == 1
        f = findings[0]
        assert f.tool == "httpx"
        assert f.scan_id == "test-scan-1"
        assert f.severity == Severity.INFO
        assert f.confidence == Confidence.CONFIRMED
        assert "nginx" in f.description
        assert "Express" in f.description
        assert f.metadata["status_code"] == 200
        assert "nginx" in f.metadata["technologies"]

    def test_parse_401_endpoint(self):
        """401 status should map to LOW severity."""
        raw = json.dumps(
            {
                "url": "http://localhost:3000/admin",
                "status_code": 401,
                "host": "localhost",
            }
        )
        findings = self.runner._parse_output(raw, "http://localhost:3000", "test-scan-2")

        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW
        assert findings[0].vulnerability_class == "access-control"

    def test_parse_500_endpoint(self):
        """500 status should map to MEDIUM severity."""
        raw = json.dumps(
            {
                "url": "http://localhost:3000/error",
                "status_code": 500,
                "host": "localhost",
            }
        )
        findings = self.runner._parse_output(raw, "http://localhost:3000", "test-scan-3")

        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert findings[0].vulnerability_class == "server-error"

    def test_parse_multiple_lines(self):
        """Parse multiple httpx JSONL lines."""
        lines = [
            json.dumps(
                {"url": "http://localhost:3000", "status_code": 200, "host": "localhost"}
            ),
            json.dumps(
                {"url": "http://localhost:3000/api", "status_code": 200, "host": "localhost"}
            ),
            json.dumps(
                {"url": "http://localhost:3000/admin", "status_code": 403, "host": "localhost"}
            ),
        ]
        raw = "\n".join(lines)
        findings = self.runner._parse_output(raw, "http://localhost:3000", "test-scan-4")

        assert len(findings) == 3

    def test_parse_empty_output(self):
        """Empty output should return no findings."""
        findings = self.runner._parse_output("", "http://localhost:3000", "test-scan-5")
        assert len(findings) == 0

    def test_parse_malformed_json(self):
        """Malformed JSON lines should be skipped, not crash."""
        raw = "not-json\n" + json.dumps(
            {"url": "http://localhost:3000", "status_code": 200, "host": "localhost"}
        )
        findings = self.runner._parse_output(raw, "http://localhost:3000", "test-scan-6")
        assert len(findings) == 1  # Only the valid line


# ─── Nuclei parser tests ────────────────────────────────────────────────


class TestNucleiParser:
    """Test Nuclei output parsing with sample data."""

    def setup_method(self):
        self.runner = NucleiRunner()

    def test_parse_single_finding(self):
        """Parse a single Nuclei JSON finding."""
        raw = json.dumps(
            {
                "template-id": "cve-2021-44228",
                "info": {
                    "name": "Apache Log4j RCE",
                    "severity": "critical",
                    "description": "Remote code execution via Log4Shell",
                    "tags": "cve,rce,log4j",
                    "reference": [
                        "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
                    ],
                    "classification": {
                        "cve-id": "CVE-2021-44228",
                        "cwe-id": "CWE-502",
                        "cvss-score": 10.0,
                    },
                    "remediation": "Upgrade Log4j to 2.17.0 or later",
                },
                "matched-at": "http://localhost:3000/api",
                "matcher-name": "log4j-header",
                "request": "GET /api HTTP/1.1\nHost: localhost:3000",
                "response": "HTTP/1.1 200 OK",
            }
        )
        findings = self.runner._parse_output(raw, "http://localhost:3000", "test-scan-10")

        assert len(findings) == 1
        f = findings[0]
        assert f.tool == "nuclei"
        assert f.severity == Severity.CRITICAL
        assert f.confidence == Confidence.CONFIRMED
        assert "CVE-2021-44228" in f.title
        assert "Log4j" in f.title
        assert f.endpoint == "http://localhost:3000/api"
        assert f.metadata["cve_id"] == "CVE-2021-44228"
        assert f.metadata["cvss_score"] == 10.0
        assert f.remediation == "Upgrade Log4j to 2.17.0 or later"

    def test_parse_info_severity(self):
        """Info-level Nuclei findings should map correctly."""
        raw = json.dumps(
            {
                "template-id": "tech-detect",
                "info": {
                    "name": "Technology Detection",
                    "severity": "info",
                    "tags": "tech",
                },
                "matched-at": "http://localhost:3000",
            }
        )
        findings = self.runner._parse_output(raw, "http://localhost:3000", "test-scan-11")

        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO

    def test_parse_multiple_findings(self):
        """Parse multiple Nuclei JSONL findings."""
        entries = [
            {
                "template-id": "tech-1",
                "info": {"name": "Finding 1", "severity": "low", "tags": "misc"},
                "matched-at": "http://localhost:3000",
            },
            {
                "template-id": "tech-2",
                "info": {"name": "Finding 2", "severity": "high", "tags": "vuln"},
                "matched-at": "http://localhost:3000/admin",
            },
        ]
        raw = "\n".join(json.dumps(e) for e in entries)
        findings = self.runner._parse_output(raw, "http://localhost:3000", "test-scan-12")

        assert len(findings) == 2
        assert findings[0].severity == Severity.LOW
        assert findings[1].severity == Severity.HIGH

    def test_parse_tags_as_string(self):
        """Nuclei sometimes returns tags as comma-separated string."""
        raw = json.dumps(
            {
                "template-id": "xss-reflected",
                "info": {
                    "name": "Reflected XSS",
                    "severity": "medium",
                    "tags": "xss,reflected,owasp",
                },
                "matched-at": "http://localhost:3000/search",
            }
        )
        findings = self.runner._parse_output(raw, "http://localhost:3000", "test-scan-13")

        assert len(findings) == 1
        assert findings[0].vulnerability_class == "xss"
        assert "xss" in findings[0].metadata["tags"]

    def test_parse_empty_output(self):
        """Empty Nuclei output should return no findings."""
        findings = self.runner._parse_output("", "http://localhost:3000", "test-scan-14")
        assert len(findings) == 0

    def test_parse_malformed_json(self):
        """Malformed JSON should be skipped gracefully."""
        raw = "INVALID\n" + json.dumps(
            {
                "template-id": "valid",
                "info": {"name": "Valid Finding", "severity": "low", "tags": "misc"},
                "matched-at": "http://localhost:3000",
            }
        )
        findings = self.runner._parse_output(raw, "http://localhost:3000", "test-scan-15")
        assert len(findings) == 1


# ─── Finding schema tests ───────────────────────────────────────────────


class TestFindingSchema:
    """Test the common Finding schema."""

    def test_finding_has_uuid(self):
        """Each finding should get a unique ID by default."""
        from app.schemas.finding import Finding

        f1 = Finding()
        f2 = Finding()
        assert f1.id != f2.id
        assert len(f1.id) == 36  # UUID format

    def test_finding_serialization(self):
        """Finding should serialize to JSON cleanly."""
        from app.schemas.finding import Finding

        f = Finding(
            tool="nuclei",
            target="http://localhost:3000",
            title="Test Finding",
            severity=Severity.HIGH,
        )
        data = f.model_dump()
        assert data["tool"] == "nuclei"
        assert data["severity"] == "high"
        assert "id" in data
        assert "timestamp" in data

    def test_finding_metadata_extensible(self):
        """Metadata dict should accept arbitrary keys (for AI fields later)."""
        from app.schemas.finding import Finding

        f = Finding(
            tool="promptfoo",
            metadata={
                "probe_category": "prompt-injection",
                "transcript": "...",
                "model_response": "...",
                "attack_type": "direct",
            },
        )
        assert f.metadata["probe_category"] == "prompt-injection"
        assert f.metadata["attack_type"] == "direct"


# ─── Runner Execution and Subprocess Tests ───────────────────────────────


class TestRunnerExecution:
    """Test runner execution lifecycle, error handling, timeouts, and missing binaries."""

    async def test_missing_binary_returns_failed_task(self):
        """Runner with non-existent binary should return FAILED task with clear error."""
        from app.schemas.scan import TaskStatus

        runner = HttpxRunner(binary_path="nonexistent_binary_xyz_123")
        task, findings = await runner.run("http://127.0.0.1:3000", "test-missing-bin")

        assert task.status == TaskStatus.FAILED
        assert "not found on PATH" in task.error
        assert findings == []

    async def test_subprocess_timeout_handling(self, monkeypatch):
        """Runner must catch TimeoutError and mark task FAILED."""
        from unittest.mock import AsyncMock, MagicMock

        from app.schemas.scan import TaskStatus

        runner = HttpxRunner(timeout=1)

        # Mock binary find to succeed
        monkeypatch.setattr(runner, "_find_binary", lambda: "/mock/bin/httpx")

        # Mock asyncio.create_subprocess_exec and wait_for to simulate timeout
        mock_proc = AsyncMock()
        mock_proc.kill = MagicMock()  # kill() is synchronous in asyncio.subprocess.Process
        mock_proc.wait = AsyncMock()
        monkeypatch.setattr(
            "asyncio.create_subprocess_exec",
            AsyncMock(return_value=mock_proc),
        )

        async def mock_wait_for(fut, *args, **kwargs):
            if hasattr(fut, "close"):
                fut.close()
            raise TimeoutError()

        monkeypatch.setattr("asyncio.wait_for", mock_wait_for)

        task, findings = await runner.run("http://127.0.0.1:3000", "test-timeout")
        assert task.status == TaskStatus.FAILED
        assert "Timed out" in task.error
        assert task.exit_code == -1
        assert findings == []

    async def test_subprocess_nonzero_exit_code(self, monkeypatch):
        """Non-zero exit code should mark task FAILED with captured stderr."""
        from unittest.mock import AsyncMock

        from app.schemas.scan import TaskStatus

        runner = HttpxRunner()
        monkeypatch.setattr(runner, "_find_binary", lambda: "/mock/bin/httpx")

        mock_proc = AsyncMock()
        mock_proc.returncode = 2
        mock_proc.communicate = AsyncMock(
            return_value=(b"", b"Error: unexpected fatal failure")
        )
        monkeypatch.setattr(
            "asyncio.create_subprocess_exec",
            AsyncMock(return_value=mock_proc),
        )

        task, findings = await runner.run("http://127.0.0.1:3000", "test-nonzero")
        assert task.status == TaskStatus.FAILED
        assert task.exit_code == 2
        assert "Error: unexpected fatal failure" in task.error
        assert findings == []


# ─── Live Local Integration Test ─────────────────────────────────────────


class TestLiveScannerIntegration:
    """Integration test using an ephemeral local HTTP server and real httpx binary."""

    async def test_real_httpx_scan_on_local_server(self):
        """Run real httpx binary against an intentionally configured local server."""
        import http.server
        import shutil
        import socketserver
        import threading

        # Skip only if httpx binary is not installed on this host
        if not shutil.which("httpx"):
            return

        class LocalAppHandler(http.server.SimpleHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Server", "SfynxLocalApp/1.0")
                self.end_headers()
                self.wfile.write(b"<html><title>Sfynx</title><body>OK</body></html>")

            def log_message(self, *args, **kwargs):
                pass

        # Bind to port 0 (OS picks a free port)
        with socketserver.TCPServer(("127.0.0.1", 0), LocalAppHandler) as httpd:
            port = httpd.server_address[1]
            server_thread = threading.Thread(target=httpd.serve_forever)
            server_thread.daemon = True
            server_thread.start()

            runner = HttpxRunner()
            task, findings = await runner.run(f"http://127.0.0.1:{port}", "live-integration-scan")

            httpd.shutdown()

            from app.schemas.scan import TaskStatus

            assert task.status == TaskStatus.COMPLETED
            assert len(findings) == 1
            f = findings[0]
            assert f.tool == "httpx"
            assert f.metadata["status_code"] == 200
            assert "SfynxLocalApp" in f.metadata["web_server"]


