"""
SFYNX httpx Runner.

httpx is used for target discovery: probing URLs, detecting status codes,
technology fingerprinting, and identifying live endpoints.

This runner invokes the ProjectDiscovery httpx CLI tool
(not the Python httpx library).
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

from app.runners.base import BaseRunner
from app.schemas.finding import Confidence, Finding, Severity

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger("sfynx.runners.httpx")


class HttpxRunner(BaseRunner):
    """
    Adapter for ProjectDiscovery's httpx CLI tool.

    httpx probes targets and returns:
    - HTTP status codes
    - Content types
    - Web server info
    - Technology fingerprints
    - TLS/certificate info
    - CDN detection

    Output is parsed into Finding objects with severity=info
    since httpx performs discovery, not vulnerability detection.
    """

    tool_name = "httpx"
    default_timeout = 120

    def _build_command(
        self, target: str, output_file: Path, **kwargs: Any
    ) -> list[str]:
        """
        Build httpx CLI command as an argument array.

        Uses JSON output for reliable parsing.
        """
        cmd = [
            self.binary_path,
            "-u", target,
            "-json",
            "-o", str(output_file),
            "-silent",
            "-no-color",
            # Useful probes for discovery
            "-status-code",
            "-content-length",
            "-content-type",
            "-title",
            "-web-server",
            "-tech-detect",
            "-follow-redirects",
            "-timeout", "10",
        ]
        return cmd

    def _parse_output(
        self, raw_output: str, target: str, scan_id: str
    ) -> list[Finding]:
        """
        Parse httpx JSON lines output into Finding objects.

        httpx outputs one JSON object per line (JSONL format).
        Each line represents a probed endpoint.
        """
        findings: list[Finding] = []

        for line in raw_output.strip().splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                logger.warning("httpx: skipping non-JSON line: %s", line[:100])
                continue

            url = data.get("url", target)
            status_code = data.get("status_code", 0)
            title = data.get("title", "")
            web_server = data.get("webserver", "")
            content_type = data.get("content_type", "")
            content_length = data.get("content_length", 0)
            technologies = data.get("tech", [])
            host = data.get("host", "")

            # Build a descriptive title
            finding_title = f"Endpoint Discovered: {url}"
            if status_code:
                finding_title += f" [{status_code}]"

            # Build description with all discovered info
            desc_parts = [f"URL: {url}", f"Status: {status_code}"]
            if title:
                desc_parts.append(f"Title: {title}")
            if web_server:
                desc_parts.append(f"Server: {web_server}")
            if content_type:
                desc_parts.append(f"Content-Type: {content_type}")
            if technologies:
                desc_parts.append(f"Technologies: {', '.join(technologies)}")

            description = "\n".join(desc_parts)

            # Determine severity based on status code
            severity = Severity.INFO
            vuln_class = "discovery"

            if status_code in (401, 403):
                severity = Severity.LOW
                vuln_class = "access-control"
            elif status_code == 500:
                severity = Severity.MEDIUM
                vuln_class = "server-error"
            elif status_code in (301, 302, 307, 308):
                vuln_class = "redirect"

            finding = Finding(
                scan_id=scan_id,
                tool="httpx",
                target=target,
                endpoint=url,
                vulnerability_class=vuln_class,
                title=finding_title,
                description=description,
                severity=severity,
                confidence=Confidence.CONFIRMED,
                evidence=json.dumps(data, indent=2),
                metadata={
                    "status_code": status_code,
                    "title": title,
                    "web_server": web_server,
                    "content_type": content_type,
                    "content_length": content_length,
                    "technologies": technologies,
                    "host": host,
                    "raw": data,
                },
            )
            findings.append(finding)

        logger.info(
            "httpx: parsed %d findings for scan_id=%s",
            len(findings),
            scan_id,
        )
        return findings
