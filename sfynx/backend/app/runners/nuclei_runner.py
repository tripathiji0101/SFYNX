"""
SFYNX Nuclei Runner.

Nuclei is used for known vulnerability detection: CVEs, misconfigurations,
exposed panels, default credentials, and security template matching.

This runner invokes ProjectDiscovery's Nuclei CLI tool.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

from app.runners.base import BaseRunner
from app.schemas.finding import Confidence, Finding, Severity

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger("sfynx.runners.nuclei")

# Map Nuclei severity strings to our enum
_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "unknown": Severity.UNKNOWN,
}


class NucleiRunner(BaseRunner):
    """
    Adapter for ProjectDiscovery's Nuclei CLI tool.

    Nuclei scans targets using template-based detection for:
    - Known CVEs
    - Misconfigurations
    - Exposed admin panels
    - Default credentials
    - Information disclosure
    - Security headers
    - Technology detection

    Output is parsed into Finding objects with proper severity mapping.
    """

    tool_name = "nuclei"
    default_timeout = 300

    def _build_command(
        self, target: str, output_file: Path, **kwargs: Any
    ) -> list[str]:
        """
        Build Nuclei CLI command as an argument array.

        Uses JSON output and automatic template updates.
        """
        cmd = [
            self.binary_path,
            "-u", target,
            "-jsonl",
            "-o", str(output_file),
            "-silent",
            "-no-color",
            # Safety: rate limiting to avoid overwhelming the target
            "-rate-limit", "50",
            "-bulk-size", "10",
            "-concurrency", "10",
        ]

        # Allow restricting severity
        severity_filter = kwargs.get("severity")
        if severity_filter:
            cmd.extend(["-severity", severity_filter])

        # Allow restricting template tags
        tags = kwargs.get("tags")
        if tags:
            cmd.extend(["-tags", tags])

        return cmd

    def _parse_output(
        self, raw_output: str, target: str, scan_id: str
    ) -> list[Finding]:
        """
        Parse Nuclei JSONL output into Finding objects.

        Nuclei outputs one JSON object per line, each representing
        a matched template (i.e., a detected issue).
        """
        findings: list[Finding] = []

        for line in raw_output.strip().splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                logger.warning("nuclei: skipping non-JSON line: %s", line[:100])
                continue

            # Extract Nuclei's structured fields
            info = data.get("info", {})
            template_id = data.get("template-id", data.get("templateID", ""))
            matched_at = data.get("matched-at", data.get("matched", ""))
            matcher_name = data.get("matcher-name", data.get("matcher_name", ""))
            extracted_results = data.get("extracted-results", [])

            # Severity mapping
            nuclei_severity = info.get("severity", "unknown").lower()
            severity = _SEVERITY_MAP.get(nuclei_severity, Severity.UNKNOWN)

            # Classification
            classification = info.get("classification", {})
            cve_id = classification.get("cve-id", classification.get("cve_id"))
            cwe_id = classification.get("cwe-id", classification.get("cwe_id"))
            cvss_score = classification.get("cvss-score", classification.get("cvss_score"))

            # Build title
            title = info.get("name", template_id)
            if cve_id:
                if isinstance(cve_id, list):
                    cve_id = cve_id[0] if cve_id else ""
                title = f"{cve_id}: {title}"

            # Build description
            description = info.get("description", "")
            if matcher_name:
                description += f"\nMatcher: {matcher_name}"
            if extracted_results:
                description += f"\nExtracted: {', '.join(str(r) for r in extracted_results)}"

            # References
            references = info.get("reference", [])
            if isinstance(references, str):
                references = [references] if references else []

            # Tags → vulnerability class
            tags = info.get("tags", [])
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(",")]
            vuln_class = tags[0] if tags else "misconfiguration"

            # HTTP request/response if available
            request_data = data.get("request", "")
            response_data = data.get("response", "")
            curl_command = data.get("curl-command", "")

            finding = Finding(
                scan_id=scan_id,
                tool="nuclei",
                target=target,
                endpoint=matched_at,
                vulnerability_class=vuln_class,
                title=title,
                description=description,
                severity=severity,
                confidence=Confidence.CONFIRMED,
                evidence=json.dumps(
                    {
                        "template_id": template_id,
                        "matched_at": matched_at,
                        "matcher_name": matcher_name,
                        "extracted_results": extracted_results,
                    },
                    indent=2,
                ),
                request=request_data if isinstance(request_data, str) else json.dumps(request_data),
                response=(
                    response_data
                    if isinstance(response_data, str)
                    else json.dumps(response_data)
                ),
                remediation=info.get("remediation", ""),
                references=references,
                metadata={
                    "template_id": template_id,
                    "tags": tags,
                    "cve_id": cve_id,
                    "cwe_id": cwe_id,
                    "cvss_score": cvss_score,
                    "matcher_name": matcher_name,
                    "curl_command": curl_command,
                    "classification": classification,
                    "raw": data,
                },
            )
            findings.append(finding)

        logger.info(
            "nuclei: parsed %d findings for scan_id=%s",
            len(findings),
            scan_id,
        )
        return findings
