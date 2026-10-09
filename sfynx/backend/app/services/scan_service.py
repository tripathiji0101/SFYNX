"""
SFYNX Scan Service.

Orchestrates the scan lifecycle:
1. Validate authorization
2. Create scan record
3. Run security tools sequentially
4. Collect and normalize findings
5. Return structured results

In Phase 1 this uses in-memory storage.
Phase 4 will migrate to PostgreSQL + async job queue.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from app.core.authorization import AuthorizationError, validate_scan_request
from app.core.config import get_settings
from app.runners.httpx_runner import HttpxRunner
from app.runners.nuclei_runner import NucleiRunner
from app.schemas.finding import Finding
from app.schemas.scan import (
    ScanRequest,
    ScanResponse,
    ScanResult,
    ScanStatus,
    ScanSummary,
    TaskResult,
)

logger = logging.getLogger("sfynx.services.scan")


class ScanStore:
    """
    In-memory scan storage for Phase 1.

    This will be replaced by PostgreSQL in Phase 4.
    Thread-safe via asyncio (single event loop).
    """

    def __init__(self) -> None:
        self._scans: dict[str, ScanResult] = {}

    def create(self, scan_id: str, target: str) -> ScanResult:
        result = ScanResult(
            scan_id=scan_id,
            target=target,
            status=ScanStatus.QUEUED,
            created_at=datetime.now(UTC),
        )
        self._scans[scan_id] = result
        return result

    def get(self, scan_id: str) -> ScanResult | None:
        return self._scans.get(scan_id)

    def update(self, scan_id: str, **kwargs: Any) -> ScanResult | None:
        scan = self._scans.get(scan_id)
        if scan:
            for key, value in kwargs.items():
                if hasattr(scan, key):
                    setattr(scan, key, value)
        return scan

    def list_all(self) -> list[ScanSummary]:
        return [
            ScanSummary(
                scan_id=s.scan_id,
                target=s.target,
                status=s.status,
                created_at=s.created_at,
                finished_at=s.finished_at,
                finding_count=s.finding_count,
            )
            for s in self._scans.values()
        ]


# Singleton store — replaced by DB in Phase 4
_store = ScanStore()


def get_store() -> ScanStore:
    return _store


class ScanService:
    """
    Core scan orchestration service.

    Coordinates the Authorization Gate, tool execution, and result collection.
    """

    def __init__(self) -> None:
        self.store = get_store()
        settings = get_settings()

        # Initialize runners with configured timeouts and paths
        self.httpx_runner = HttpxRunner(
            binary_path=settings.sfynx_httpx_bin,
            timeout=settings.sfynx_httpx_timeout,
        )
        self.nuclei_runner = NucleiRunner(
            binary_path=settings.sfynx_nuclei_bin,
            timeout=settings.sfynx_nuclei_timeout,
        )
        self._background_tasks: set[asyncio.Task[None]] = set()

    async def create_scan(self, request: ScanRequest) -> ScanResponse:
        """
        Validate and create a new scan.

        Returns immediately with scan_id and QUEUED status.
        The actual scanning runs as a background task.
        """
        # Authorization Gate — this MUST pass before any scanning
        try:
            validate_scan_request(request)
        except AuthorizationError as e:
            scan_id = str(uuid.uuid4())
            self.store.create(scan_id, request.target)
            self.store.update(scan_id, status=ScanStatus.BLOCKED)
            logger.warning("Scan BLOCKED: scan_id=%s reason=%s", scan_id, e.reason)
            return ScanResponse(
                scan_id=scan_id,
                status=ScanStatus.BLOCKED,
                message=f"BLOCKED: {e.reason}",
            )

        scan_id = str(uuid.uuid4())
        self.store.create(scan_id, request.target)

        logger.info("Scan QUEUED: scan_id=%s target=%s", scan_id, request.target)

        # Launch scan execution as background task with strong reference to prevent GC
        task = asyncio.create_task(self._execute_scan(scan_id, request))
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

        return ScanResponse(
            scan_id=scan_id,
            status=ScanStatus.QUEUED,
            message="Scan queued successfully",
        )

    async def _execute_scan(self, scan_id: str, request: ScanRequest) -> None:
        """
        Execute all security tools for a scan.

        Runs httpx first (discovery), then Nuclei (vulnerability scanning).
        Each tool's findings are normalized to the common schema.
        """
        self.store.update(scan_id, status=ScanStatus.RUNNING)
        logger.info("Scan RUNNING: scan_id=%s", scan_id)

        all_findings: list[Finding] = []
        all_tasks: list[TaskResult] = []

        # Determine which tools to run
        tools_to_run = request.tools or ["httpx", "nuclei"]

        try:
            # Phase 1: Sequential execution
            # Phase 2+ will implement pipeline chaining where httpx
            # discovery feeds into Nuclei targeting

            if "httpx" in tools_to_run:
                httpx_task, httpx_findings = await self.httpx_runner.run(
                    target=request.target,
                    scan_id=scan_id,
                )
                all_tasks.append(httpx_task)
                all_findings.extend(httpx_findings)
                logger.info(
                    "httpx complete: scan_id=%s findings=%d",
                    scan_id,
                    len(httpx_findings),
                )

            if "nuclei" in tools_to_run:
                nuclei_task, nuclei_findings = await self.nuclei_runner.run(
                    target=request.target,
                    scan_id=scan_id,
                )
                all_tasks.append(nuclei_task)
                all_findings.extend(nuclei_findings)
                logger.info(
                    "nuclei complete: scan_id=%s findings=%d",
                    scan_id,
                    len(nuclei_findings),
                )

            # Update scan with results
            self.store.update(
                scan_id,
                status=ScanStatus.COMPLETED,
                finished_at=datetime.now(UTC),
                tasks=all_tasks,
                findings=all_findings,
                finding_count=len(all_findings),
            )
            logger.info(
                "Scan COMPLETED: scan_id=%s total_findings=%d",
                scan_id,
                len(all_findings),
            )

        except Exception as e:
            logger.error(
                "Scan FAILED: scan_id=%s error=%s",
                scan_id,
                e,
                exc_info=True,
            )
            self.store.update(
                scan_id,
                status=ScanStatus.FAILED,
                finished_at=datetime.now(UTC),
                tasks=all_tasks,
                findings=all_findings,
                finding_count=len(all_findings),
                metadata={"error": str(e)},
            )

    def get_scan(self, scan_id: str) -> ScanResult | None:
        """Get a scan by ID."""
        return self.store.get(scan_id)

    def list_scans(self) -> list[ScanSummary]:
        """List all scans."""
        return self.store.list_all()

    def get_findings(self, scan_id: str) -> list[Finding] | None:
        """Get findings for a specific scan."""
        scan = self.store.get(scan_id)
        if scan is None:
            return None
        return scan.findings
