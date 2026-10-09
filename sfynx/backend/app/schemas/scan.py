"""
SFYNX Scan request/response schemas.

Defines the API contract for scan operations.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from app.schemas.finding import Finding


class ScanStatus(StrEnum):
    """Scan lifecycle states."""

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"
    CANCELLED = "cancelled"


class TaskStatus(StrEnum):
    """Individual tool task states."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class ScanRequest(BaseModel):
    """
    Incoming scan request from the user.

    Authorization and scope are MANDATORY.
    The Authorization & Scope Gate validates these before any scanning begins.
    """

    target: str
    authorization: bool = False
    scope: list[str] = Field(default_factory=list)
    excluded_scope: list[str] = Field(default_factory=list)
    testing_window: str | None = None  # Optional: e.g. "2024-01-01T00:00Z/2024-01-02T00:00Z"
    tools: list[str] | None = None  # Optional: restrict to specific tools


class ScanResponse(BaseModel):
    """Returned when a scan is created."""

    scan_id: str
    status: ScanStatus
    message: str = ""


class TaskResult(BaseModel):
    """Result of a single tool execution."""

    tool: str
    status: TaskStatus
    started_at: datetime | None = None
    finished_at: datetime | None = None
    exit_code: int | None = None
    error: str = ""
    finding_count: int = 0


class ScanResult(BaseModel):
    """Full scan result including all task results and findings."""

    scan_id: str
    target: str
    status: ScanStatus
    created_at: datetime
    finished_at: datetime | None = None
    tasks: list[TaskResult] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    finding_count: int = 0
    metadata: dict[str, Any] = Field(default_factory=dict)


class ScanSummary(BaseModel):
    """Compact scan info for list endpoints."""

    scan_id: str
    target: str
    status: ScanStatus
    created_at: datetime
    finished_at: datetime | None = None
    finding_count: int = 0
