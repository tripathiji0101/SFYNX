"""
SFYNX Common Finding Schema.

This is the single unified findings schema used by ALL security tools
and ALL pillars (Web/API/Cloud AND AI/RAG/Memory).

Design principles:
- One schema for all tools — no incompatible silos
- Core fields cover Web/API/Cloud scanning
- Extensible metadata dict for tool-specific data
- AI-specific fields (optional) for Pillar B in later phases
- Pydantic validation on all data
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class Severity(StrEnum):
    """Standardized severity levels across all tools."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class Confidence(StrEnum):
    """How confident the tool/triage is in this finding."""

    CONFIRMED = "confirmed"
    FIRM = "firm"
    TENTATIVE = "tentative"
    UNKNOWN = "unknown"


class Finding(BaseModel):
    """
    The unified finding model.

    Every security tool adapter MUST convert its output into this schema.
    This ensures consistent storage, deduplication, and LLM triage
    regardless of whether the finding came from Nuclei, ZAP, or Promptfoo.
    """

    # Identity
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: str = ""
    tool: str = ""  # e.g. "httpx", "nuclei", "promptfoo"

    # Target information
    target: str = ""
    endpoint: str = ""
    parameter: str = ""

    # Classification
    vulnerability_class: str = ""  # e.g. "XSS", "SQLi", "prompt-injection"
    title: str = ""
    description: str = ""
    severity: Severity = Severity.UNKNOWN
    confidence: Confidence = Confidence.UNKNOWN

    # Evidence
    evidence: str = ""
    request: str = ""
    response: str = ""

    # Remediation
    remediation: str = ""
    references: list[str] = Field(default_factory=list)

    # Timestamps
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    # Extensible metadata — tool-specific or phase-specific data
    # This is where AI-specific fields will live in later phases:
    #   probe_category, transcript, model_response, attack_type,
    #   agent_tool, rag_document, memory_event
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = {"ser_json_timedelta": "iso8601"}


class FindingSummary(BaseModel):
    """Compact representation for API list responses."""

    id: str
    tool: str
    target: str
    title: str
    severity: Severity
    confidence: Confidence
    endpoint: str = ""
    vulnerability_class: str = ""
    timestamp: datetime
