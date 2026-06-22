"""Pydantic models for SupplyScan."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, ConfigDict


class Severity(str, Enum):
    """Severity levels used throughout the scanner."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class EvidenceItem(BaseModel):
    """Structured evidence supporting a detector finding."""

    model_config = ConfigDict(frozen=True)

    label: str = Field(min_length=1)
    value: str = Field(min_length=1)


class DetectorResult(BaseModel):
    """Normalized output from a detector."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(min_length=1)
    severity: Severity
    findings: list[str] = Field(default_factory=list)
    evidence: list[EvidenceItem] = Field(default_factory=list)

    @property
    def has_findings(self) -> bool:
        """Return whether this detector reported a meaningful finding."""

        return bool(self.findings) and self.severity != Severity.INFO


class ThreatExplanation(BaseModel):
    """Human-readable explanation from the AI explainer."""

    model_config = ConfigDict(frozen=True)

    severity: Severity
    explanation: str = Field(min_length=1)
    recommended_action: str = Field(min_length=1)


class ScanTarget(BaseModel):
    """A resolved scan target."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(min_length=1)
    version: str | None = None
    source: str | None = None


class ScanReport(BaseModel):
    """Full scan result for a target package."""

    model_config = ConfigDict(frozen=True)

    target: ScanTarget
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    duration_ms: int = Field(ge=0)
    clean: bool
    overall_severity: Severity
    detector_results: list[DetectorResult] = Field(default_factory=list)
    explanation: ThreatExplanation | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
