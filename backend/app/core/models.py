"""
SmartGuard AI - Shared data models.

These mirror the entity definitions in the SRS and are used by both the
Module 1 upload endpoints and the Module 2 scanner.
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, computed_field


class SeverityLevel(str, Enum):
    """Severity bucket reported to the user.

    Slither's five impact levels are collapsed into the four levels the
    SmartGuard risk model uses, plus an informational bucket so that
    no detector output is silently dropped.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class AnalysisStatus(str, Enum):
    """Lifecycle of a single analysis job."""

    QUEUED = "queued"
    SCANNING = "scanning"
    COMPLETED = "completed"
    FAILED = "failed"


#: Mapping from a Slither impact string to a SmartGuard severity level.
SLITHER_IMPACT_TO_SEVERITY: dict[str, SeverityLevel] = {
    "High": SeverityLevel.CRITICAL,
    "Medium": SeverityLevel.HIGH,
    "Low": SeverityLevel.MEDIUM,
    "Informational": SeverityLevel.LOW,
    "Optimization": SeverityLevel.INFORMATIONAL,
}


class SlitherFinding(BaseModel):
    """A single normalised Slither detector hit."""

    finding_id: str
    detector: str
    impact: str
    severity: SeverityLevel
    confidence: str
    description: str
    contract: str
    function: Optional[str] = None
    line: Optional[int] = None
    source_mapping: Optional[str] = None
    first_markdown_element: Optional[str] = None

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "detector": self.detector,
            "impact": self.impact,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "description": self.description,
            "contract": self.contract,
            "function": self.function,
            "line": self.line,
            "source_mapping": self.source_mapping,
        }


class SeverityCount(BaseModel):
    """How many findings fall into each severity bucket."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    informational: int = 0

    @computed_field  # type: ignore[prop-decorator]
    @property
    def total(self) -> int:
        return (
            self.critical
            + self.high
            + self.medium
            + self.low
            + self.informational
        )


class UploadReceipt(BaseModel):
    """Returned immediately by Module 1 so the caller can start polling."""

    analysis_id: str
    contract_name: str
    source_type: str
    source_size_bytes: int
    status: AnalysisStatus = AnalysisStatus.QUEUED


class AnalysisResult(BaseModel):
    """Full output of a completed analysis."""

    analysis_id: str
    contract_name: str
    status: AnalysisStatus
    source_type: str
    source_size_bytes: int
    findings: list[SlitherFinding] = Field(default_factory=list)
    summary: SeverityCount = Field(default_factory=SeverityCount)
    detectors_available: int = 0
    detectors_ran: int = 0
    scan_duration_seconds: float = 0.0
    error: Optional[str] = None
    error_code: Optional[str] = None
