"""Pydantic models for ACC v1 MCP binding."""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal
from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ApprovalConfig(BaseModel):
    required: bool = False
    prompt: str | None = None
    when: list[dict[str, Any]] = Field(default_factory=list)


class SubjectConfig(BaseModel):
    required: bool = False


class ExecutionConfig(BaseModel):
    readonly: bool = False
    idempotent: bool = False
    timeout_ms: int | None = None
    rate_limit: dict[str, Any] | None = None


class AuditConfig(BaseModel):
    sensitive: bool = False
    redaction: list[str] = Field(default_factory=list)


class GuidanceConfig(BaseModel):
    when_to_use: str | None = None
    returns: str | None = None
    examples: list[str] = Field(default_factory=list)


class ACCDeclaration(BaseModel):
    """ACC v1 declaration carried in MCP tool annotations."""

    version: Literal[1] = 1
    enabled: bool = True
    scope: str
    risk: RiskConfig = Field(default_factory=lambda: RiskConfig(level=RiskLevel.MEDIUM))
    subject: SubjectConfig = Field(default_factory=SubjectConfig)
    approval: ApprovalConfig = Field(default_factory=ApprovalConfig)
    execution: ExecutionConfig = Field(default_factory=ExecutionConfig)
    audit: AuditConfig = Field(default_factory=AuditConfig)
    guidance: GuidanceConfig = Field(default_factory=GuidanceConfig)


class RiskConfig(BaseModel):
    level: RiskLevel = RiskLevel.MEDIUM


class MCPTool(BaseModel):
    """An MCP tool definition with optional ACC annotations."""

    name: str
    description: str = ""
    inputSchema: dict[str, Any] = Field(default_factory=dict)
    annotations: dict[str, Any] = Field(default_factory=dict)


class GateDecisionResult(BaseModel):
    """Result of a gateway evaluation."""

    tool_name: str
    allowed: bool
    risk_level: RiskLevel
    reason: str
    requires_approval: bool
    approval_prompt: str | None = None


class DriftItem(BaseModel):
    """A single drift finding."""

    tool_name: str
    change_type: Literal["added", "removed", "modified"]
    field: str
    old_value: Any = None
    new_value: Any = None
    severity: Literal["breaking", "degraded", "compatible"]


class DriftReport(BaseModel):
    """Complete drift report between two snapshots."""

    drifted: bool
    breaking: list[DriftItem] = Field(default_factory=list)
    degraded: list[DriftItem] = Field(default_factory=list)
    compatible: list[DriftItem] = Field(default_factory=list)
