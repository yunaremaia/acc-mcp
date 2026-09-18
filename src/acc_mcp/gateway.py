"""Gateway enforcement for MCP tool calls."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from acc_mcp.models import (
    GateDecisionResult,
    MCPTool,
    RiskLevel,
    ACCDeclaration,
)
from acc_mcp.parser import ACCParser
from acc_mcp.risk import RiskEngine


class Policy:
    """Risk and approval policy configuration."""

    def __init__(
        self,
        risk_overrides: dict[str, RiskLevel] | None = None,
        approval_scopes: list[str] | None = None,
        approval_tools: list[str] | None = None,
        block_tools: list[str] | None = None,
    ):
        self.risk_overrides = risk_overrides or {}
        self.approval_scopes = approval_scopes or []
        self.approval_tools = approval_tools or []
        self.block_tools = block_tools or []

    @classmethod
    def from_yaml(cls, path: str | Path) -> "Policy":
        """Load policy from a YAML file."""
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        risk_overrides = {}
        for scope, level in data.get("risk_overrides", {}).items():
            risk_overrides[scope] = RiskLevel(level)
        return cls(
            risk_overrides=risk_overrides,
            approval_scopes=data.get("approval_required_scopes", []),
            approval_tools=data.get("approval_required_tools", []),
            block_tools=data.get("blocked_tools", []),
        )

    @classmethod
    def standard(cls) -> "Policy":
        """Standard policy: block critical, require approval for high."""
        return cls()


class Gateway:
    """Enforce ACC policies on MCP tool calls."""

    def __init__(self, policy: Policy | None = None):
        self.policy = policy or Policy.standard()
        self.parser = ACCParser()
        self.risk_engine = RiskEngine()

    def evaluate(
        self,
        tool: MCPTool,
        arguments: dict[str, Any] | None = None,
    ) -> GateDecisionResult:
        """Evaluate a tool call against policy.

        Returns a GateDecisionResult indicating whether the call is allowed.
        """
        arguments = arguments or {}

        # Parse ACC declaration
        declaration = self.parser.parse_tool(tool)

        # Classify risk
        risk = self.risk_engine.classify(tool, declaration)

        # Apply policy overrides
        scope = self.risk_engine.get_scope(declaration)
        if scope and scope in self.policy.risk_overrides:
            risk = self.policy.risk_overrides[scope]

        # Check blocked list
        if tool.name in self.policy.block_tools:
            return GateDecisionResult(
                tool_name=tool.name,
                allowed=False,
                risk_level=risk,
                reason=f"Tool '{tool.name}' is in the blocked list",
                requires_approval=False,
            )

        # Check approval requirements
        needs_approval = self.risk_engine.requires_approval(risk, declaration)
        if scope and scope in self.policy.approval_scopes:
            needs_approval = True
        if tool.name in self.policy.approval_tools:
            needs_approval = True

        approval_prompt = None
        if needs_approval and declaration and declaration.approval.prompt:
            # Template substitution
            try:
                approval_prompt = declaration.approval.prompt.format(**arguments)
            except (KeyError, IndexError):
                approval_prompt = declaration.approval.prompt
        elif needs_approval:
            approval_prompt = f"Approve call to '{tool.name}' (risk: {risk.value})?"

        return GateDecisionResult(
            tool_name=tool.name,
            allowed=True,
            risk_level=risk,
            reason="Approved" if not needs_approval else "Requires approval",
            requires_approval=needs_approval,
            approval_prompt=approval_prompt,
        )

    def evaluate_raw(
        self,
        tool_dict: dict[str, Any],
        arguments: dict[str, Any] | None = None,
    ) -> GateDecisionResult:
        """Evaluate a raw MCP tool dict against policy."""
        tool = MCPTool.model_validate(tool_dict)
        return self.evaluate(tool, arguments)
