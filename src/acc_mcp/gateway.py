"""Gateway enforcement for MCP tool calls."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from acc_mcp.models import (
    GateDecisionResult,
    MCPTool,
    RiskLevel,
)
from acc_mcp.parser import ACCParser
from acc_mcp.risk import RiskEngine


class Policy:
    """Risk and approval policy configuration."""

    VALID_RISK_LEVELS = {level.value for level in RiskLevel}
    KNOWN_POLICY_KEYS = {
        "risk_overrides",
        "approval_required_scopes",
        "approval_required_tools",
        "block_tools",
        "block_critical",
    }

    def __init__(
        self,
        risk_overrides: dict[str, RiskLevel] | None = None,
        approval_scopes: list[str] | None = None,
        approval_tools: list[str] | None = None,
        block_tools: list[str] | None = None,
        block_critical: bool = True,
    ):
        self.risk_overrides = risk_overrides or {}
        self.approval_scopes = approval_scopes or []
        self.approval_tools = approval_tools or []
        self.block_tools = block_tools or []
        self.block_critical = block_critical

    @classmethod
    def from_yaml(cls, path: str | Path) -> "Policy":
        """Load policy from a YAML file."""
        with open(path) as f:
            data = yaml.safe_load(f) or {}

        if not isinstance(data, dict):
            raise ValueError("Policy YAML must contain a mapping at the top level")

        normalized_data: dict[str, Any] = {}
        for key, value in data.items():
            if not isinstance(key, str):
                raise ValueError(f"Policy keys must be strings, got {key!r}")
            normalized_key = key.replace("-", "_")
            if normalized_key == "blocked_tools":
                normalized_key = "block_tools"
            if normalized_key in normalized_data:
                raise ValueError(f"Duplicate policy key after normalization: '{key}'")
            normalized_data[normalized_key] = value

        unknown = set(normalized_data) - cls.KNOWN_POLICY_KEYS
        if unknown:
            valid_keys = ", ".join(sorted(cls.KNOWN_POLICY_KEYS))
            unknown_keys = ", ".join(sorted(unknown))
            raise ValueError(
                f"Unknown policy key(s): {unknown_keys}. Valid keys: {valid_keys}"
            )

        data = normalized_data
        risk_overrides = {}
        raw_risk_overrides = data.get("risk_overrides", {})
        if not isinstance(raw_risk_overrides, dict):
            raise ValueError("Policy key 'risk_overrides' must be a mapping")
        for scope, level in raw_risk_overrides.items():
            if not isinstance(scope, str):
                raise ValueError(f"Risk override scopes must be strings, got {scope!r}")
            if not isinstance(level, str) or level not in cls.VALID_RISK_LEVELS:
                valid_levels = ", ".join(sorted(cls.VALID_RISK_LEVELS))
                raise ValueError(
                    f"Invalid risk level {level!r} for scope '{scope}'. "
                    f"Valid levels: {valid_levels}"
                )
            risk_overrides[scope] = RiskLevel(level)

        list_values = {}
        for key in ("approval_required_scopes", "approval_required_tools", "block_tools"):
            value = data.get(key, [])
            if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
                raise ValueError(f"Policy key '{key}' must be a list of strings")
            list_values[key] = value

        raw_block_critical = data.get("block_critical", True)
        if not isinstance(raw_block_critical, bool):
            raise ValueError("Policy key 'block_critical' must be a boolean")

        return cls(
            risk_overrides=risk_overrides,
            approval_scopes=list_values["approval_required_scopes"],
            approval_tools=list_values["approval_required_tools"],
            block_tools=list_values["block_tools"],
            block_critical=raw_block_critical,
        )

    @classmethod
    def standard(cls) -> "Policy":
        """Standard policy: block critical, require approval for high."""
        return cls(block_critical=True)


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

        # A declaration that sets `enabled: false` is the capability author
        # withdrawing the capability (ACC v1 §4.2: "the operation MUST NOT be
        # exposed as an agent-callable capability"). Nothing overrides it: not
        # an operator allow-list, not an approval prompt.
        if declaration is not None and not declaration.enabled:
            return GateDecisionResult(
                tool_name=tool.name,
                allowed=False,
                risk_level=risk,
                reason=f"Tool '{tool.name}' is disabled by its ACC declaration (enabled=false)",
                requires_approval=False,
            )

        # Critical risk is denied, not merely gated on approval. An approval
        # prompt is only meaningful for a call a human could still wave through;
        # the README risk table and Policy.standard() both document `critical`
        # as BLOCK. Set `block_critical: false` to opt out.
        if risk == RiskLevel.CRITICAL and self.policy.block_critical:
            return GateDecisionResult(
                tool_name=tool.name,
                allowed=False,
                risk_level=risk,
                reason=f"Tool '{tool.name}' is blocked: critical risk",
                requires_approval=False,
            )

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
