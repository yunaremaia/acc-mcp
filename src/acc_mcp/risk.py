"""Risk classification engine."""

from __future__ import annotations

from acc_mcp.models import ACCDeclaration, RiskLevel, MCPTool


class RiskEngine:
    """Classify risk levels for MCP tools based on ACC declarations."""

    def classify(self, tool: MCPTool, declaration: ACCDeclaration | None = None) -> RiskLevel:
        """Classify a tool's risk level.

        If the tool has an ACC declaration, use its risk config.
        Otherwise, apply heuristic classification.
        """
        if declaration is not None:
            return declaration.risk.level

        # Heuristic: classify based on tool name patterns
        name_lower = tool.name.lower()
        if any(kw in name_lower for kw in ("delete", "remove", "drop", "destroy", "kill")):
            return RiskLevel.HIGH
        if any(kw in name_lower for kw in ("write", "create", "update", "insert", "exec", "run")):
            return RiskLevel.MEDIUM
        if any(kw in name_lower for kw in ("read", "get", "list", "fetch", "search", "query")):
            return RiskLevel.LOW
        return RiskLevel.MEDIUM

    def requires_approval(self, risk_level: RiskLevel, declaration: ACCDeclaration | None = None) -> bool:
        """Determine if a tool requires human approval."""
        if declaration is not None and declaration.approval.required:
            return True
        return risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)

    def is_readonly(self, declaration: ACCDeclaration | None = None) -> bool:
        """Check if a tool is declared read-only."""
        if declaration is not None:
            return declaration.execution.readonly
        return False

    def get_scope(self, declaration: ACCDeclaration | None = None) -> str | None:
        """Get the scope of a tool."""
        if declaration is not None:
            return declaration.scope
        return None
