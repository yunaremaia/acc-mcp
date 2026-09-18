"""Drift detection for MCP tool ACC declarations."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from acc_mcp.models import (
    DriftItem,
    DriftReport,
    MCPTool,
    ACCDeclaration,
)
from acc_mcp.parser import ACCParser


class DriftDetector:
    """Detect drift between MCP tool snapshots."""

    def __init__(self):
        self.parser = ACCParser()

    def snapshot(self, tools: list[MCPTool]) -> dict[str, dict]:
        """Create a snapshot of tool ACC declarations."""
        snapshot: dict[str, dict] = {}
        for tool in tools:
            decl = self.parser.parse_tool(tool)
            if decl is not None:
                snapshot[tool.name] = {
                    "scope": decl.scope,
                    "risk": decl.risk.level,
                    "readonly": decl.execution.readonly,
                    "approval_required": decl.approval.required,
                    "description": decl.model_dump_json(),
                }
        return snapshot

    def snapshot_raw(self, tools: list[dict]) -> dict[str, dict]:
        """Create a snapshot from raw MCP tool dicts."""
        parsed = self.parser.from_raw_tools(tools)
        return self.snapshot(parsed)

    def compute_fingerprint(self, tool: MCPTool) -> str:
        """Compute a fingerprint for a tool's ACC declaration."""
        decl = self.parser.parse_tool(tool)
        if decl is None:
            return ""
        canonical = decl.model_dump_json()
        return hashlib.sha256(canonical.encode()).hexdigest()[:16]

    def check(
        self,
        baseline_tools: list[MCPTool],
        current_tools: list[MCPTool],
    ) -> DriftReport:
        """Compare current tools against baseline and report drift."""
        baseline_map = {t.name: t for t in baseline_tools}
        current_map = {t.name: t for t in current_tools}

        baseline_decls = self.parser.parse_tools(baseline_tools)
        current_decls = self.parser.parse_tools(current_tools)

        breaking: list[DriftItem] = []
        degraded: list[DriftItem] = []
        compatible: list[DriftItem] = []

        # Check for removed tools
        for name in baseline_decls:
            if name not in current_decls:
                breaking.append(DriftItem(
                    tool_name=name,
                    change_type="removed",
                    field="declaration",
                    old_value=baseline_decls[name].model_dump_json(),
                    severity="breaking",
                ))

        # Check for added tools
        for name in current_decls:
            if name not in baseline_decls:
                compatible.append(DriftItem(
                    tool_name=name,
                    change_type="added",
                    field="declaration",
                    new_value=current_decls[name].model_dump_json(),
                    severity="compatible",
                ))

        # Check for modified declarations
        for name in baseline_decls:
            if name not in current_decls:
                continue
            base_decl = baseline_decls[name]
            curr_decl = current_decls[name]

            if base_decl.scope != curr_decl.scope:
                degraded.append(DriftItem(
                    tool_name=name,
                    change_type="modified",
                    field="scope",
                    old_value=base_decl.scope,
                    new_value=curr_decl.scope,
                    severity="degraded",
                ))

            if base_decl.risk.level != curr_decl.risk.level:
                base_risk = base_decl.risk.level.value
                curr_risk = curr_decl.risk.level.value
                # Risk escalation is breaking
                risk_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
                if risk_order.get(curr_risk, 0) > risk_order.get(base_risk, 0):
                    breaking.append(DriftItem(
                        tool_name=name,
                        change_type="modified",
                        field="risk",
                        old_value=base_risk,
                        new_value=curr_risk,
                        severity="breaking",
                    ))
                else:
                    compatible.append(DriftItem(
                        tool_name=name,
                        change_type="modified",
                        field="risk",
                        old_value=base_risk,
                        new_value=curr_risk,
                        severity="compatible",
                    ))

            if base_decl.approval.required and not curr_decl.approval.required:
                # Approval removed = breaking (security downgrade)
                breaking.append(DriftItem(
                    tool_name=name,
                    change_type="modified",
                    field="approval.required",
                    old_value=True,
                    new_value=False,
                    severity="breaking",
                ))
            elif not base_decl.approval.required and curr_decl.approval.required:
                compatible.append(DriftItem(
                    tool_name=name,
                    change_type="modified",
                    field="approval.required",
                    old_value=False,
                    new_value=True,
                    severity="compatible",
                ))

        has_drift = bool(breaking or degraded)
        return DriftReport(
            drifted=has_drift,
            breaking=breaking,
            degraded=degraded,
            compatible=compatible,
        )

    def check_from_snapshots(
        self,
        baseline_snapshot: dict[str, dict],
        current_snapshot: dict[str, dict],
    ) -> DriftReport:
        """Compare two snapshot dicts and report drift."""
        # Reconstruct minimal MCPTool objects from snapshot for the check
        baseline_tools = [
            MCPTool(
                name=name,
                description=data.get("description", ""),
                annotations={"x-agent-capability": json.loads(data["description"])} if data.get("description") else {},
            )
            for name, data in baseline_snapshot.items()
        ]
        current_tools = [
            MCPTool(
                name=name,
                description=data.get("description", ""),
                annotations={"x-agent-capability": json.loads(data["description"])} if data.get("description") else {},
            )
            for name, data in current_snapshot.items()
        ]
        return self.check(baseline_tools, current_tools)

    @staticmethod
    def save_snapshot(snapshot: dict[str, dict], path: str | Path) -> None:
        """Save a snapshot to a JSON file."""
        with open(path, "w") as f:
            json.dump(snapshot, f, indent=2)

    @staticmethod
    def load_snapshot(path: str | Path) -> dict[str, dict]:
        """Load a snapshot from a JSON file."""
        with open(path) as f:
            return json.load(f)
