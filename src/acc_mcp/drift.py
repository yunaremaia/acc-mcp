"""Drift detection for MCP tool ACC declarations."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from acc_mcp.gateway import Gateway, Policy
from acc_mcp.models import (
    DriftItem,
    DriftReport,
    GateDecisionResult,
    MCPTool,
)
from acc_mcp.parser import ACCParser


def _enforcement_rank(decision: GateDecisionResult) -> int:
    """How hard the gateway enforces a call: refused > approval > allowed.

    Higher is stricter. `risk_level` and `reason` are deliberately excluded:
    both change with the risk ordinal while enforcement stays identical, so
    ranking on them would report drift where the gateway behaves exactly as it
    did at the baseline.
    """
    if not decision.allowed:
        return 2
    return 1 if decision.requires_approval else 0


class DriftDetector:
    """Detect drift between MCP tool snapshots."""

    def __init__(self, policy: Policy | None = None):
        self.parser = ACCParser()
        # The drift verdict is a claim about what the gateway will do, so it is
        # derived from the gateway itself rather than from the declarations
        # alone. Defaulting to the standard policy keeps a bare
        # `DriftDetector()` aligned with `Gateway()`.
        self.gateway = Gateway(policy=policy)

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
        """Compare current tools against baseline and report drift.

        Drift is computed over ACC declarations only: a tool without an
        ``x-agent-capability`` annotation is outside the contract and is not
        tracked. A tool that carried a declaration in the baseline and lost it
        in the current set is reported as a breaking removal.
        """
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
                # Escalation is breaking on the ordinal, unconditionally: the
                # baseline was approved at a lower declared level, and that
                # claim changed whatever the policy happens to do about it.
                #
                # De-escalation is NOT decided by the ordinal. Issue #53 filed
                # `critical` -> `low` under Policy.standard() as `compatible`
                # while the gateway went from refused to allowed, so
                # `check` printed "No drift detected." and exited 0 on a tool
                # that had just become callable. The ordinal is also the wrong
                # question in general, because policy sits between the two
                # levels: `risk_overrides` can pin a scope, `block_tools` can
                # refuse a tool whatever its level, and `block_critical:
                # false` turns the refusal into an approval gate. So the
                # de-escalation verdict comes from the gateway's own decision
                # on each declaration -- see `Gateway.decide`, the single
                # enforcement path `evaluate()` also uses.
                #
                # A de-escalation that leaves enforcement unchanged stays
                # compatible: `medium` -> `low` under the standard policy is a
                # changed declaration the gateway treats identically.
                risk_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
                escalated = risk_order.get(curr_risk, 0) > risk_order.get(base_risk, 0)
                loosened = _enforcement_rank(self.gateway.decide(name, curr_decl)) < (
                    _enforcement_rank(self.gateway.decide(name, base_decl))
                )
                severity = "breaking" if escalated or loosened else "compatible"
                (breaking if severity == "breaking" else compatible).append(DriftItem(
                    tool_name=name,
                    change_type="modified",
                    field="risk",
                    old_value=base_risk,
                    new_value=curr_risk,
                    severity=severity,
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

            # `execution.readonly` and `enabled` are security controls too:
            # both record a restriction the baseline was approved under.
            # snapshot() has always persisted `readonly`, so a tool approved as
            # read-only could become write-capable while every compared field
            # stayed identical and the gate reported clean. Same rule as
            # approval.required: losing the restriction is breaking, gaining it
            # is compatible.
            if base_decl.execution.readonly and not curr_decl.execution.readonly:
                breaking.append(DriftItem(
                    tool_name=name,
                    change_type="modified",
                    field="execution.readonly",
                    old_value=True,
                    new_value=False,
                    severity="breaking",
                ))
            elif not base_decl.execution.readonly and curr_decl.execution.readonly:
                compatible.append(DriftItem(
                    tool_name=name,
                    change_type="modified",
                    field="execution.readonly",
                    old_value=False,
                    new_value=True,
                    severity="compatible",
                ))

            if base_decl.enabled and not curr_decl.enabled:
                # The capability the baseline advertised is gone. The gateway
                # refuses such a call (enabled=false), so a consumer pinned to
                # the baseline sees a hard failure, not a softer one.
                breaking.append(DriftItem(
                    tool_name=name,
                    change_type="modified",
                    field="enabled",
                    old_value=True,
                    new_value=False,
                    severity="breaking",
                ))
            elif not base_decl.enabled and curr_decl.enabled:
                compatible.append(DriftItem(
                    tool_name=name,
                    change_type="modified",
                    field="enabled",
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
        # Reconstruct minimal MCPTool objects from snapshot for the check.
        # A snapshot written by snapshot() always carries a parseable
        # declaration in "description"; an entry without one yields an
        # undeclared tool that drift detection does not track.
        def to_tool(name: str, data: dict) -> MCPTool:
            description = data.get("description", "")
            annotations = (
                {"x-agent-capability": json.loads(description)} if description else {}
            )
            return MCPTool(
                name=name,
                description=description,
                annotations=annotations,
            )

        baseline_tools = [to_tool(name, data) for name, data in baseline_snapshot.items()]
        current_tools = [to_tool(name, data) for name, data in current_snapshot.items()]
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