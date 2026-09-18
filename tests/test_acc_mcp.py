"""Tests for acc-mcp."""

from __future__ import annotations

import json
import pytest

from acc_mcp.models import (
    ACCDeclaration,
    ApprovalConfig,
    DriftReport,
    MCPTool,
    RiskConfig,
    RiskLevel,
)
from acc_mcp.parser import ACCParser
from acc_mcp.gateway import Gateway, Policy
from acc_mcp.risk import RiskEngine
from acc_mcp.drift import DriftDetector


class TestACCParser:
    def test_parse_tool_with_acc(self):
        tool = MCPTool(
            name="delete_file",
            description="Delete a file",
            annotations={
                "x-agent-capability": {
                    "version": 1,
                    "enabled": True,
                    "scope": "fs.delete",
                    "risk": {"level": "high"},
                    "subject": {"required": True},
                    "approval": {"required": True, "prompt": "Delete {path}?"},
                    "execution": {"readonly": False},
                }
            },
        )
        parser = ACCParser()
        decl = parser.parse_tool(tool)
        assert decl is not None
        assert decl.scope == "fs.delete"
        assert decl.risk.level == RiskLevel.HIGH
        assert decl.approval.required is True

    def test_parse_tool_without_acc(self):
        tool = MCPTool(name="read_file", description="Read a file")
        parser = ACCParser()
        decl = parser.parse_tool(tool)
        assert decl is None

    def test_parse_tools_mixed(self):
        tools = [
            MCPTool(
                name="delete_file",
                annotations={"x-agent-capability": {"scope": "fs.delete", "risk": {"level": "high"}}},
            ),
            MCPTool(name="read_file"),
        ]
        parser = ACCParser()
        decls = parser.parse_tools(tools)
        assert "delete_file" in decls
        assert "read_file" not in decls

    def test_from_raw_tools(self):
        raw = [{"name": "test", "description": "Test tool"}]
        tools = ACCParser.from_raw_tools(raw)
        assert len(tools) == 1
        assert tools[0].name == "test"


class TestRiskEngine:
    def test_classify_with_declaration(self):
        engine = RiskEngine()
        tool = MCPTool(name="test")
        decl = ACCDeclaration(scope="test", risk=RiskConfig(level=RiskLevel.CRITICAL))
        assert engine.classify(tool, decl) == RiskLevel.CRITICAL

    def test_classify_heuristic_delete(self):
        engine = RiskEngine()
        tool = MCPTool(name="delete_file")
        assert engine.classify(tool) == RiskLevel.HIGH

    def test_classify_heuristic_read(self):
        engine = RiskEngine()
        tool = MCPTool(name="read_file")
        assert engine.classify(tool) == RiskLevel.LOW

    def test_requires_approval_high_risk(self):
        engine = RiskEngine()
        assert engine.requires_approval(RiskLevel.HIGH) is True

    def test_requires_approval_low_risk(self):
        engine = RiskEngine()
        assert engine.requires_approval(RiskLevel.LOW) is False

    def test_requires_approval_from_declaration(self):
        engine = RiskEngine()
        decl = ACCDeclaration(scope="test", approval=ApprovalConfig(required=True))
        assert engine.requires_approval(RiskLevel.LOW, decl) is True


class TestGateway:
    def test_policy_from_yaml_empty(self, tmp_path):
        path = tmp_path / "policy.yaml"
        path.write_text("")

        assert Policy.from_yaml(path).risk_overrides == {}

    def test_policy_from_yaml_valid_and_normalizes_blocked_tools(self, tmp_path):
        path = tmp_path / "policy.yaml"
        path.write_text(
            "risk-overrides:\n"
            "  fs.delete: critical\n"
            "blocked-tools:\n"
            "  - delete_file\n"
        )

        policy = Policy.from_yaml(path)

        assert policy.risk_overrides == {"fs.delete": RiskLevel.CRITICAL}
        assert policy.block_tools == ["delete_file"]

    def test_policy_from_yaml_rejects_unknown_keys(self, tmp_path):
        path = tmp_path / "policy.yaml"
        path.write_text("risk_overdes:\n  fs.delete: critical\n")

        with pytest.raises(ValueError, match="Unknown policy key"):
            Policy.from_yaml(path)

    def test_policy_from_yaml_rejects_invalid_risk_level(self, tmp_path):
        path = tmp_path / "policy.yaml"
        path.write_text("risk_overrides:\n  fs.delete: extreme\n")

        with pytest.raises(ValueError, match="Valid levels: critical, high, low, medium"):
            Policy.from_yaml(path)

    def test_evaluate_allowed(self):
        gateway = Gateway()
        tool = MCPTool(name="read_file", description="Read a file")
        result = gateway.evaluate(tool)
        assert result.allowed is True
        assert result.risk_level == RiskLevel.LOW

    def test_evaluate_requires_approval(self):
        gateway = Gateway()
        tool = MCPTool(
            name="delete_file",
            annotations={
                "x-agent-capability": {
                    "scope": "fs.delete",
                    "risk": {"level": "high"},
                    "approval": {"required": True, "prompt": "Delete {path}?"},
                }
            },
        )
        result = gateway.evaluate(tool, {"path": "/tmp/test.txt"})
        assert result.allowed is True
        assert result.requires_approval is True
        assert result.approval_prompt == "Delete /tmp/test.txt?"

    def test_evaluate_blocked(self):
        policy = Policy(block_tools=["delete_file"])
        gateway = Gateway(policy=policy)
        tool = MCPTool(name="delete_file")
        result = gateway.evaluate(tool)
        assert result.allowed is False

    def test_evaluate_risk_override(self):
        policy = Policy(risk_overrides={"fs.delete": RiskLevel.CRITICAL})
        gateway = Gateway(policy=policy)
        tool = MCPTool(
            name="delete_file",
            annotations={"x-agent-capability": {"scope": "fs.delete", "risk": {"level": "medium"}}},
        )
        result = gateway.evaluate(tool)
        assert result.risk_level == RiskLevel.CRITICAL


class TestDriftDetector:
    def test_no_drift(self):
        detector = DriftDetector()
        tools = [
            MCPTool(
                name="read_file",
                annotations={"x-agent-capability": {"scope": "fs.read", "risk": {"level": "low"}}},
            ),
        ]
        report = detector.check(tools, tools)
        assert report.drifted is False

    def test_detect_removed_tool(self):
        detector = DriftDetector()
        baseline = [
            MCPTool(
                name="read_file",
                annotations={"x-agent-capability": {"scope": "fs.read", "risk": {"level": "low"}}},
            ),
            MCPTool(
                name="delete_file",
                annotations={"x-agent-capability": {"scope": "fs.delete", "risk": {"level": "high"}}},
            ),
        ]
        current = [
            MCPTool(
                name="read_file",
                annotations={"x-agent-capability": {"scope": "fs.read", "risk": {"level": "low"}}},
            ),
        ]
        report = detector.check(baseline, current)
        assert report.drifted is True
        assert len(report.breaking) == 1
        assert report.breaking[0].tool_name == "delete_file"

    def test_detect_risk_escalation(self):
        detector = DriftDetector()
        baseline = [
            MCPTool(
                name="write_file",
                annotations={"x-agent-capability": {"scope": "fs.write", "risk": {"level": "medium"}}},
            ),
        ]
        current = [
            MCPTool(
                name="write_file",
                annotations={"x-agent-capability": {"scope": "fs.write", "risk": {"level": "critical"}}},
            ),
        ]
        report = detector.check(baseline, current)
        assert report.drifted is True
        assert any(i.severity == "breaking" for i in report.breaking)

    def test_detect_approval_removed(self):
        detector = DriftDetector()
        baseline = [
            MCPTool(
                name="delete_file",
                annotations={
                    "x-agent-capability": {
                        "scope": "fs.delete",
                        "risk": {"level": "high"},
                        "approval": {"required": True},
                    }
                },
            ),
        ]
        current = [
            MCPTool(
                name="delete_file",
                annotations={
                    "x-agent-capability": {
                        "scope": "fs.delete",
                        "risk": {"level": "high"},
                        "approval": {"required": False},
                    }
                },
            ),
        ]
        report = detector.check(baseline, current)
        assert report.drifted is True
        assert any(i.field == "approval.required" for i in report.breaking)

    def test_snapshot_roundtrip(self, tmp_path):
        detector = DriftDetector()
        tools = [
            MCPTool(
                name="read_file",
                annotations={"x-agent-capability": {"scope": "fs.read", "risk": {"level": "low"}}},
            ),
        ]
        snapshot = detector.snapshot(tools)
        path = tmp_path / "snapshot.json"
        detector.save_snapshot(snapshot, path)
        loaded = detector.load_snapshot(path)
        assert loaded == snapshot


class TestCLI:
    def test_validate_policy(self, tmp_path, capsys):
        path = tmp_path / "policy.yaml"
        path.write_text("block_tools:\n  - delete_file\n")

        from acc_mcp.cli import main
        import sys
        old_argv = sys.argv
        try:
            sys.argv = ["acc-mcp", "--validate-policy", str(path)]
            ret = main()
        finally:
            sys.argv = old_argv

        assert ret == 0
        assert "Policy is valid" in capsys.readouterr().out

    def test_inspect(self, tmp_path, capsys):
        tools = [
            {
                "name": "delete_file",
                "description": "Delete a file",
                "annotations": {
                    "x-agent-capability": {
                        "scope": "fs.delete",
                        "risk": {"level": "high"},
                    }
                },
            }
        ]
        tools_file = tmp_path / "tools.json"
        tools_file.write_text(json.dumps(tools))

        from acc_mcp.cli import main
        import sys
        old_argv = sys.argv
        try:
            sys.argv = ["acc-mcp", "inspect", str(tools_file)]
            ret = main()
        except SystemExit as e:
            ret = e.code
        finally:
            sys.argv = old_argv

        assert ret == 0
        captured = capsys.readouterr()
        assert "fs.delete" in captured.out
