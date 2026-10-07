"""Contract tests for DriftDetector.check() scope and the snapshot round-trip.

These tests pin two behaviours that the drift checker relies on and that are
not exercised elsewhere:

1. ``check()`` compares *ACC declarations*, so tools that carry no
   ``x-agent-capability`` annotation are untracked by design. Removing the
   unread ``baseline_map`` / ``current_map`` locals therefore changes nothing.
2. ``snapshot()`` always writes a non-empty JSON declaration into the
   ``description`` field of every entry it emits, so ``check_from_snapshots()``
   never has to fall back to the empty-annotations branch on a snapshot this
   package produced.
"""

from __future__ import annotations

import json

from acc_mcp.drift import DriftDetector
from acc_mcp.models import ACCDeclaration, MCPTool

READ_DECL = {"scope": "fs.read", "risk": {"level": "low"}}


def make_tool(name: str, decl: dict | None) -> MCPTool:
    """Build an MCPTool, declared with an ACC contract or left undeclared."""
    annotations = {} if decl is None else {"x-agent-capability": decl}
    return MCPTool(name=name, annotations=annotations)


def all_items(report) -> list:
    return [*report.breaking, *report.degraded, *report.compatible]


class TestUndeclaredToolsAreUntracked:
    """Contract: drift is computed over ACC declarations only."""

    def test_undeclared_tool_is_absent_from_the_snapshot(self):
        # Positive control: the parser really is dropping undeclared tools,
        # which is what makes them invisible downstream.
        detector = DriftDetector()
        snapshot = detector.snapshot([make_tool("read_file", READ_DECL), make_tool("plain_tool", None)])

        assert set(snapshot) == {"read_file"}

    def test_undeclared_tool_in_both_sets_is_invisible(self):
        # `plain_tool` carries no declaration on either side. It is outside the
        # ACC contract, so no drift item mentions it.
        detector = DriftDetector()
        baseline = [make_tool("read_file", READ_DECL), make_tool("plain_tool", None)]
        current = [
            make_tool("read_file", {"scope": "fs.write", "risk": {"level": "low"}}),
            make_tool("plain_tool", None),
        ]

        report = detector.check(baseline, current)

        assert [item.tool_name for item in all_items(report)] == ["read_file"]

    def test_new_undeclared_tool_is_invisible(self):
        # A tool that appears in the current set without a declaration is not
        # drift: there is no declaration for it to have drifted from.
        detector = DriftDetector()
        baseline = [make_tool("read_file", READ_DECL)]
        current = [make_tool("read_file", READ_DECL), make_tool("brand_new", None)]

        report = detector.check(baseline, current)

        assert report.drifted is False
        assert all_items(report) == []

    def test_stripped_declaration_is_reported_as_breaking_removed(self):
        # The security-relevant case, and the one a reader of the removed
        # `baseline_map` may worry was lost: a declared tool that keeps existing
        # but has its ACC contract deleted. It IS detected, as breaking.
        detector = DriftDetector()
        baseline = [make_tool("delete_file", {"scope": "fs.delete", "risk": {"level": "critical"}})]
        current = [make_tool("delete_file", None)]

        report = detector.check(baseline, current)

        assert report.drifted is True
        assert [(i.tool_name, i.change_type, i.severity) for i in report.breaking] == [
            ("delete_file", "removed", "breaking")
        ]

    def test_full_scenario_reports_exactly_the_declared_changes(self):
        # One test over the whole matrix the deleted maps spanned: an unchanged
        # declared tool, a scope change, a risk escalation, an approval
        # downgrade, a removed tool, a newly declared tool, and two undeclared
        # tools. If the maps were load-bearing, this set of items would differ.
        detector = DriftDetector()
        baseline = [
            make_tool("unchanged", READ_DECL),
            make_tool("scoped", READ_DECL),
            make_tool("risky", READ_DECL),
            make_tool("guard", {"scope": "fs.delete", "approval": {"required": True}}),
            make_tool("gone", READ_DECL),
            make_tool("baseline_plain", None),
            make_tool("current_plain", None),
        ]
        current = [
            make_tool("unchanged", READ_DECL),
            make_tool("scoped", {"scope": "fs.write", "risk": {"level": "low"}}),
            make_tool("risky", {"scope": "fs.read", "risk": {"level": "critical"}}),
            make_tool("guard", {"scope": "fs.delete", "approval": {"required": False}}),
            make_tool("baseline_plain", None),
            make_tool("current_plain", None),
            make_tool("new_declared", READ_DECL),
        ]

        report = detector.check(baseline, current)

        assert [(i.tool_name, i.field, i.severity) for i in report.breaking] == [
            ("gone", "declaration", "breaking"),
            ("risky", "risk", "breaking"),
            ("guard", "approval.required", "breaking"),
        ]
        assert [(i.tool_name, i.field, i.severity) for i in report.degraded] == [
            ("scoped", "scope", "degraded")
        ]
        assert [(i.tool_name, i.field, i.severity) for i in report.compatible] == [
            ("new_declared", "declaration", "compatible")
        ]
        assert report.drifted is True


class TestSnapshotDeclarationIsAlwaysPresent:
    """Contract: every snapshot entry carries a parseable ACC declaration."""

    def test_every_snapshot_entry_has_a_non_empty_declaration(self):
        detector = DriftDetector()
        snapshot = detector.snapshot(
            [
                make_tool("read_file", READ_DECL),
                make_tool("delete_file", {"scope": "fs.delete", "risk": {"level": "critical"}}),
                make_tool("bare", {"scope": "fs.stat"}),
                make_tool("plain_tool", None),
            ]
        )

        assert snapshot, "fixture must produce at least one entry"
        for name, entry in snapshot.items():
            assert entry["description"], f"{name} snapshot entry has an empty description"
            # And the description round-trips back into a real declaration,
            # which is what check_from_snapshots() feeds to the parser.
            assert ACCDeclaration.model_validate(json.loads(entry["description"])).scope

    def test_snapshot_declared_tool_is_tracked_from_the_snapshot_dict(self):
        # Positive control for the empty-annotations fallback: a snapshot this
        # package produced IS tracked by check_from_snapshots().
        detector = DriftDetector()
        snapshot = detector.snapshot([make_tool("delete_file", {"scope": "fs.delete"})])

        report = detector.check_from_snapshots(snapshot, {})

        assert [(i.tool_name, i.change_type, i.severity) for i in report.breaking] == [
            ("delete_file", "removed", "breaking")
        ]

    def test_roundtrip_through_a_file_preserves_drift_detection(self, tmp_path):
        detector = DriftDetector()
        baseline = detector.snapshot([make_tool("read_file", READ_DECL)])
        path = tmp_path / "baseline.json"
        detector.save_snapshot(baseline, path)

        loaded = detector.load_snapshot(path)
        current = detector.snapshot(
            [make_tool("read_file", {"scope": "fs.read", "risk": {"level": "critical"}})]
        )
        report = detector.check_from_snapshots(loaded, current)

        assert [(i.tool_name, i.field, i.severity) for i in report.breaking] == [
            ("read_file", "risk", "breaking")
        ]

    def test_empty_description_in_a_hand_authored_snapshot_is_silently_dropped(self):
        """Documents the residual fail-open, which snapshot() itself cannot cause.

        `check_from_snapshots` rebuilds an undeclared tool when an entry has no
        `description`, which drops that tool out of drift detection with no
        error. `TestSnapshotDeclarationIsAlwaysPresent` proves snapshot() never
        produces such an entry, so the only way to reach this is a snapshot file
        written by hand or edited outside acc-mcp.
        """
        detector = DriftDetector()
        crafted = {"delete_file": {"scope": "fs.delete", "risk": {"level": "critical"}, "description": ""}}

        report = detector.check_from_snapshots(crafted, {})

        assert all_items(report) == []
        assert report.drifted is False

    def test_malformed_description_in_a_snapshot_is_silently_dropped(self):
        # A non-empty but unparseable description is treated like an empty
        # one: the tool is undeclared and therefore not tracked.
        detector = DriftDetector()
        crafted = {"delete_file": {"description": "not json"}}

        report = detector.check_from_snapshots(crafted, {})

        assert all_items(report) == []
        assert report.drifted is False