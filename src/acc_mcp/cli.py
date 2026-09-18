"""acc-mcp CLI."""

from __future__ import annotations

import argparse
import json
import sys

from acc_mcp import __version__
from acc_mcp.models import MCPTool
from acc_mcp.parser import ACCParser
from acc_mcp.gateway import Gateway, Policy
from acc_mcp.drift import DriftDetector


def cmd_inspect(args: argparse.Namespace) -> int:
    """Inspect ACC declarations from a JSON file of tools."""
    with open(args.tools_file) as f:
        raw_tools = json.load(f)

    parser = ACCParser()
    tools = parser.from_raw_tools(raw_tools)
    decls = parser.parse_tools(tools)

    if not decls:
        print("No ACC declarations found in tools.")
        return 0

    print(f"Found ACC declarations for {len(decls)} tool(s):\n")
    for name, decl in decls.items():
        print(f"  {name}:")
        print(f"    scope: {decl.scope}")
        print(f"    risk: {decl.risk.level.value}")
        print(f"    readonly: {decl.execution.readonly}")
        print(f"    approval_required: {decl.approval.required}")
        print()
    return 0


def cmd_snapshot(args: argparse.Namespace) -> int:
    """Create a snapshot of tool ACC declarations."""
    with open(args.tools_file) as f:
        raw_tools = json.load(f)

    detector = DriftDetector()
    snapshot = detector.snapshot_raw(raw_tools)

    if args.output:
        detector.save_snapshot(snapshot, args.output)
        print(f"Snapshot saved to {args.output}")
    else:
        print(json.dumps(snapshot, indent=2))
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    """Check for drift between baseline and current tools."""
    detector = DriftDetector()

    with open(args.baseline) as f:
        baseline = json.load(f)
    with open(args.tools_file) as f:
        raw_tools = json.load(f)

    current = detector.snapshot_raw(raw_tools)
    report = detector.check_from_snapshots(baseline, current)

    if not report.drifted:
        print("No drift detected.")
        return 0

    print(f"Drift detected!")
    if report.breaking:
        print(f"\n  Breaking changes ({len(report.breaking)}):")
        for item in report.breaking:
            print(f"    - {item.tool_name}.{item.field}: {item.old_value} -> {item.new_value}")
    if report.degraded:
        print(f"\n  Degraded changes ({len(report.degraded)}):")
        for item in report.degraded:
            print(f"    - {item.tool_name}.{item.field}: {item.old_value} -> {item.new_value}")
    if report.compatible:
        print(f"\n  Compatible changes ({len(report.compatible)}):")
        for item in report.compatible:
            print(f"    - {item.tool_name}.{item.field}: {item.old_value} -> {item.new_value}")
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(prog="acc-mcp", description="ACC v1 MCP binding")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    # inspect
    inspect_parser = subparsers.add_parser("inspect", help="Inspect ACC declarations")
    inspect_parser.add_argument("tools_file", help="JSON file with MCP tool definitions")
    inspect_parser.set_defaults(func=cmd_inspect)

    # snapshot
    snapshot_parser = subparsers.add_parser("snapshot", help="Create ACC snapshot")
    snapshot_parser.add_argument("tools_file", help="JSON file with MCP tool definitions")
    snapshot_parser.add_argument("-o", "--output", help="Output file for snapshot")
    snapshot_parser.set_defaults(func=cmd_snapshot)

    # check
    check_parser = subparsers.add_parser("check", help="Check for drift")
    check_parser.add_argument("--baseline", required=True, help="Baseline snapshot JSON")
    check_parser.add_argument("tools_file", help="Current tools JSON file")
    check_parser.set_defaults(func=cmd_check)

    args = parser.parse_args()
    if args.command is None:
        parser.print_help()
        return 1
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
