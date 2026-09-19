"""JSON-RPC MCP proxy which enforces ACC decisions before tool calls."""

from __future__ import annotations

import json
import sys
from typing import Any, TextIO

from acc_mcp.gateway import Gateway
from acc_mcp.models import GateDecisionResult, MCPTool
from acc_mcp.parser import ACCParser
from acc_mcp.transport import MCPTransport


class MCPProxy:
    def __init__(
        self,
        transport: MCPTransport,
        gateway: Gateway,
        *,
        dry_run: bool = False,
        report_path: str | None = None,
    ):
        self.transport = transport
        self.gateway = gateway
        self.dry_run = dry_run
        self.report_path = report_path
        self.tools: dict[str, MCPTool] = {}
        self.decisions: list[GateDecisionResult] = []

    def _initialize(self, request: dict[str, Any]) -> dict[str, Any]:
        response = self.transport.request(request)
        self.transport.notify(
            {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}
        )
        tools_response = self.transport.request(
            {"jsonrpc": "2.0", "id": "__acc_mcp_tools_list__", "method": "tools/list", "params": {}}
        )
        raw_tools = tools_response.get("result", {}).get("tools", [])
        self.tools = {tool.name: tool for tool in ACCParser.from_raw_tools(raw_tools)}
        return response

    def _decision_error(self, request_id: Any, decision: GateDecisionResult) -> dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": -32003,
                "message": "Tool call blocked by ACC policy",
                "data": decision.model_dump(mode="json"),
            },
        }

    def snapshot(self) -> list[dict[str, Any]]:
        """Initialize the upstream and return its ACC-enriched tool definitions."""
        self._initialize(
            {
                "jsonrpc": "2.0",
                "id": "__acc_mcp_initialize__",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "acc-mcp", "version": "0.1.0"},
                },
            }
        )
        return [tool.model_dump(by_alias=True) for tool in self.tools.values()]

    def handle(self, request: dict[str, Any]) -> dict[str, Any] | None:
        method = request.get("method")
        if method == "initialize":
            return self._initialize(request)
        if method == "notifications/initialized":
            self.transport.notify(request)
            return None
        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": request.get("id"),
                "result": {"tools": [tool.model_dump(by_alias=True) for tool in self.tools.values()]},
            }
        if method != "tools/call":
            if "id" not in request:
                self.transport.notify(request)
                return None
            return self.transport.request(request)

        params = request.get("params") or {}
        tool_name = params.get("name")
        tool = self.tools.get(tool_name)
        if tool is None:
            decision = GateDecisionResult(
                tool_name=str(tool_name),
                allowed=False,
                risk_level="critical",
                reason=f"Unknown tool '{tool_name}'",
                requires_approval=False,
            )
        else:
            decision = self.gateway.evaluate(tool, params.get("arguments") or {})
        self.decisions.append(decision)
        if self.dry_run:
            print(
                f"dry-run: {tool_name}: {'allow' if decision.allowed else 'block'} "
                f"({decision.reason})",
                file=sys.stderr,
            )
        if not self.dry_run and (not decision.allowed or decision.requires_approval):
            return self._decision_error(request.get("id"), decision)
        return self.transport.request(request)

    def run(self, input_stream: TextIO = sys.stdin, output_stream: TextIO = sys.stdout) -> None:
        try:
            for line in input_stream:
                if not line.strip():
                    continue
                request = json.loads(line)
                response = self.handle(request)
                if response is not None:
                    output_stream.write(json.dumps(response) + "\n")
                    output_stream.flush()
        finally:
            if self.report_path:
                with open(self.report_path, "w", encoding="utf-8") as report:
                    json.dump([item.model_dump(mode="json") for item in self.decisions], report, indent=2)
            self.transport.close()
