"""Parser for extracting ACC declarations from MCP tool schemas."""

from __future__ import annotations

from acc_mcp.models import ACCDeclaration, MCPTool


class ACCParser:
    """Extract and validate ACC declarations from MCP tool definitions."""

    ACC_ANNOTATION_KEY = "x-agent-capability"

    def parse_tool(self, tool: MCPTool) -> ACCDeclaration | None:
        """Extract ACC declaration from a single MCP tool."""
        raw = tool.annotations.get(self.ACC_ANNOTATION_KEY)
        if raw is None:
            return None
        return ACCDeclaration.model_validate(raw)

    def parse_tools(self, tools: list[MCPTool]) -> dict[str, ACCDeclaration]:
        """Extract ACC declarations from multiple MCP tools.

        Returns a dict of tool_name -> ACCDeclaration for tools that have one.
        """
        result: dict[str, ACCDeclaration] = {}
        for tool in tools:
            decl = self.parse_tool(tool)
            if decl is not None:
                result[tool.name] = decl
        return result

    def tool_has_acc(self, tool: MCPTool) -> bool:
        """Check if a tool has an ACC declaration."""
        return self.ACC_ANNOTATION_KEY in tool.annotations

    @staticmethod
    def from_raw_tools(raw_tools: list[dict]) -> list[MCPTool]:
        """Convert raw MCP tool dicts to MCPTool objects."""
        return [MCPTool.model_validate(t) for t in raw_tools]
