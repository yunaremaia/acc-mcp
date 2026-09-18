# acc-mcp

**Agent Capability Contract (ACC) v1 — MCP Binding**

Parse ACC declarations from MCP tool schemas and enforce scope, risk, and approval semantics at the gateway. This is the missing MCP binding for the [agent-capability-contract](https://github.com/agent-capability/agent-capability-contract) specification.

## Problem

MCP servers expose tools, but the protocol has no standard way to declare:
- Which operations are read-only vs. destructive
- Which require human approval before execution
- Which scope/permissions a tool needs
- Whether a trusted acting subject is required

The ACC v1 spec defines a portable contract for exactly this — but today only has an OpenAPI binding. **acc-mcp fills that gap.**

## What It Does

1. **Parse** — Extract ACC declarations from MCP tool `annotations` or `_meta` fields
2. **Classify** — Assign risk levels (low/medium/high/critical) based on ACC metadata
3. **Enforce** — Block, warn, or require approval before tool invocation
4. **Audit** — Log every decision with hash-chained tamper evidence
5. **Diff** — Detect when a server's ACC declarations drift from approved baselines

## Architecture

```
MCP Client → acc-mcp Gateway → Upstream MCP Server
                  │
                  ├─ ACC Parser (extract declarations from tool schemas)
                  ├─ Risk Engine (classify by scope + execution hints)
                  ├─ Approval Gate (hold high-risk calls for human review)
                  ├─ Drift Detector (compare against approved baselines)
                  └─ Audit Log (hash-chained, optionally signed)
```

## Quick Start

```bash
pip install acc-mcp

# Start gateway in front of an MCP server
acc-mcp gateway --upstream "npx -y @modelcontextprotocol/server-filesystem /tmp" --mode enforce

# Parse and inspect ACC declarations from a server
acc-mcp inspect --server filesystem

# Create a baseline snapshot
acc-mcp snapshot --server filesystem --output baseline.json

# Check for drift against baseline
acc-mcp check --baseline baseline.json --server filesystem
```

## ACC Declaration Format in MCP

Tools declare ACC metadata via the `annotations` field:

```json
{
  "name": "delete_file",
  "description": "Delete a file from the filesystem",
  "inputSchema": { "type": "object", "properties": { "path": { "type": "string" } } },
  "annotations": {
    "x-agent-capability": {
      "version": 1,
      "enabled": true,
      "scope": "fs.delete",
      "risk": { "level": "high" },
      "subject": { "required": true },
      "approval": { "required": true, "prompt": "Confirm file deletion" },
      "execution": { "readonly": false, "idempotent": false }
    }
  }
}
```

## Risk Classification

| ACC Risk Level | Default Action | Description |
|---|---|---|
| `low` | ALLOW | Read-only, idempotent operations |
| `medium` | ALLOW | Read operations with side effects |
| `high` | WARN | Write operations, non-idempotent |
| `critical` | BLOCK | Destructive, irreversible operations |

Override with policy file:

```yaml
# acc-mcp.yaml
risk_overrides:
  "fs.delete": critical
  "fs.read": low

approval_required:
  - scope: "fs.delete"
    prompt: "Confirm deletion of {path}"
  - scope: "shell.execute"
    prompt: "Execute: {command}"
```

## Drift Detection

When a server updates its tool schemas, acc-mcp compares against the approved baseline:

```bash
acc-mcp drift-check --baseline baseline.json
# Exit 0: no drift
# Exit 1: drift detected (breaking changes in tool contracts)
```

Drift categories:
- **BREAKING**: Tool removed, required param added, type narrowed
- **DEGRADED**: Description changed, optional param added
- **COMPATIBLE**: New tool added, output field added

## Integration

### As MCP Gateway (stdio)

```bash
acc-mcp gateway \
  --upstream "npx -y @modelcontextprotocol/server-filesystem /tmp" \
  --mode enforce \
  --policy acc-mcp.yaml
```

### As Python Library

```python
from acc_mcp import ACCParser, Gateway, Policy

parser = ACCParser()
tools = parser.extract_tools(mcp_tool_definitions)

policy = Policy.from_yaml("acc-mcp.yaml")
gateway = Gateway(policy=policy)

for tool in tools:
    decision = gateway.evaluate(tool, arguments={"path": "/tmp/test.txt"})
    if decision.allowed:
        result = execute_tool(tool, arguments)
    else:
        print(f"Blocked: {decision.reason}")
```

### GitHub Action

```yaml
- uses: yunaremaia/acc-mcp/drift-check@v1
  with:
    baseline: acc-baseline.json
    fail-on: breaking
```

## Roadmap

- [x] ACC v1 MCP binding parser
- [x] Risk classification engine
- [x] Approval gate with human-in-the-loop
- [x] Drift detection against baselines
- [ ] Signed audit log (Ed25519)
- [ ] Kubernetes operator for fleet-wide enforcement
- [ ] Prometheus metrics export
- [ ] Web dashboard for drift visualization
- [ ] Multi-server aggregation

## License

MIT

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All public artifacts (PRs, issues, comments) must be in English.
