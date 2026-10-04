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
4. **Diff** — Detect when a server's ACC declarations drift from approved baselines

## Architecture

```
MCP Client → acc-mcp (serve) → Upstream MCP Server
                 │
                 ├─ ACC Parser (extract declarations from tool schemas)
                 ├─ Risk Engine (classify by scope + execution hints)
                 ├─ Approval Gate (hold high-risk calls for human review)
                 └─ Drift Detector (compare against approved baselines)
```

## Install

```bash
pip install git+https://github.com/yunaremaia/acc-mcp.git
```

> **Not on PyPI yet.** `acc-mcp` has no PyPI release — the project page returns
> 404 — so `pip install acc-mcp` does not resolve. Install from Git with the
> command above until the first release is published.

## Quick Start

Every command below is executable as written against `examples/tools.json`, a
sample `tools/list` response. `tests/test_readme_quickstart.py` runs this exact
sequence, so it cannot rot again silently.

```bash
# 1. Verify the installed package version
acc-mcp --version
# acc-mcp version 0.1.0

# 2. Inspect the ACC declarations carried by a tool list
acc-mcp inspect examples/tools.json

# 3. Record the current declarations as an approved baseline
acc-mcp snapshot examples/tools.json --output baseline.json

# 4. Re-check the same tools against that baseline (exit 0 = no drift)
acc-mcp check --baseline baseline.json examples/tools.json

# 5. Validate a policy file without starting a proxy
acc-mcp --validate-policy examples/acc-mcp.yaml
```

Run it:

```console
$ acc-mcp --version
acc-mcp version 0.1.0

$ acc-mcp inspect examples/tools.json
Found ACC declarations for 3 tool(s):

  read_file:
    scope: fs.read
    risk: low
    readonly: True
    approval_required: False

  write_file:
    scope: fs.write
    risk: medium
    readonly: False
    approval_required: False

  delete_file:
    scope: fs.delete
    risk: critical
    readonly: False
    approval_required: True

$ acc-mcp snapshot examples/tools.json --output baseline.json
Snapshot saved to baseline.json

$ acc-mcp check --baseline baseline.json examples/tools.json
No drift detected.

$ acc-mcp --validate-policy examples/acc-mcp.yaml
Policy is valid: examples/acc-mcp.yaml
```

To put a real MCP server behind the enforcement proxy:

```bash
acc-mcp serve \
  --server-cmd "npx -y @modelcontextprotocol/server-filesystem /tmp" \
  --policy examples/acc-mcp.yaml
```

> **Enforcement modes.** `serve` enforces by default. `--dry-run` records every
> decision to stderr and forwards the call anyway. There is no `--mode` flag.

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
| `high` | REQUIRE APPROVAL | Write operations, non-idempotent |
| `critical` | BLOCK | Destructive, irreversible operations |

"Require approval" means `allowed=True` **and** `requires_approval=True`: the
gate holds the call for a human rather than refusing it. `critical` is refused
outright unless the policy sets `block_critical: false`. The approval gate only
ever holds a call — there is no in-process approver, so the caller must collect
the human's `yes` and decide what to do with it.

A tool whose declaration sets `enabled: false` is also blocked: the capability
author has withdrawn it, so it is neither callable nor advertised by the proxy
(ACC v1 §4.2).

Override any of this with a policy file — see
[`examples/acc-mcp.yaml`](examples/acc-mcp.yaml) for a commented one:

```yaml
risk_overrides:
  "fs.delete": critical
  "fs.read": low

approval_required_scopes:
  - "fs.delete"
approval_required_tools:
  - "execute_command"
block_tools:
  - "delete_all"

# Deny `critical` tools outright (default: true). Set to false to let them
# through the approval gate instead of refusing them.
block_critical: true
```

An unknown key or an invalid risk level is an error, not a warning. Validate a
policy before starting the proxy:

```bash
acc-mcp --validate-policy examples/acc-mcp.yaml
```

## Drift Detection

Snapshot a server's declarations to get an approved baseline, then re-check on
every deploy. `check` takes the baseline and the current tool list, and reports
what changed:

```bash
# Approve the current state
acc-mcp snapshot examples/tools.json --output baseline.json

# Later, against the server's current tools/list response
acc-mcp check --baseline baseline.json examples/tools.json
# No drift detected.        -> exit 0
# Drift detected!           -> exit 1
```

Drift is computed over ACC declarations only — a tool without an
`x-agent-capability` annotation is outside the contract and is not tracked.
Removing a declaration is itself reported as a breaking removal.

Categories, as classified by `DriftDetector.check`:

- **BREAKING** — the tool was removed or disabled, its `risk.level` was raised,
  its `approval.required` was flipped off, or `execution.readonly` was dropped.
  Every one of these removes a restriction the baseline was approved under, so
  the report is actionable: someone weakened a control.
- **DEGRADED** — the tool's `scope` changed. The capability still exists but
  claims a different scope than the one that was approved.
- **COMPATIBLE** — a new tool was declared, or a restriction was *added*
  (`approval.required`, `execution.readonly`, `enabled`) or the risk level was
  lowered.

`check` exits 1 when there is any breaking or degraded item. Compatible-only
changes exit 0: `DriftReport.drifted` is `bool(breaking or degraded)`. Inspect
`report.compatible` if you want to see them anyway.

Note that drift compares **declarations, not schemas**. A change to a tool's
`inputSchema` — a new required parameter, a narrowed type — is not drift as far
as this detector is concerned, because the ACC declaration says nothing about
parameter shape. It is listed here because it is the most surprising boundary
of the current implementation, not because it is covered.

## Integration

### As MCP Proxy (stdio)

`serve` proxies an MCP server and evaluates every `tools/call` against the
policy before forwarding it:

```bash
# stdio upstream
acc-mcp serve --server-cmd "npx -y @modelcontextprotocol/server-filesystem /tmp" \
  --policy examples/acc-mcp.yaml --report-json decisions.json

# Streamable HTTP upstream
acc-mcp serve --server-url http://localhost:3000/mcp --policy examples/acc-mcp.yaml

# Fetch and save the upstream tool snapshot without starting a proxy
acc-mcp serve --server-url http://localhost:3000/mcp --snapshot-only
```

Exactly one of `--server-cmd` or `--server-url` is required. Calls requiring
approval or denied by policy are returned as JSON-RPC errors with the
`GateDecisionResult` in the error data. Use `--dry-run` to record decisions
while forwarding calls.

### As Python Library

```python
from acc_mcp import ACCParser, Gateway, Policy

parser = ACCParser()
tools = parser.from_raw_tools(mcp_tool_definitions)  # list[MCPTool]
declarations = parser.parse_tools(tools)  # dict[str, ACCDeclaration]

policy = Policy.from_yaml("acc-mcp.yaml")
gateway = Gateway(policy=policy)

for tool in tools:
    decision = gateway.evaluate(tool, arguments={"path": "/tmp/test.txt"})
    if decision.allowed and not decision.requires_approval:
        result = execute_tool(tool, arguments)
    else:
        print(f"Blocked: {decision.reason}")
```

Two things to note, because both are easy to get wrong:

- `evaluate()` returns `allowed=True` for a call that still *requires approval*.
  `GateDecisionResult.requires_approval` (and `.approval_prompt`) is the signal
  that a human must sign off, so gate on both fields as above.
- `parse_tools()` only returns tools that carry an `x-agent-capability`
  annotation. `from_raw_tools()` returns every tool; a tool missing the
  annotation is reported by neither, and `Gateway.evaluate()` classifies it
  heuristically from its name.

### GitHub Actions

There is no `drift-check` action. Run the CLI in your workflow instead:

```yaml
- name: Check for ACC drift
  run: |
    pip install git+https://github.com/yunaremaia/acc-mcp.git
    acc-mcp snapshot tools/approved.json --output /tmp/baseline.json
    acc-mcp check --baseline /tmp/baseline.json tools/current.json
```

Note that `check` takes the current tool list as a **positional** argument, not
`--server` or `--tools-file`.

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
