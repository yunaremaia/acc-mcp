"""Contract tests: ACC declarations that the gateway and drift checker must enforce.

The engine parsed declarations it never read. Three fields were documented as
security controls but did nothing at all:

1. ``risk.level: critical`` -- the README's risk table says BLOCK and
   ``Policy.standard()``'s docstring says "block critical", yet ``evaluate()``
   had no deny branch for it and returned ``allowed=True``.
2. ``enabled: false`` -- parsed into ``ACCDeclaration.enabled`` and then never
   consumed, so a tool the server author explicitly disabled executed anyway
   and was still advertised to the client.
3. ``execution.readonly`` and ``enabled`` in the drift comparison --
   ``DriftDetector.check()`` diffed only ``scope``, ``risk.level`` and
   ``approval.required``, so a read-only tool that became write-capable, or a
   tool that was disabled, both reported as no drift.

A declared control that the enforcement path ignores is worse than a missing
control: the README and the ACC declaration tell an operator the boundary
exists. These tests pin the enforcement so the gap cannot reopen silently.
"""

from __future__ import annotations

import pytest

from acc_mcp.drift import DriftDetector
from acc_mcp.gateway import Gateway, Policy
from acc_mcp.models import MCPTool, RiskLevel
from acc_mcp.proxy import MCPProxy


def make_tool(name: str, decl: dict | None) -> MCPTool:
    """Build an MCPTool, declared with an ACC contract or left undeclared."""
    annotations = {} if decl is None else {"x-agent-capability": decl}
    return MCPTool(name=name, description=f"{name} tool", annotations=annotations)


def all_items(report) -> list:
    return [*report.breaking, *report.degraded, *report.compatible]


class TestCriticalRiskIsDenied:
    """`risk.level: critical` must be blocked, as the README documents."""

    def test_critical_tool_is_blocked_by_the_standard_policy(self):
        # The exact reproduction from the issue report: a `critical` tool with
        # no other policy configuration at all.
        tool = make_tool("wipe_database", {"scope": "db.wipe", "risk": {"level": "critical"}})

        decision = Gateway(policy=Policy.standard()).evaluate(tool)

        assert decision.allowed is False
        assert decision.risk_level == RiskLevel.CRITICAL
        assert "wipe_database" in decision.reason

    def test_critical_tool_is_blocked_by_the_default_gateway(self):
        # `Gateway()` with no policy must behave the same as standard(): an
        # operator who never configured a policy is the case that matters.
        tool = make_tool("wipe_database", {"scope": "db.wipe", "risk": {"level": "critical"}})

        decision = Gateway().evaluate(tool)

        assert decision.allowed is False

    def test_high_risk_is_not_blocked(self):
        # The negative control: only `critical` is denied. `high` still gates
        # on approval, so the deny cannot be swallowing every risky tool.
        tool = make_tool("delete_file", {"scope": "fs.delete", "risk": {"level": "high"}})

        decision = Gateway().evaluate(tool)

        assert decision.allowed is True
        assert decision.requires_approval is True

    def test_low_and_medium_risk_are_allowed(self):
        # Positive control that the deny branch keys on CRITICAL and nothing else.
        for level in ("low", "medium"):
            decision = Gateway().evaluate(make_tool("read_file", {"scope": "fs.read", "risk": {"level": level}}))
            assert decision.allowed is True, f"{level} must not be denied"

    def test_critical_is_blocked_even_when_approval_is_requested(self):
        # A declaration asking for approval must not be able to talk its way
        # past a deny: `approval.required` is advisory, the risk block is not.
        tool = make_tool(
            "wipe_database",
            {
                "scope": "db.wipe",
                "risk": {"level": "critical"},
                "approval": {"required": True, "prompt": "Confirm wipe"},
            },
        )

        decision = Gateway().evaluate(tool)

        assert decision.allowed is False
        assert decision.requires_approval is False

    def test_risk_override_to_critical_is_enforced(self):
        # An operator escalating a scope to `critical` via policy expects the
        # block to take effect; otherwise the override only decorates the report.
        policy = Policy(risk_overrides={"fs.delete": RiskLevel.CRITICAL})
        tool = make_tool("delete_file", {"scope": "fs.delete", "risk": {"level": "medium"}})

        decision = Gateway(policy=policy).evaluate(tool)

        assert decision.allowed is False
        assert decision.risk_level == RiskLevel.CRITICAL

    def test_critical_block_can_be_disabled_by_policy(self):
        # Operators who want critical to mean "approval, not refusal" need an
        # opt-out; without it the deny is unconditional and unworkaroundable.
        policy = Policy(block_critical=False)
        tool = make_tool("wipe_database", {"scope": "db.wipe", "risk": {"level": "critical"}})

        decision = Gateway(policy=policy).evaluate(tool)

        assert decision.allowed is True
        assert decision.requires_approval is True

    def test_block_critical_is_loadable_from_a_policy_file(self, tmp_path):
        # The opt-out has to be reachable from the documented YAML surface,
        # otherwise `KNOWN_POLICY_KEYS` rejects the operator's own file.
        path = tmp_path / "policy.yaml"
        path.write_text("block_critical: false\n")

        policy = Policy.from_yaml(path)

        assert policy.block_critical is False

    def test_block_critical_defaults_to_true_when_loading_a_policy_file(self, tmp_path):
        # A policy file that says nothing about critical risk must not silently
        # opt out of blocking it.
        path = tmp_path / "policy.yaml"
        path.write_text('block_tools:\n  - "delete_all"\n')

        policy = Policy.from_yaml(path)

        assert policy.block_critical is True

    def test_blocked_critical_tool_still_names_its_risk_in_the_reason(self):
        # The reason string is what an operator reads in the proxy's JSON-RPC
        # error and in the decision report; it must explain the refusal.
        tool = make_tool("wipe_database", {"scope": "db.wipe", "risk": {"level": "critical"}})

        decision = Gateway().evaluate(tool)

        assert "critical" in decision.reason.lower()


class TestDisabledToolIsDenied:
    """`enabled: false` must not be invocable, per ACC v1 §4.2."""

    def test_disabled_tool_is_blocked(self):
        # The exact reproduction from the issue report.
        tool = make_tool(
            "disabled_delete",
            {"scope": "fs.delete", "risk": {"level": "low"}, "enabled": False},
        )

        decision = Gateway().evaluate(tool)

        assert decision.allowed is False
        assert decision.requires_approval is False

    def test_disabled_tool_is_blocked_despite_a_critical_risk_declaration(self):
        # A disabled tool declaring `critical` is refused for the right reason:
        # the declaration is off, not merely risky. A caller reading only the
        # reason must not think approval would unlock it.
        tool = make_tool(
            "disabled_delete",
            {"scope": "fs.delete", "risk": {"level": "critical"}, "enabled": False},
        )

        decision = Gateway().evaluate(tool)

        assert decision.allowed is False
        assert "disabled" in decision.reason.lower()

    def test_disabled_tool_is_blocked_even_when_the_policy_allows_it(self):
        # The operator has not blocked this tool by name; the server author
        # disabled it. An explicit allow must not resurrect a disabled tool.
        tool = make_tool("disabled_delete", {"scope": "fs.delete", "enabled": False})

        decision = Gateway(policy=Policy(block_tools=[])).evaluate(tool)

        assert decision.allowed is False

    def test_disabled_tool_is_blocked_even_when_approval_is_granted(self):
        # `enabled: false` is an opt-out by the capability author, not a gate a
        # human can wave through.
        tool = make_tool(
            "disabled_delete",
            {"scope": "fs.delete", "enabled": False, "approval": {"required": True}},
        )

        decision = Gateway().evaluate(tool)

        assert decision.allowed is False
        assert decision.requires_approval is False

    def test_enabled_tool_is_not_affected(self):
        # Positive control: the fix must not deny the default (`enabled` defaults
        # to True) or an explicit `enabled: true`.
        for decl in ({"scope": "fs.read", "risk": {"level": "low"}}, {"scope": "fs.read", "enabled": True}):
            decision = Gateway().evaluate(make_tool("read_file", decl))
            assert decision.allowed is True

    def test_undeclared_tool_is_still_allowed(self):
        # Tools with no ACC declaration are outside the contract and must keep
        # the heuristic path; `enabled` has no value to read there.
        decision = Gateway().evaluate(make_tool("read_file", None))

        assert decision.allowed is True


class DisabledToolTransport:
    """A fake upstream that reports whether a tools/call reached it."""

    def __init__(self) -> None:
        self.notifications: list = []
        self.requests: list = []
        self.responses = {
            "initialize": {
                "jsonrpc": "2.0",
                "id": "client-init",
                "result": {"protocolVersion": "2025-03-26", "capabilities": {}},
            },
            "tools/list": {
                "jsonrpc": "2.0",
                "id": "__acc_mcp_tools_list__",
                "result": {
                    "tools": [
                        {
                            "name": "read_file",
                            "inputSchema": {"type": "object"},
                            "annotations": {
                                "x-agent-capability": {"scope": "fs.read", "risk": {"level": "low"}}
                            },
                        },
                        {
                            "name": "disabled_delete",
                            "inputSchema": {"type": "object"},
                            "annotations": {
                                "x-agent-capability": {
                                    "scope": "fs.delete",
                                    "risk": {"level": "low"},
                                    "enabled": False,
                                }
                            },
                        },
                    ]
                },
            },
        }

    def request(self, message):
        self.requests.append(message)
        if message["method"] == "tools/call":
            return {"jsonrpc": "2.0", "id": message["id"], "result": {"content": []}}
        return self.responses[message["method"]]

    def notify(self, message):
        self.notifications.append(message)

    def close(self):
        pass

    def upstream_calls(self) -> list:
        return [r for r in self.requests if r["method"] == "tools/call"]


class TestProxyHonoursDeclarations:
    """End-to-end: the proxy must neither advertise nor execute a disabled tool."""

    def _initialized_proxy(self, transport=None, **kwargs):
        transport = transport or DisabledToolTransport()
        proxy = MCPProxy(transport, Gateway(), **kwargs)
        proxy.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        return transport, proxy

    def test_disabled_tool_call_never_reaches_the_upstream(self):
        # ACC v1 §4.2: "When false, the operation MUST NOT be exposed as an
        # agent-callable capability."
        transport, proxy = self._initialized_proxy()

        response = proxy.handle(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "disabled_delete", "arguments": {}},
            }
        )

        assert response["error"]["code"] == -32003
        assert transport.upstream_calls() == []

    def test_disabled_tool_is_not_advertised_to_the_client(self):
        # Advertising a tool the proxy will refuse is a contract the client
        # cannot satisfy: every call it makes in good faith fails.
        _, proxy = self._initialized_proxy()

        listed = proxy.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})

        names = [tool["name"] for tool in listed["result"]["tools"]]
        assert "disabled_delete" not in names
        assert "read_file" in names

    def test_enabled_tool_still_reaches_the_upstream(self):
        # Positive control for both assertions above: filtering and refusing
        # must not swallow the tools that are legitimately callable.
        transport, proxy = self._initialized_proxy()

        response = proxy.handle(
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {}},
            }
        )

        assert response["result"] == {"content": []}
        assert [r["params"]["name"] for r in transport.upstream_calls()] == ["read_file"]

    def test_critical_tool_call_never_reaches_the_upstream(self):
        # A `critical` tool is refused by policy rather than by approval, and
        # the proxy must not forward it either way.
        transport, proxy = self._initialized_proxy()
        proxy.tools["wipe_database"] = make_tool(
            "wipe_database", {"scope": "db.wipe", "risk": {"level": "critical"}}
        )

        response = proxy.handle(
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {"name": "wipe_database", "arguments": {}},
            }
        )

        assert response["error"]["code"] == -32003
        assert transport.upstream_calls() == []


class TestDriftComparesSecurityRelevantFields:
    """`check()` must diff the fields that decide what a tool is allowed to do."""

    def _read_tool(self, **overrides) -> MCPTool:
        decl = {"version": 1, "enabled": True, "scope": "fs.read", "risk": {"level": "low"}}
        decl.update(overrides)
        return make_tool("read_file", decl)

    def test_readonly_to_writable_is_breaking(self):
        # The exact reproduction from the issue report: a tool approved as
        # read-only mutates state while keeping its scope and risk level.
        baseline = [self._read_tool(execution={"readonly": True, "idempotent": True}, subject={"required": True})]
        current = [self._read_tool(execution={"readonly": False, "idempotent": False}, subject={"required": False})]

        report = DriftDetector().check(baseline, current)

        assert report.drifted is True
        assert [(i.field, i.severity) for i in report.breaking] == [
            ("execution.readonly", "breaking")
        ]
        assert [(i.old_value, i.new_value) for i in report.breaking] == [(True, False)]

    def test_writable_to_readonly_is_compatible(self):
        # The inverse is a tightening: report it, but do not fail a CI gate on it.
        baseline = [self._read_tool(execution={"readonly": False})]
        current = [self._read_tool(execution={"readonly": True})]

        report = DriftDetector().check(baseline, current)

        assert report.drifted is False
        assert [(i.field, i.severity) for i in report.compatible] == [
            ("execution.readonly", "compatible")
        ]

    def test_enabled_to_disabled_is_breaking(self):
        # A capability the baseline advertised disappearing from the current
        # contract is a breaking change for any consumer of that baseline.
        baseline = [self._read_tool()]
        current = [self._read_tool(enabled=False)]

        report = DriftDetector().check(baseline, current)

        assert report.drifted is True
        assert [(i.field, i.severity) for i in report.breaking] == [("enabled", "breaking")]

    def test_disabled_to_enabled_is_compatible(self):
        baseline = [self._read_tool(enabled=False)]
        current = [self._read_tool()]

        report = DriftDetector().check(baseline, current)

        assert report.drifted is False
        assert [(i.field, i.severity) for i in report.compatible] == [("enabled", "compatible")]

    def test_unchanged_declaration_produces_no_items(self):
        # Positive control: the new comparisons must not fire on a stable
        # declaration, or every drift run would be noise.
        tool = self._read_tool(execution={"readonly": True}, approval={"required": True})

        report = DriftDetector().check([tool], [tool])

        assert report.drifted is False
        assert all_items(report) == []

    def test_readonly_flip_is_detected_through_the_snapshot_round_trip(self):
        # The CLI path: `acc-mcp check` compares snapshots, so the field must
        # survive the snapshot and the round-trip must still report it.
        detector = DriftDetector()
        baseline = detector.snapshot([self._read_tool(execution={"readonly": True})])
        current = detector.snapshot([self._read_tool(execution={"readonly": False})])

        report = detector.check_from_snapshots(baseline, current)

        assert report.drifted is True
        assert [(i.field, i.severity) for i in report.breaking] == [
            ("execution.readonly", "breaking")
        ]

    def test_disabled_flip_is_detected_through_the_snapshot_round_trip(self):
        detector = DriftDetector()
        baseline = detector.snapshot([self._read_tool()])
        current = detector.snapshot([self._read_tool(enabled=False)])

        report = detector.check_from_snapshots(baseline, current)

        assert report.drifted is True
        assert [(i.field, i.severity) for i in report.breaking] == [("enabled", "breaking")]

    def test_drift_items_name_the_tool_they_belong_to(self):
        # A CI log reads tool by tool; an item that omits the tool name is
        # unactionable.
        baseline = [self._read_tool(execution={"readonly": True}), make_tool("write_file", {"scope": "fs.write"})]
        current = [self._read_tool(execution={"readonly": False}), make_tool("write_file", {"scope": "fs.write"})]

        report = DriftDetector().check(baseline, current)

        assert [i.tool_name for i in report.breaking] == ["read_file"]
        assert all(i.change_type == "modified" for i in report.breaking)

    @pytest.mark.parametrize(
        ("baseline_decl", "current_decl", "expected_field"),
        [
            ({"scope": "fs.read", "execution": {"readonly": True}},
             {"scope": "fs.read", "execution": {"readonly": False}}, "execution.readonly"),
            ({"scope": "fs.read", "enabled": True},
             {"scope": "fs.read", "enabled": False}, "enabled"),
        ],
    )
    def test_security_fields_never_report_clean_on_a_flip(
        self, baseline_decl, current_decl, expected_field
    ):
        # The generic form of the bug: a loss of restriction on a field that
        # previously escaped the comparison set must now be reported.
        report = DriftDetector().check(
            [make_tool("read_file", baseline_decl)], [make_tool("read_file", current_decl)]
        )

        assert report.drifted is True
        assert expected_field in {i.field for i in report.breaking}