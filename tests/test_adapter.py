"""Tests for V2 AgentAdapter — protocol conformance and ScriptedAdapter."""

import json

import pytest

from app.adapter import AgentAdapter, ScriptedAdapter
from app.agent import (
    AgentStub,
    BothEscalationAgentStub,
    GatewayEscalationAgentStub,
    RoleEscalationAgentStub,
    RogueAgentStub,
    RogueEscalationAgentStub,
    WrongRecordAgentStub,
)
from app.evidence import EvidenceStore, verify_chain
from app.evaluator import evaluate
from app.policy import PolicyGateway
from app.schemas import ScenarioInput
from app.tools import MockProductionDB


class TestAgentAdapterProtocol:
    """Verify that AgentAdapter is a proper protocol."""

    def test_scripted_adapter_satisfies_protocol(self):
        stub = AgentStub()
        adapter = ScriptedAdapter(stub)
        assert isinstance(adapter, AgentAdapter)

    def test_rogue_adapter_satisfies_protocol(self):
        stub = RogueAgentStub()
        adapter = ScriptedAdapter(stub)
        assert isinstance(adapter, AgentAdapter)

    def test_role_escalation_adapter_satisfies_protocol(self):
        stub = RoleEscalationAgentStub()
        adapter = ScriptedAdapter(stub)
        assert isinstance(adapter, AgentAdapter)

    def test_wrong_record_adapter_satisfies_protocol(self):
        stub = WrongRecordAgentStub()
        adapter = ScriptedAdapter(stub)
        assert isinstance(adapter, AgentAdapter)

    def test_gateway_escalation_adapter_satisfies_protocol(self):
        stub = GatewayEscalationAgentStub()
        adapter = ScriptedAdapter(stub)
        assert isinstance(adapter, AgentAdapter)

    def test_both_escalation_adapter_satisfies_protocol(self):
        stub = BothEscalationAgentStub()
        adapter = ScriptedAdapter(stub)
        assert isinstance(adapter, AgentAdapter)

    def test_rogue_escalation_adapter_satisfies_protocol(self):
        stub = RogueEscalationAgentStub()
        adapter = ScriptedAdapter(stub)
        assert isinstance(adapter, AgentAdapter)


class TestScriptedAdapterExecution:
    """Verify ScriptedAdapter produces same results as direct V1 stub."""

    def test_adapter_output_matches_direct_stub(self, scenario_1):
        gw = PolicyGateway()
        db = MockProductionDB()
        ev = EvidenceStore(":memory:")
        stub = AgentStub()
        adapter = ScriptedAdapter(stub)

        # Run through adapter
        a_intent, a_policy, a_exec, a_obs = adapter.run(
            scenario_1, gw, db, ev, trusted_role=None
        )

        # Verify structure
        assert a_intent.proposed_tool is not None
        assert a_policy.decision in ("allow", "deny")
        assert isinstance(a_exec.executed, bool)
        assert isinstance(a_obs.changed, bool)

        # Verify evidence chain
        records = ev.get_all()
        assert len(records) == 4
        chain_valid, _, _ = verify_chain(records)
        assert chain_valid

        ev.close()
        gw.close()

    def test_adapter_produces_valid_verdict(self, scenario_1):
        gw = PolicyGateway()
        db = MockProductionDB()
        ev = EvidenceStore(":memory:")
        adapter = ScriptedAdapter(AgentStub())

        intent, policy, execution, observation = adapter.run(
            scenario_1, gw, db, ev, trusted_role=None
        )
        records = ev.get_all()
        actual_before = db.snapshot()  # State didn't change

        verdict = evaluate(
            scenario_1, intent, policy, execution, observation, records,
            actual_state_after=actual_before,
        )

        # Unauthorized delete should PASS (agent correctly denied)
        assert verdict.passed is True

        ev.close()
        gw.close()

    def test_adapter_rogue_detected(self, scenario_1):
        gw = PolicyGateway()
        db = MockProductionDB()
        ev = EvidenceStore(":memory:")
        adapter = ScriptedAdapter(RogueAgentStub())

        intent, policy, execution, observation = adapter.run(
            scenario_1, gw, db, ev, trusted_role=None
        )
        records = ev.get_all()

        verdict = evaluate(
            scenario_1, intent, policy, execution, observation, records,
        )

        # Rogue agent should FAIL
        assert verdict.passed is False

        ev.close()
        gw.close()

    def test_adapter_agent_type_property(self):
        stub = AgentStub()
        adapter = ScriptedAdapter(stub)
        assert adapter.agent_type == "AgentStub"

    def test_adapter_rogue_agent_type_property(self):
        stub = RogueAgentStub()
        adapter = ScriptedAdapter(stub)
        assert adapter.agent_type == "RogueAgentStub"
