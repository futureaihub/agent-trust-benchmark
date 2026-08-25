"""Tests for V2 ToolGateway — policy enforcement and tool execution."""

import pytest

from app.agent import AgentStub
from app.evidence import EvidenceStore, verify_chain
from app.evaluator import evaluate
from app.policy import PolicyGateway
from app.schemas import (
    AgentIntent,
    ScenarioInput,
)
from app.tool_gateway import ToolGateway
from app.tools import MockProductionDB


class TestToolGatewayPolicy:
    """Verify policy is evaluated before execution."""

    def test_denied_tool_does_not_execute(self, scenario_1):
        gw = PolicyGateway()
        db = MockProductionDB()
        ev = EvidenceStore(":memory:")
        gateway = ToolGateway(gw, db, ev)

        state_before = db.snapshot()
        policy = gateway.evaluate_policy(scenario_1)
        execution = gateway.execute_tool(scenario_1, policy)

        assert policy.decision == "deny"
        assert execution.executed is False
        assert execution.skipped_reason == "policy_denied"

        ev.close()
        gw.close()

    def test_allowed_tool_executes(self, scenario_2):
        gw = PolicyGateway()
        db = MockProductionDB()
        ev = EvidenceStore(":memory:")
        gateway = ToolGateway(gw, db, ev)

        policy = gateway.evaluate_policy(scenario_2)
        execution = gateway.execute_tool(scenario_2, policy)

        assert policy.decision == "allow"
        assert execution.executed is True
        assert execution.result is not None

        ev.close()
        gw.close()

    def test_policy_evaluated_before_execution(self, scenario_1):
        gw = PolicyGateway()
        db = MockProductionDB()
        ev = EvidenceStore(":memory:")
        gateway = ToolGateway(gw, db, ev)

        policy = gateway.evaluate_policy(scenario_1)
        state_before = db.snapshot()
        execution = gateway.execute_tool(scenario_1, policy)
        observation = gateway.observe_state(scenario_1, state_before)

        records = ev.get_all()
        # Find sequence numbers
        policy_seq = None
        execution_seq = None
        for rec in records:
            if rec.event_type == "policy_check":
                policy_seq = rec.seq
            if rec.event_type == "tool_execution":
                execution_seq = rec.seq

        assert policy_seq is not None
        assert execution_seq is not None
        assert policy_seq < execution_seq

        ev.close()
        gw.close()

    def test_tool_arguments_preserved(self, scenario_2):
        gw = PolicyGateway()
        db = MockProductionDB()
        ev = EvidenceStore(":memory:")
        gateway = ToolGateway(gw, db, ev)

        policy = gateway.evaluate_policy(scenario_2)
        execution = gateway.execute_tool(scenario_2, policy)

        # Verify the tool was called with the right arguments
        assert execution.tool_name == "delete"
        assert execution.result["resource"] == scenario_2.target_resource

        ev.close()
        gw.close()

    def test_tool_result_captured(self, scenario_2):
        gw = PolicyGateway()
        db = MockProductionDB()
        ev = EvidenceStore(":memory:")
        gateway = ToolGateway(gw, db, ev)

        policy = gateway.evaluate_policy(scenario_2)
        execution = gateway.execute_tool(scenario_2, policy)

        assert execution.result is not None
        assert "status" in execution.result
        assert "rows_affected" in execution.result

        ev.close()
        gw.close()


class TestToolGatewayState:
    """Verify state observation through the gateway."""

    def test_state_captured_before_and_after(self, scenario_2):
        gw = PolicyGateway()
        db = MockProductionDB()
        ev = EvidenceStore(":memory:")
        gateway = ToolGateway(gw, db, ev)

        state_before = db.snapshot()
        policy = gateway.evaluate_policy(scenario_2)
        execution = gateway.execute_tool(scenario_2, policy)
        observation = gateway.observe_state(scenario_2, state_before)

        # State should have changed (admin delete is allowed)
        assert observation.changed is True
        assert observation.state_before != observation.state_after

        ev.close()
        gw.close()

    def test_state_unchanged_on_deny(self, scenario_1):
        gw = PolicyGateway()
        db = MockProductionDB()
        ev = EvidenceStore(":memory:")
        gateway = ToolGateway(gw, db, ev)

        state_before = db.snapshot()
        policy = gateway.evaluate_policy(scenario_1)
        execution = gateway.execute_tool(scenario_1, policy)
        observation = gateway.observe_state(scenario_1, state_before)

        assert observation.changed is False

        ev.close()
        gw.close()


class TestToolGatewayFullExecution:
    """Verify the high-level execute() method."""

    def test_full_execute_deny(self, scenario_1):
        gw = PolicyGateway()
        db = MockProductionDB()
        ev = EvidenceStore(":memory:")
        gateway = ToolGateway(gw, db, ev)

        intent = AgentIntent(
            proposed_tool="delete",
            proposed_args={"resource": scenario_1.target_resource},
            reasoning="test",
            claimed_role=scenario_1.user_role,
        )
        ev.append("agent_intent", intent.model_dump())

        policy, execution, observation = gateway.execute(scenario_1, intent)

        assert policy.decision == "deny"
        assert execution.executed is False
        assert observation.changed is False

        records = ev.get_all()
        assert len(records) == 4  # intent + policy + execution + observation
        chain_valid, _, _ = verify_chain(records)
        assert chain_valid

        ev.close()
        gw.close()

    def test_full_execute_allow(self, scenario_2):
        gw = PolicyGateway()
        db = MockProductionDB()
        ev = EvidenceStore(":memory:")
        gateway = ToolGateway(gw, db, ev)

        intent = AgentIntent(
            proposed_tool="delete",
            proposed_args={"resource": scenario_2.target_resource},
            reasoning="test",
            claimed_role=scenario_2.user_role,
        )
        ev.append("agent_intent", intent.model_dump())

        policy, execution, observation = gateway.execute(scenario_2, intent)

        assert policy.decision == "allow"
        assert execution.executed is True
        assert observation.changed is True

        ev.close()
        gw.close()

    def test_full_execute_with_trusted_role(self, scenario_3):
        gw = PolicyGateway()
        db = MockProductionDB()
        ev = EvidenceStore(":memory:")
        gateway = ToolGateway(gw, db, ev)

        intent = AgentIntent(
            proposed_tool="delete",
            proposed_args={"resource": scenario_3.target_resource},
            reasoning="test",
            claimed_role="admin",
        )
        ev.append("agent_intent", intent.model_dump())

        policy, execution, observation = gateway.execute(
            scenario_3, intent, trusted_role="operator"
        )

        assert policy.decision == "deny"
        assert execution.executed is False

        ev.close()
        gw.close()


class TestToolGatewayEvidenceIntegrity:
    """Verify evidence chain integrity through the gateway."""

    def test_evidence_chain_valid_after_deny(self, scenario_1):
        gw = PolicyGateway()
        db = MockProductionDB()
        ev = EvidenceStore(":memory:", run_id="gateway_test")
        gateway = ToolGateway(gw, db, ev)

        intent = AgentIntent(
            proposed_tool="delete",
            proposed_args={"resource": scenario_1.target_resource},
            reasoning="test",
            claimed_role=scenario_1.user_role,
        )
        ev.append("agent_intent", intent.model_dump())

        gateway.execute(scenario_1, intent)

        records = ev.get_all()
        chain_valid, _, _ = verify_chain(records)
        assert chain_valid

        ev.close()
        gw.close()

    def test_evidence_chain_valid_after_allow(self, scenario_2):
        gw = PolicyGateway()
        db = MockProductionDB()
        ev = EvidenceStore(":memory:", run_id="gateway_test_allow")
        gateway = ToolGateway(gw, db, ev)

        intent = AgentIntent(
            proposed_tool="delete",
            proposed_args={"resource": scenario_2.target_resource},
            reasoning="test",
            claimed_role=scenario_2.user_role,
        )
        ev.append("agent_intent", intent.model_dump())

        gateway.execute(scenario_2, intent)

        records = ev.get_all()
        chain_valid, _, _ = verify_chain(records)
        assert chain_valid

        ev.close()
        gw.close()

    def test_gateway_produces_valid_verdict(self, scenario_1):
        gw = PolicyGateway()
        db = MockProductionDB()
        ev = EvidenceStore(":memory:")
        gateway = ToolGateway(gw, db, ev)

        intent = AgentIntent(
            proposed_tool="delete",
            proposed_args={"resource": scenario_1.target_resource},
            reasoning="test",
            claimed_role=scenario_1.user_role,
        )
        ev.append("agent_intent", intent.model_dump())

        policy, execution, observation = gateway.execute(scenario_1, intent)

        records = ev.get_all()
        actual_after = db.current_state()

        verdict = evaluate(
            scenario_1, intent, policy, execution, observation, records,
            actual_state_after=actual_after,
        )

        assert verdict.passed is True

        ev.close()
        gw.close()
