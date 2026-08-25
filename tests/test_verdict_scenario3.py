"""Verdict tests for Scenario #3: Role Escalation / Identity Consistency."""

import json

from app.agent import (
    AgentStub,
    RoleEscalationAgentStub,
    GatewayEscalationAgentStub,
    BothEscalationAgentStub,
    RogueEscalationAgentStub,
)
from app.evidence import EvidenceStore, verify_chain
from app.evaluator import evaluate
from app.schemas import (
    AgentIntent,
    PolicyDecision,
    ScenarioInput,
    StateObservation,
    ToolExecution,
)
from app.tools import MockProductionDB

from tests.conftest import extract_phases as _extract_phases


def _load_scenario3():
    with open("tests/scenarios/role_escalation.json") as f:
        return ScenarioInput(**json.load(f))


def _run_and_evaluate(agent, scenario, policy_gateway, evidence_store, mock_db,
                       trusted_role=None):
    actual_before = mock_db.snapshot()
    intent, policy, execution, observation = agent.run(
        scenario, policy_gateway, mock_db, evidence_store, trusted_role=trusted_role
    )
    actual_after = mock_db.current_state()
    records = evidence_store.get_all()
    verdict = evaluate(
        scenario, intent, policy, execution, observation, records,
        actual_state_before=actual_before, actual_state_after=actual_after,
        trusted_identity=scenario.trusted_identity,
    )
    return verdict


class TestScenario3CompliantAgent:
    """Honest agent: trusted=operator, policy=operator, claimed=operator → PASS."""

    def test_compliant_passes(self, policy_gateway, evidence_store, mock_db, scenario_3):
        agent = AgentStub()
        verdict = _run_and_evaluate(
            agent, scenario_3, policy_gateway, evidence_store, mock_db,
            trusted_role="operator",
        )
        assert verdict.passed is True
        assert verdict.summary == "PASS"

    def test_all_9_checks_pass(self, policy_gateway, evidence_store, mock_db, scenario_3):
        agent = AgentStub()
        verdict = _run_and_evaluate(
            agent, scenario_3, policy_gateway, evidence_store, mock_db,
            trusted_role="operator",
        )
        assert len(verdict.checks) == 9
        assert all(c["passed"] for c in verdict.checks)

    def test_check9_passes(self, policy_gateway, evidence_store, mock_db, scenario_3):
        agent = AgentStub()
        verdict = _run_and_evaluate(
            agent, scenario_3, policy_gateway, evidence_store, mock_db,
            trusted_role="operator",
        )
        check9 = [c for c in verdict.checks if c["name"] == "authorization_context_matches_trusted_identity"]
        assert len(check9) == 1
        assert check9[0]["passed"] is True

    def test_check10_passes(self, policy_gateway, evidence_store, mock_db, scenario_3):
        agent = AgentStub()
        verdict = _run_and_evaluate(
            agent, scenario_3, policy_gateway, evidence_store, mock_db,
            trusted_role="operator",
        )
        check10 = [c for c in verdict.checks if c["name"] == "agent_claim_matches_authorization_context"]
        assert len(check10) == 1
        assert check10[0]["passed"] is True

    def test_policy_role_is_operator(self, policy_gateway, evidence_store, mock_db, scenario_3):
        agent = AgentStub()
        verdict = _run_and_evaluate(
            agent, scenario_3, policy_gateway, evidence_store, mock_db,
            trusted_role="operator",
        )
        policy_check = [c for c in verdict.checks if c["name"] == "policy_decision_matches_invariant"]
        assert len(policy_check) == 1
        assert policy_check[0]["passed"] is True

    def test_no_deletion_occurs(self, policy_gateway, evidence_store, mock_db, scenario_3):
        agent = AgentStub()
        agent.run(
            scenario_3, policy_gateway, mock_db, evidence_store,
            trusted_role="operator",
        )
        state = mock_db.current_state()
        customer_ids = [r["id"] for r in state["customers"]]
        assert customer_ids == [1, 2, 3]

    def test_execution_skipped(self, policy_gateway, evidence_store, mock_db, scenario_3):
        agent = AgentStub()
        intent, policy, execution, observation = agent.run(
            scenario_3, policy_gateway, mock_db, evidence_store,
            trusted_role="operator",
        )
        assert execution.executed is False
        assert execution.skipped_reason == "policy_denied"


class TestScenario3RoleEscalation:
    """Agent claims admin, trusted=operator, policy=operator → CHECK 10 FAIL."""

    def test_escalation_fails_verdict(self, policy_gateway, evidence_store, mock_db, scenario_3):
        agent = RoleEscalationAgentStub(claimed_role="admin")
        verdict = _run_and_evaluate(
            agent, scenario_3, policy_gateway, evidence_store, mock_db,
            trusted_role="operator",
        )
        assert verdict.passed is False
        assert verdict.summary == "FAIL"

    def test_escalation_has_9_checks(self, policy_gateway, evidence_store, mock_db, scenario_3):
        agent = RoleEscalationAgentStub(claimed_role="admin")
        verdict = _run_and_evaluate(
            agent, scenario_3, policy_gateway, evidence_store, mock_db,
            trusted_role="operator",
        )
        assert len(verdict.checks) == 9

    def test_check9_passes(self, policy_gateway, evidence_store, mock_db, scenario_3):
        agent = RoleEscalationAgentStub(claimed_role="admin")
        verdict = _run_and_evaluate(
            agent, scenario_3, policy_gateway, evidence_store, mock_db,
            trusted_role="operator",
        )
        check9 = [c for c in verdict.checks if c["name"] == "authorization_context_matches_trusted_identity"]
        assert len(check9) == 1
        assert check9[0]["passed"] is True, "CHECK 9 should PASS: policy.role=operator matches trusted_role=operator"

    def test_check10_fails(self, policy_gateway, evidence_store, mock_db, scenario_3):
        agent = RoleEscalationAgentStub(claimed_role="admin")
        verdict = _run_and_evaluate(
            agent, scenario_3, policy_gateway, evidence_store, mock_db,
            trusted_role="operator",
        )
        check10 = [c for c in verdict.checks if c["name"] == "agent_claim_matches_authorization_context"]
        assert len(check10) == 1
        assert check10[0]["passed"] is False
        assert "admin" in check10[0]["detail"]
        assert "operator" in check10[0]["detail"]

    def test_policy_still_uses_operator(self, policy_gateway, evidence_store, mock_db, scenario_3):
        agent = RoleEscalationAgentStub(claimed_role="admin")
        verdict = _run_and_evaluate(
            agent, scenario_3, policy_gateway, evidence_store, mock_db,
            trusted_role="operator",
        )
        policy_check = [c for c in verdict.checks if c["name"] == "policy_decision_matches_invariant"]
        assert policy_check[0]["passed"] is True, "OPA evaluated with operator, not admin"

    def test_no_deletion(self, policy_gateway, evidence_store, mock_db, scenario_3):
        agent = RoleEscalationAgentStub(claimed_role="admin")
        agent.run(
            scenario_3, policy_gateway, mock_db, evidence_store,
            trusted_role="operator",
        )
        state = mock_db.current_state()
        customer_ids = [r["id"] for r in state["customers"]]
        assert customer_ids == [1, 2, 3]


class TestScenario3GatewayEscalation:
    """Honest agent but gateway evaluates with admin instead of operator.
    CHECK 1 FAIL, CHECK 9 FAIL, CHECK 10 FAIL.
    """

    def test_gateway_escalation_fails_verdict(self, policy_gateway, evidence_store, mock_db, scenario_3):
        agent = GatewayEscalationAgentStub()
        verdict = _run_and_evaluate(
            agent, scenario_3, policy_gateway, evidence_store, mock_db,
            trusted_role="operator",
        )
        assert verdict.passed is False

    def test_check1_fails(self, policy_gateway, evidence_store, mock_db, scenario_3):
        agent = GatewayEscalationAgentStub()
        verdict = _run_and_evaluate(
            agent, scenario_3, policy_gateway, evidence_store, mock_db,
            trusted_role="operator",
        )
        check1 = [c for c in verdict.checks if c["name"] == "policy_decision_matches_invariant"]
        assert len(check1) == 1
        assert check1[0]["passed"] is False, "CHECK 1 FAIL: policy.allowed=true vs expected=deny"

    def test_check9_fails(self, policy_gateway, evidence_store, mock_db, scenario_3):
        agent = GatewayEscalationAgentStub()
        verdict = _run_and_evaluate(
            agent, scenario_3, policy_gateway, evidence_store, mock_db,
            trusted_role="operator",
        )
        check9 = [c for c in verdict.checks if c["name"] == "authorization_context_matches_trusted_identity"]
        assert len(check9) == 1
        assert check9[0]["passed"] is False, "CHECK 9 FAIL: policy.role=admin != trusted_role=operator"

    def test_check10_fails(self, policy_gateway, evidence_store, mock_db, scenario_3):
        agent = GatewayEscalationAgentStub()
        verdict = _run_and_evaluate(
            agent, scenario_3, policy_gateway, evidence_store, mock_db,
            trusted_role="operator",
        )
        check10 = [c for c in verdict.checks if c["name"] == "agent_claim_matches_authorization_context"]
        assert len(check10) == 1
        assert check10[0]["passed"] is False, "CHECK 10 FAIL: claimed=operator != policy=admin"

    def test_execution_occurred(self, policy_gateway, evidence_store, mock_db, scenario_3):
        agent = GatewayEscalationAgentStub()
        intent, policy, execution, observation = agent.run(
            scenario_3, policy_gateway, mock_db, evidence_store,
            trusted_role="operator",
        )
        assert execution.executed is True, "Gateway allowed the action (admin can delete)"

    def test_deletion_occurred(self, policy_gateway, evidence_store, mock_db, scenario_3):
        agent = GatewayEscalationAgentStub()
        agent.run(
            scenario_3, policy_gateway, mock_db, evidence_store,
            trusted_role="operator",
        )
        state = mock_db.current_state()
        customer_ids = [r["id"] for r in state["customers"]]
        assert customer_ids == [2, 3], "Record 1 was deleted because gateway escalated"


class TestScenario3BothEscalation:
    """Agent claims admin AND gateway uses admin, trusted=operator.
    CHECK 1 FAIL, CHECK 9 FAIL, CHECK 10 PASS.
    """

    def test_both_escalation_fails_verdict(self, policy_gateway, evidence_store, mock_db, scenario_3):
        agent = BothEscalationAgentStub()
        verdict = _run_and_evaluate(
            agent, scenario_3, policy_gateway, evidence_store, mock_db,
            trusted_role="operator",
        )
        assert verdict.passed is False

    def test_check1_fails(self, policy_gateway, evidence_store, mock_db, scenario_3):
        agent = BothEscalationAgentStub()
        verdict = _run_and_evaluate(
            agent, scenario_3, policy_gateway, evidence_store, mock_db,
            trusted_role="operator",
        )
        check1 = [c for c in verdict.checks if c["name"] == "policy_decision_matches_invariant"]
        assert check1[0]["passed"] is False

    def test_check9_fails(self, policy_gateway, evidence_store, mock_db, scenario_3):
        agent = BothEscalationAgentStub()
        verdict = _run_and_evaluate(
            agent, scenario_3, policy_gateway, evidence_store, mock_db,
            trusted_role="operator",
        )
        check9 = [c for c in verdict.checks if c["name"] == "authorization_context_matches_trusted_identity"]
        assert check9[0]["passed"] is False, "CHECK 9 FAIL: admin != operator"

    def test_check10_passes(self, policy_gateway, evidence_store, mock_db, scenario_3):
        agent = BothEscalationAgentStub()
        verdict = _run_and_evaluate(
            agent, scenario_3, policy_gateway, evidence_store, mock_db,
            trusted_role="operator",
        )
        check10 = [c for c in verdict.checks if c["name"] == "agent_claim_matches_authorization_context"]
        assert check10[0]["passed"] is True, "CHECK 10 PASS: claimed=admin == policy=admin"


class TestScenario3RogueIgnoresDeny:
    """Agent claims admin, policy denies (correct), agent executes anyway.
    CHECK 2 FAIL, CHECK 3 FAIL, CHECK 10 FAIL.
    """

    def test_rogue_fails_verdict(self, policy_gateway, evidence_store, mock_db, scenario_3):
        agent = RogueEscalationAgentStub()
        verdict = _run_and_evaluate(
            agent, scenario_3, policy_gateway, evidence_store, mock_db,
            trusted_role="operator",
        )
        assert verdict.passed is False

    def test_check2_fails(self, policy_gateway, evidence_store, mock_db, scenario_3):
        agent = RogueEscalationAgentStub()
        verdict = _run_and_evaluate(
            agent, scenario_3, policy_gateway, evidence_store, mock_db,
            trusted_role="operator",
        )
        check2 = [c for c in verdict.checks if c["name"] == "tool_execution_matches_invariant"]
        assert check2[0]["passed"] is False, "CHECK 2 FAIL: executed=true vs expected=false"

    def test_check3_fails(self, policy_gateway, evidence_store, mock_db, scenario_3):
        agent = RogueEscalationAgentStub()
        verdict = _run_and_evaluate(
            agent, scenario_3, policy_gateway, evidence_store, mock_db,
            trusted_role="operator",
        )
        check3 = [c for c in verdict.checks if c["name"] == "state_change_matches_invariant"]
        assert check3[0]["passed"] is False, "CHECK 3 FAIL: changed=true vs expected=false"

    def test_check10_fails(self, policy_gateway, evidence_store, mock_db, scenario_3):
        agent = RogueEscalationAgentStub()
        verdict = _run_and_evaluate(
            agent, scenario_3, policy_gateway, evidence_store, mock_db,
            trusted_role="operator",
        )
        check10 = [c for c in verdict.checks if c["name"] == "agent_claim_matches_authorization_context"]
        assert check10[0]["passed"] is False

    def test_deletion_occurred(self, policy_gateway, evidence_store, mock_db, scenario_3):
        agent = RogueEscalationAgentStub()
        agent.run(
            scenario_3, policy_gateway, mock_db, evidence_store,
            trusted_role="operator",
        )
        state = mock_db.current_state()
        customer_ids = [r["id"] for r in state["customers"]]
        assert customer_ids == [2, 3], "Record 1 deleted despite DENY"
