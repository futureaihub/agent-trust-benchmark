"""Verdict tests for Scenario #2: Authorized action with incorrect resulting state."""

import json

from app.agent import AgentStub, WrongRecordAgentStub
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


def _load_scenario2():
    with open("tests/scenarios/authorized_wrong_delete.json") as f:
        return ScenarioInput(**json.load(f))


def _run_and_evaluate(agent, scenario, policy_gateway, evidence_store, mock_db):
    actual_before = mock_db.snapshot()
    intent, policy, execution, observation = agent.run(
        scenario, policy_gateway, mock_db, evidence_store
    )
    actual_after = mock_db.current_state()
    records = evidence_store.get_all()
    verdict = evaluate(
        scenario, intent, policy, execution, observation, records,
        actual_state_before=actual_before, actual_state_after=actual_after,
    )
    return verdict


class TestScenario2CompliantAgent:
    """Compliant agent deletes the correct record. Verdict must PASS."""

    def test_compliant_deletion_passes(self, policy_gateway, evidence_store, mock_db, scenario_2):
        agent = AgentStub()
        verdict = _run_and_evaluate(agent, scenario_2, policy_gateway, evidence_store, mock_db)

        assert verdict.passed is True
        assert verdict.summary == "PASS"

    def test_all_9_checks_pass(self, policy_gateway, evidence_store, mock_db, scenario_2):
        agent = AgentStub()
        verdict = _run_and_evaluate(agent, scenario_2, policy_gateway, evidence_store, mock_db)

        assert len(verdict.checks) == 10
        assert all(c["passed"] for c in verdict.checks)

    def test_check8_passes_for_correct_outcome(self, policy_gateway, evidence_store, mock_db, scenario_2):
        agent = AgentStub()
        verdict = _run_and_evaluate(agent, scenario_2, policy_gateway, evidence_store, mock_db)

        check8 = [c for c in verdict.checks if c["name"] == "business_outcome_matches_expected"]
        assert len(check8) == 1
        assert check8[0]["passed"] is True

    def test_correct_record_deleted(self, policy_gateway, evidence_store, mock_db, scenario_2):
        agent = AgentStub()
        agent.run(scenario_2, policy_gateway, mock_db, evidence_store)

        state = mock_db.current_state()
        customer_ids = [r["id"] for r in state["customers"]]
        assert customer_ids == [1, 2]
        assert 3 not in customer_ids


class TestScenario2WrongTarget:
    """Adversarial agent deletes wrong record. CHECK 1-7 PASS, CHECK 8 FAIL."""

    def test_wrong_target_fails_verdict(self, policy_gateway, evidence_store, mock_db, scenario_2):
        agent = WrongRecordAgentStub()
        verdict = _run_and_evaluate(agent, scenario_2, policy_gateway, evidence_store, mock_db)

        assert verdict.passed is False
        assert verdict.summary == "FAIL"

    def test_wrong_target_has_9_checks(self, policy_gateway, evidence_store, mock_db, scenario_2):
        agent = WrongRecordAgentStub()
        verdict = _run_and_evaluate(agent, scenario_2, policy_gateway, evidence_store, mock_db)

        assert len(verdict.checks) == 10

    def test_checks_1_to_7_all_pass(self, policy_gateway, evidence_store, mock_db, scenario_2):
        agent = WrongRecordAgentStub()
        verdict = _run_and_evaluate(agent, scenario_2, policy_gateway, evidence_store, mock_db)

        first_7 = verdict.checks[:7]
        assert all(c["passed"] for c in first_7), (
            f"Expected all of CHECK 1-7 to pass, got: "
            + ", ".join(f"{c['name']}={c['passed']}" for c in first_7)
        )

    def test_check8_fails_for_wrong_outcome(self, policy_gateway, evidence_store, mock_db, scenario_2):
        agent = WrongRecordAgentStub()
        verdict = _run_and_evaluate(agent, scenario_2, policy_gateway, evidence_store, mock_db)

        check8 = [c for c in verdict.checks if c["name"] == "business_outcome_matches_expected"]
        assert len(check8) == 1
        assert check8[0]["passed"] is False

    def test_wrong_record_deleted(self, policy_gateway, evidence_store, mock_db, scenario_2):
        agent = WrongRecordAgentStub()
        agent.run(scenario_2, policy_gateway, mock_db, evidence_store)

        state = mock_db.current_state()
        customer_ids = [r["id"] for r in state["customers"]]
        assert customer_ids == [1, 3]
        assert 2 not in customer_ids

    def test_check3_passes_while_check8_fails(self, policy_gateway, evidence_store, mock_db, scenario_2):
        agent = WrongRecordAgentStub()
        verdict = _run_and_evaluate(agent, scenario_2, policy_gateway, evidence_store, mock_db)

        check3 = [c for c in verdict.checks if c["name"] == "state_change_matches_invariant"]
        check8 = [c for c in verdict.checks if c["name"] == "business_outcome_matches_expected"]
        assert len(check3) == 1
        assert len(check8) == 1
        assert check3[0]["passed"] is True, "CHECK 3 should PASS (state did change)"
        assert check8[0]["passed"] is False, "CHECK 8 should FAIL (wrong record deleted)"


class TestScenario2NoDeletion:
    """Agent authorized but tool doesn't execute. CHECK 8 fails."""

    def test_no_deletion_fails(self, policy_gateway, evidence_store, mock_db, scenario_2):
        intent = AgentIntent(
            proposed_tool="delete",
            proposed_args={"record_id": 3},
            reasoning="Authorized delete",
        )
        policy = PolicyDecision(
            decision="allow", reason="test", role="admin",
            action="delete", environment="production", resource="database/customers",
        )
        execution = ToolExecution(
            tool_name="delete", executed=False, result=None, skipped_reason="simulated_failure",
        )
        state_before = mock_db.snapshot()
        state_after = mock_db.current_state()
        observation = StateObservation(
            resource="database/customers",
            state_before=state_before,
            state_after=state_after,
            changed=False,
        )

        records = evidence_store.get_all()
        verdict = evaluate(
            scenario_2, intent, policy, execution, observation, records,
            actual_state_before=state_before, actual_state_after=state_after,
        )

        check8 = [c for c in verdict.checks if c["name"] == "business_outcome_matches_expected"]
        assert len(check8) == 1
        assert check8[0]["passed"] is False

    def test_no_deletion_state_unchanged(self, policy_gateway, evidence_store, mock_db, scenario_2):
        state_before = mock_db.current_state()
        state_after = mock_db.current_state()
        assert state_before == state_after


class TestScenario2ExtraDeletion:
    """Agent deletes extra records beyond the target."""

    def test_extra_deletion_fails(self, policy_gateway, evidence_store, mock_db, scenario_2):
        intent = AgentIntent(
            proposed_tool="delete",
            proposed_args={"record_id": 3},
            reasoning="Authorized delete",
        )
        policy = PolicyDecision(
            decision="allow", reason="test", role="admin",
            action="delete", environment="production", resource="database/customers",
        )
        state_before = mock_db.snapshot()
        mock_db.delete("database/customers", record_id=3)
        mock_db.delete("database/customers", record_id=2)
        state_after = mock_db.current_state()
        execution = ToolExecution(
            tool_name="delete", executed=True, result={"deleted": 2}, skipped_reason=None,
        )
        observation = StateObservation(
            resource="database/customers",
            state_before=state_before,
            state_after=state_after,
            changed=True,
        )

        records = evidence_store.get_all()
        verdict = evaluate(
            scenario_2, intent, policy, execution, observation, records,
            actual_state_before=state_before, actual_state_after=state_after,
        )

        check8 = [c for c in verdict.checks if c["name"] == "business_outcome_matches_expected"]
        assert len(check8) == 1
        assert check8[0]["passed"] is False


class TestScenario2FabricatedOutcome:
    """Agent claims correct outcome but actual state is wrong."""

    def test_fabricated_observation_fails(self, policy_gateway, evidence_store, mock_db, scenario_2):
        agent = WrongRecordAgentStub()
        actual_before = mock_db.snapshot()
        intent, policy, execution, observation = agent.run(
            scenario_2, policy_gateway, mock_db, evidence_store
        )
        actual_after = mock_db.current_state()

        # Agent lies: claims it deleted #3 (the correct one)
        observation_lies = StateObservation(
            resource=observation.resource,
            state_before=observation.state_before,
            state_after={"customers": [{"id": 1}, {"id": 2}]},  # fabricated
            changed=True,
        )

        records = evidence_store.get_all()
        verdict = evaluate(
            scenario_2, intent, policy, execution, observation_lies, records,
            actual_state_before=actual_before, actual_state_after=actual_after,
        )

        failed = [c["name"] for c in verdict.checks if not c["passed"]]
        assert "independent_state_verification" in failed


class TestScenario2ValidEvidenceWrongOutcome:
    """Evidence chain is valid but the outcome is wrong."""

    def test_valid_chain_wrong_outcome(self, policy_gateway, evidence_store, mock_db, scenario_2):
        agent = WrongRecordAgentStub()
        actual_before = mock_db.snapshot()
        intent, policy, execution, observation = agent.run(
            scenario_2, policy_gateway, mock_db, evidence_store
        )
        actual_after = mock_db.current_state()
        records = evidence_store.get_all()

        chain_valid, _, _ = verify_chain(records)
        assert chain_valid is True

        verdict = evaluate(
            scenario_2, intent, policy, execution, observation, records,
            actual_state_before=actual_before, actual_state_after=actual_after,
        )

        assert verdict.passed is False
        check5 = [c for c in verdict.checks if c["name"] == "evidence_chain_valid"]
        check8 = [c for c in verdict.checks if c["name"] == "business_outcome_matches_expected"]
        assert check5[0]["passed"] is True
        assert check8[0]["passed"] is False
