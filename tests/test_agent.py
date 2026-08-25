"""Integration tests for agent execution flow."""

from app.agent import AgentStub, RogueAgentStub
from app.evidence import verify_chain
from app.evaluator import evaluate


class TestAgentExecution:
    """Verify the agent follows the execution model correctly."""

    def test_unauthorized_delete_is_denied(self, policy_gateway, evidence_store, mock_db, scenario_1):
        agent = AgentStub()
        intent, policy, execution, observation = agent.run(
            scenario_1, policy_gateway, mock_db, evidence_store
        )
        assert policy.decision == "deny"
        assert execution.executed is False
        assert execution.skipped_reason == "policy_denied"
        assert observation.changed is False

    def test_unauthorized_delete_does_not_change_state(self, policy_gateway, evidence_store, mock_db, scenario_1):
        state_before = mock_db.snapshot()
        agent = AgentStub()
        agent.run(scenario_1, policy_gateway, mock_db, evidence_store)
        state_after = mock_db.current_state()
        assert state_before == state_after

    def test_unauthorized_delete_records_all_phases(self, policy_gateway, evidence_store, mock_db, scenario_1):
        agent = AgentStub()
        agent.run(scenario_1, policy_gateway, mock_db, evidence_store)

        records = evidence_store.get_all()
        event_types = [r.event_type for r in records]
        assert "agent_intent" in event_types
        assert "policy_check" in event_types
        assert "tool_execution" in event_types
        assert "state_observation" in event_types

    def test_unauthorized_delete_evidence_chain_valid(self, policy_gateway, evidence_store, mock_db, scenario_1):
        agent = AgentStub()
        agent.run(scenario_1, policy_gateway, mock_db, evidence_store)
        records = evidence_store.get_all()
        valid, _, _ = verify_chain(records)
        assert valid is True

    def test_rogue_agent_calls_delete_despite_deny(self, policy_gateway, evidence_store, mock_db, scenario_1):
        agent = RogueAgentStub()
        intent, policy, execution, observation = agent.run(
            scenario_1, policy_gateway, mock_db, evidence_store
        )
        # Policy denied, but rogue agent executed anyway
        assert policy.decision == "deny"
        assert execution.executed is True
        assert observation.changed is True

    def test_rogue_agent_state_changed(self, policy_gateway, evidence_store, mock_db, scenario_1):
        state_before = mock_db.snapshot()
        agent = RogueAgentStub()
        agent.run(scenario_1, policy_gateway, mock_db, evidence_store)
        state_after = mock_db.current_state()
        assert state_before != state_after
