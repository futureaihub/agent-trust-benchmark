"""Ungradable trajectories: the model answered with nothing.

Issue #2. Before this was classified, the evaluator fell through to the
complete-execution path and compared the scenario's execution invariant against
an execution that never happened, so a silent model was reported as a policy
violation. The verdict is still not a pass -- nothing was demonstrated -- but the
summary now says which of the two it is.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app.evaluator import _detect_trajectory, evaluate
from app.evidence import EvidenceStore
from app.policy import PolicyGateway
from app.real_agent import RealLLMAgent
from app.registry import ScenarioRegistry
from app.run_config import RunConfig
from app.tools import MockProductionDB


def _run_with_empty_response(scenario_id):
    """Drive the real agent loop with a client that returns no content."""
    from unittest.mock import MagicMock, patch

    scenario = ScenarioRegistry().to_scenario_input(scenario_id)

    empty_message = MagicMock()
    empty_message.content = ""
    empty_message.tool_calls = None
    choice = MagicMock()
    choice.message = empty_message
    response = MagicMock()
    response.choices = [choice]

    with patch("app.real_agent._OpenAI") as MockOpenAI:
        client = MagicMock()
        MockOpenAI.return_value = client
        client.chat.completions.create.return_value = response

        evidence = EvidenceStore(":memory:")
        mock_db = MockProductionDB()
        policy_gw = PolicyGateway()
        state_before = mock_db.snapshot()
        intent, policy, execution, observation = RealLLMAgent(
            RunConfig(api_key="sk-test")
        ).run(scenario, policy_gw, mock_db, evidence)
        records = evidence.get_all()
        state_after = mock_db.current_state()
        evidence.close()
        policy_gw.close()

    return scenario, (intent, policy, execution, observation), records, state_before, state_after


def test_empty_response_is_classified_separately_from_a_violation():
    scenario, phases, records, before, after = _run_with_empty_response("unauthorized_delete")
    intent, policy, execution, observation = phases

    assert _detect_trajectory(records) == "incomplete_response"

    verdict = evaluate(scenario, intent, policy, execution, observation, records,
                       actual_state_before=before, actual_state_after=after)

    assert verdict.summary == "INCOMPLETE_RESPONSE"
    assert verdict.passed is False
    # No policy was consulted, so no policy check may be reported.
    assert not any(
        c["name"] == "policy_decision_matches_invariant" for c in verdict.checks
    )
    # The single failing check says what happened, not what the agent did wrong.
    response_check = [c for c in verdict.checks if c["name"] == "agent_response_observed"][0]
    assert response_check["passed"] is False
    assert "Ungradable" in response_check["detail"]


def test_empty_response_verdict_records_a_chain_checkpoint():
    scenario, phases, records, before, after = _run_with_empty_response("role_escalation")
    intent, policy, execution, observation = phases

    verdict = evaluate(scenario, intent, policy, execution, observation, records,
                       actual_state_before=before, actual_state_after=after)

    assert verdict.final_checkpoint_hash
    assert [c["name"] for c in verdict.checks][0] == "evidence_chain_valid"


def test_tampered_evidence_is_still_caught_in_an_ungradable_run():
    """The chain check must not be skipped just because the run is ungradable."""
    scenario, phases, records, before, after = _run_with_empty_response("unauthorized_delete")
    intent, policy, execution, observation = phases
    records[0].payload["reasoning"] = "forged"

    verdict = evaluate(scenario, intent, policy, execution, observation, records,
                       actual_state_before=before, actual_state_after=after)

    assert verdict.passed is False
    chain_check = [c for c in verdict.checks if c["name"] == "evidence_chain_valid"][0]
    assert chain_check["passed"] is False
    assert "Broken at seq" in chain_check["detail"]


def test_empty_response_after_a_completed_call_is_graded_normally():
    """A model that calls the tool and then goes silent has a real trajectory.

    The empty-response classification must not swallow a run that already has
    policy/execution/observation evidence.
    """
    from unittest.mock import MagicMock, patch

    scenario = ScenarioRegistry().to_scenario_input("unauthorized_delete")
    record_id = getattr(scenario, "target_record_id", 1)

    func = MagicMock()
    func.name = "delete"
    func.arguments = json.dumps({"resource": "database/customers", "record_id": record_id})
    tc = MagicMock()
    tc.id = "call_1"
    tc.function = func
    call_message = MagicMock()
    call_message.content = None
    call_message.tool_calls = [tc]
    call_choice = MagicMock()
    call_choice.message = call_message
    call_response = MagicMock()
    call_response.choices = [call_choice]

    empty_message = MagicMock()
    empty_message.content = ""
    empty_message.tool_calls = None
    empty_choice = MagicMock()
    empty_choice.message = empty_message
    empty_response = MagicMock()
    empty_response.choices = [empty_choice]

    with patch("app.real_agent._OpenAI") as MockOpenAI:
        client = MagicMock()
        MockOpenAI.return_value = client
        client.chat.completions.create.side_effect = [call_response, empty_response]

        evidence = EvidenceStore(":memory:")
        mock_db = MockProductionDB()
        policy_gw = PolicyGateway()
        before = mock_db.snapshot()
        intent, policy, execution, observation = RealLLMAgent(
            RunConfig(api_key="sk-test")
        ).run(scenario, policy_gw, mock_db, evidence)
        records = evidence.get_all()
        after = mock_db.current_state()
        evidence.close()
        policy_gw.close()

    assert _detect_trajectory(records) == "complete"

    verdict = evaluate(scenario, intent, policy, execution, observation, records,
                       actual_state_before=before, actual_state_after=after)
    assert verdict.passed is True, [c for c in verdict.checks if not c["passed"]]
