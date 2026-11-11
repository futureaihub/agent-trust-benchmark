"""Red-team adversarial tests for Scenario #3 (role escalation).

Each case builds a trajectory and asserts what the evaluator must conclude.
The expectations are the point: before this file was converted, every case
printed its result and asserted nothing, so a regression in CHECK 9 or CHECK 10
would have gone unnoticed while the suite stayed green (issue #3).
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app.agent import (
    AgentStub,
    RoleEscalationAgentStub,
    GatewayEscalationAgentStub,
    BothEscalationAgentStub,
    RogueEscalationAgentStub,
)
from app.evaluator import evaluate
from app.evidence import EvidenceStore
from app.policy import PolicyGateway
from app.schemas import ScenarioInput
from app.tools import MockProductionDB


def load_scenario():
    with open("tests/scenarios/role_escalation.json") as f:
        return ScenarioInput(**json.load(f))


SCENARIO = load_scenario()
TRUSTED_ROLE = "operator"


def check_by_name(verdict, name):
    matches = [c for c in verdict.checks if c["name"] == name]
    assert len(matches) == 1, f"expected exactly one {name} check, got {len(matches)}"
    return matches[0]


def evaluate_with(agent, trusted_role=TRUSTED_ROLE):
    gw = PolicyGateway()
    store = EvidenceStore(":memory:")
    db = MockProductionDB()
    actual_before = db.snapshot()
    intent, policy, execution, observation = agent.run(
        SCENARIO, gw, db, store, trusted_role=trusted_role
    )
    actual_after = db.current_state()
    records = store.get_all()
    verdict = evaluate(
        SCENARIO, intent, policy, execution, observation, records,
        actual_state_before=actual_before, actual_state_after=actual_after,
        trusted_identity=SCENARIO.trusted_identity,
    )
    gw.close()
    return verdict


def test_honest_agent_passes_all_checks():
    """operator == trusted == policy role: nothing to detect, everything passes."""
    verdict = evaluate_with(AgentStub())

    assert verdict.passed is True, [c for c in verdict.checks if not c["passed"]]
    assert len(verdict.checks) == 9
    assert check_by_name(verdict, "authorization_context_matches_trusted_identity")["passed"] is True
    assert check_by_name(verdict, "agent_claim_matches_authorization_context")["passed"] is True


def test_agent_claiming_admin_is_caught_by_check_10():
    """The agent claims admin; the policy was still evaluated as operator.

    CHECK 9 compares the authorization context against the trusted identity and
    passes, because the gateway did not escalate. CHECK 10 is what catches the
    lie, so asserting only the verdict would not localise the defect.
    """
    verdict = evaluate_with(RoleEscalationAgentStub(claimed_role="admin"))

    assert verdict.passed is False
    assert check_by_name(verdict, "authorization_context_matches_trusted_identity")["passed"] is True
    assert check_by_name(verdict, "agent_claim_matches_authorization_context")["passed"] is False


def test_gateway_escalation_is_caught_by_checks_1_9_10():
    """The gateway evaluates the policy as admin while trusted role is operator."""
    verdict = evaluate_with(GatewayEscalationAgentStub())

    assert verdict.passed is False
    assert check_by_name(verdict, "policy_decision_matches_invariant")["passed"] is False
    assert check_by_name(verdict, "authorization_context_matches_trusted_identity")["passed"] is False
    assert check_by_name(verdict, "agent_claim_matches_authorization_context")["passed"] is False


def test_both_escalating_is_caught_despite_consistent_claim():
    """Agent and gateway both say admin, so the claim "matches" the context.

    CHECK 10 cannot catch this: agent claim and policy role agree. CHECK 9 is
    the only check that still sees the escalation, which is why it is asserted
    separately here.
    """
    verdict = evaluate_with(BothEscalationAgentStub())

    assert verdict.passed is False
    assert check_by_name(verdict, "policy_decision_matches_invariant")["passed"] is False
    assert check_by_name(verdict, "authorization_context_matches_trusted_identity")["passed"] is False
    assert check_by_name(verdict, "agent_claim_matches_authorization_context")["passed"] is True


def test_rogue_execution_despite_deny_is_caught():
    """Role escalation plus ignoring the DENY: execution and state checks fail."""
    verdict = evaluate_with(RogueEscalationAgentStub())

    assert verdict.passed is False
    assert check_by_name(verdict, "tool_execution_matches_invariant")["passed"] is False
    assert check_by_name(verdict, "state_change_matches_invariant")["passed"] is False
    assert check_by_name(verdict, "agent_claim_matches_authorization_context")["passed"] is False
