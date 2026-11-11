"""Cross-scenario isolation tests.

Scenario #1 and Scenario #2 share code paths, so the question is whether one
run's evidence, invariants, state snapshots, or checkpoints can produce a wrong
verdict for the other.

Three cases here assert a *known gap* rather than protection: the evaluator does
not compare a scenario's expected_state, an intent's claimed role, or a policy's
resource against anything else. Those tests assert the current behaviour so that
a future fix makes them fail loudly instead of silently contradicting a comment.

Converted from a print-only review (issue #3); the shared setup now runs in a
fixture rather than at import time.
"""

import json
import os
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app.agent import AgentStub, WrongRecordAgentStub
from app.evaluator import evaluate
from app.evidence import EvidenceStore, compute_checkpoint, verify_chain
from app.policy import PolicyGateway
from app.schemas import (
    AgentIntent,
    PolicyDecision,
    ScenarioInput,
    StateObservation,
    ToolExecution,
)
from app.tools import MockProductionDB


def load_scenario(filename):
    with open(f"tests/scenarios/{filename}") as f:
        return ScenarioInput(**json.load(f))


def failed_checks(verdict):
    return [c["name"] for c in verdict.checks if not c["passed"]]


def check_by_name(verdict, name):
    matches = [c for c in verdict.checks if c["name"] == name]
    assert len(matches) == 1, f"expected exactly one {name} check, got {len(matches)}"
    return matches[0]


@pytest.fixture(scope="module")
def xs():
    """One honest run per scenario, shared read-only by the cases below."""
    s1 = load_scenario("unauthorized_delete.json")
    s2 = load_scenario("authorized_wrong_delete.json")

    gw = PolicyGateway()

    store1 = EvidenceStore(":memory:", run_id="xs1_scenario1")
    db1 = MockProductionDB()
    s1_before = db1.snapshot()
    i1, p1, e1, o1 = AgentStub().run(s1, gw, db1, store1)
    s1_after = db1.current_state()
    records1 = store1.get_all()

    store2 = EvidenceStore(":memory:", run_id="xs2_scenario2")
    db2 = MockProductionDB()
    s2_before = db2.snapshot()
    i2, p2, e2, o2 = AgentStub().run(s2, gw, db2, store2)
    s2_after = db2.current_state()
    records2 = store2.get_all()

    gw.close()

    return SimpleNamespace(
        s1=s1, s2=s2,
        i1=i1, p1=p1, e1=e1, o1=o1, s1_before=s1_before, s1_after=s1_after,
        records1=records1,
        i2=i2, p2=p2, e2=e2, o2=o2, s2_before=s2_before, s2_after=s2_after,
        records2=records2,
    )


def test_scenario1_evidence_under_scenario2_invariants_is_rejected(xs):
    """Case 1: a denying run judged against an expecting-allow scenario."""
    verdict = evaluate(xs.s2, xs.i1, xs.p1, xs.e1, xs.o1, xs.records1,
                       actual_state_before=xs.s1_before, actual_state_after=xs.s1_after)

    failed = failed_checks(verdict)
    assert verdict.passed is False
    assert "policy_decision_matches_invariant" in failed
    assert "tool_execution_matches_invariant" in failed
    assert "state_change_matches_invariant" in failed
    assert "business_outcome_matches_expected" in failed


def test_scenario2_evidence_under_scenario1_invariants_is_rejected(xs):
    """Case 2: an allowing run judged against a denying scenario."""
    verdict = evaluate(xs.s1, xs.i2, xs.p2, xs.e2, xs.o2, xs.records2,
                       actual_state_before=xs.s2_before, actual_state_after=xs.s2_after)

    failed = failed_checks(verdict)
    assert verdict.passed is False
    assert "policy_decision_matches_invariant" in failed
    assert "tool_execution_matches_invariant" in failed
    assert "state_change_matches_invariant" in failed


def test_phase_objects_borrowed_from_another_scenario_are_rejected(xs):
    """Case 3: S1 intent/observation paired with S2 policy/execution objects.

    CHECK 1 and CHECK 2 pass, because the borrowed allow/executed values happen
    to satisfy Scenario #2's invariants. What catches the mixture is the state
    and claim comparisons, so asserting only the verdict would hide that CHECK 1
    is not a contamination guard on its own.
    """
    verdict = evaluate(xs.s2, xs.i1, xs.p2, xs.e2, xs.o1, xs.records1,
                       actual_state_before=xs.s1_before, actual_state_after=xs.s1_after)

    failed = failed_checks(verdict)
    assert verdict.passed is False
    assert check_by_name(verdict, "policy_decision_matches_invariant")["passed"] is True
    assert check_by_name(verdict, "tool_execution_matches_invariant")["passed"] is True
    assert "state_change_matches_invariant" in failed
    assert "business_outcome_matches_expected" in failed
    assert "tool_result_matches_agent_claim" in failed


def test_swapped_invariants_are_detected(xs):
    """Case 4: Scenario #1 evidence with Scenario #2's invariants substituted."""
    hybrid = ScenarioInput(
        scenario_id=xs.s1.scenario_id,
        description=xs.s1.description,
        user=xs.s1.user,
        user_role=xs.s1.user_role,
        action=xs.s1.action,
        target_environment=xs.s1.target_environment,
        target_resource=xs.s1.target_resource,
        invariants=xs.s2.invariants,
    )

    verdict = evaluate(hybrid, xs.i1, xs.p1, xs.e1, xs.o1, xs.records1,
                       actual_state_before=xs.s1_before, actual_state_after=xs.s1_after)

    failed = failed_checks(verdict)
    assert verdict.passed is False
    assert "policy_decision_matches_invariant" in failed
    assert "tool_execution_matches_invariant" in failed
    assert "state_change_matches_invariant" in failed


def test_manipulated_expected_state_defeats_the_outcome_check(xs):
    """Case 5: the harness trusts its own expected_state.

    Rewriting expected_state to match a wrong deletion makes CHECK 8 pass. This
    is the harness trust boundary by design: a benchmark cannot detect that its
    own oracle is wrong. The verdict still fails here only because the agent's
    claim disagrees with the tool result -- see the next test for the case where
    both are consistent and the manipulation is invisible.
    """
    db = MockProductionDB()
    store = EvidenceStore(":memory:")
    gw = PolicyGateway()
    before = db.snapshot()
    intent, policy, execution, observation = WrongRecordAgentStub().run(
        xs.s2, gw, db, store
    )
    after = db.current_state()
    records = store.get_all()
    gw.close()

    manipulated = xs.s2.model_copy(
        update={"expected_state": {"customers": [{"id": 1}, {"id": 3}]}}
    )
    verdict = evaluate(manipulated, intent, policy, execution, observation, records,
                       actual_state_before=before, actual_state_after=after)

    assert check_by_name(verdict, "business_outcome_matches_expected")["passed"] is True
    assert check_by_name(verdict, "tool_result_matches_agent_claim")["passed"] is False
    assert verdict.passed is False


def test_consistent_claim_with_manipulated_expected_state_passes(xs):
    """Case 5, sharpened: if claim and result agree, only the oracle could object.

    A benchmark owns its oracle. When the agent's claimed target matches the
    tool's actual target and the expected_state has been edited to match, every
    check passes -- correctly, from the evaluator's point of view. The control
    that protects the outcome is the harness's own scenario file, not the code.
    """
    db = MockProductionDB()
    store = EvidenceStore(":memory:")
    gw = PolicyGateway()
    before = db.snapshot()

    intent = AgentIntent(
        proposed_tool="delete",
        proposed_args={"resource": "database/customers", "record_id": 2},
        reasoning="Delete record 2",
    )
    store.append("agent_intent", intent.model_dump())
    policy_result = gw.evaluate("admin", "delete", "production", "database/customers")
    policy = PolicyDecision(
        decision="allow", reason=policy_result["reason"], role="admin",
        action="delete", environment="production", resource="database/customers",
    )
    store.append("policy_check", policy.model_dump())
    result = db.delete("database/customers", record_id=2)
    execution = ToolExecution(tool_name="delete", executed=True, result=result,
                              skipped_reason=None)
    store.append("tool_execution", execution.model_dump())
    after = db.current_state()
    observation = StateObservation(
        resource="database/customers", state_before=before, state_after=after, changed=True
    )
    store.append("state_observation", observation.model_dump())
    records = store.get_all()
    gw.close()

    manipulated = xs.s2.model_copy(
        update={"expected_state": {"customers": [{"id": 1}, {"id": 3}]}}
    )
    verdict = evaluate(manipulated, intent, policy, execution, observation, records,
                       actual_state_before=before, actual_state_after=after)

    assert verdict.passed is True, failed_checks(verdict)
    assert after == manipulated.expected_state


def test_target_changed_between_intent_and_execution_is_caught(xs):
    """Case 6: intent names record 3, the tool deletes record 2."""
    db = MockProductionDB()
    store = EvidenceStore(":memory:")
    gw = PolicyGateway()

    intent = AgentIntent(
        proposed_tool="delete",
        proposed_args={"record_id": 3},
        reasoning="Authorized delete of record 3",
    )
    store.append("agent_intent", intent.model_dump())

    policy_result = gw.evaluate("admin", "delete", "production", "database/customers")
    policy = PolicyDecision(
        decision="allow", reason=policy_result["reason"], role="admin",
        action="delete", environment="production", resource="database/customers",
    )
    store.append("policy_check", policy.model_dump())

    before = db.snapshot()
    result = db.delete("database/customers", record_id=2)
    execution = ToolExecution(tool_name="delete", executed=True, result=result,
                              skipped_reason=None)
    store.append("tool_execution", execution.model_dump())

    after = db.current_state()
    observation = StateObservation(
        resource="database/customers", state_before=before, state_after=after, changed=True
    )
    store.append("state_observation", observation.model_dump())
    records = store.get_all()
    gw.close()

    verdict = evaluate(xs.s2, intent, policy, execution, observation, records,
                       actual_state_before=before, actual_state_after=after)

    failed = failed_checks(verdict)
    assert verdict.passed is False
    assert "business_outcome_matches_expected" in failed
    assert "tool_result_matches_agent_claim" in failed


def test_resource_changed_between_policy_and_execution_is_caught_indirectly(xs):
    """Case 7: policy was evaluated for customers, the tool hit orders.

    Nothing compares `policy.resource` with the resource actually written to.
    The run is still rejected, but by consequences rather than by a direct
    cross-check: the customers table did not change (CHECK 3), the expected
    state was not reached (CHECK 8), and the record ids disagree (CHECK 11).
    """
    db = MockProductionDB()
    store = EvidenceStore(":memory:")
    gw = PolicyGateway()

    intent = AgentIntent(
        proposed_tool="delete",
        proposed_args={"resource": "database/customers", "record_id": 3},
        reasoning="Authorized delete",
    )
    store.append("agent_intent", intent.model_dump())

    policy_result = gw.evaluate("admin", "delete", "production", "database/customers")
    policy = PolicyDecision(
        decision="allow", reason=policy_result["reason"], role="admin",
        action="delete", environment="production", resource="database/customers",
    )
    store.append("policy_check", policy.model_dump())

    before = db.snapshot()
    result = db.delete("database/orders", record_id=1)
    execution = ToolExecution(tool_name="delete", executed=True, result=result,
                              skipped_reason=None)
    store.append("tool_execution", execution.model_dump())

    after = db.current_state()
    observation = StateObservation(
        resource="database/customers", state_before=before, state_after=after, changed=False
    )
    store.append("state_observation", observation.model_dump())
    records = store.get_all()
    gw.close()

    verdict = evaluate(xs.s2, intent, policy, execution, observation, records,
                       actual_state_before=before, actual_state_after=after)

    failed = failed_checks(verdict)
    assert result["status"] == "not_found", "the orders table is absent in the mock DB"
    assert check_by_name(verdict, "policy_decision_matches_invariant")["passed"] is True
    assert "state_change_matches_invariant" in failed
    assert "business_outcome_matches_expected" in failed
    assert "tool_result_matches_agent_claim" in failed


def test_role_changed_between_intent_and_policy_is_not_checked(xs):
    """Case 8: intent describes an operator, the policy was evaluated as admin.

    Known gap, asserted deliberately. The evaluator compares the policy decision
    against the scenario invariant and never compares the intent's claimed role
    against the policy's role, so this trajectory passes. Making this test fail
    is the correct outcome if role consistency is added.
    """
    db = MockProductionDB()
    store = EvidenceStore(":memory:")
    gw = PolicyGateway()

    intent = AgentIntent(
        proposed_tool="delete",
        proposed_args={"resource": "database/customers", "record_id": 3},
        reasoning="Operator delete",
    )
    store.append("agent_intent", intent.model_dump())

    policy_result = gw.evaluate("admin", "delete", "production", "database/customers")
    policy = PolicyDecision(
        decision="allow", reason=policy_result["reason"], role="admin",
        action="delete", environment="production", resource="database/customers",
    )
    store.append("policy_check", policy.model_dump())

    before = db.snapshot()
    result = db.delete("database/customers", record_id=3)
    execution = ToolExecution(tool_name="delete", executed=True, result=result,
                              skipped_reason=None)
    store.append("tool_execution", execution.model_dump())

    after = db.current_state()
    observation = StateObservation(
        resource="database/customers", state_before=before, state_after=after, changed=True
    )
    store.append("state_observation", observation.model_dump())
    records = store.get_all()
    gw.close()

    verdict = evaluate(xs.s2, intent, policy, execution, observation, records,
                       actual_state_before=before, actual_state_after=after)

    assert intent.claimed_role != policy.role, "the case requires a role mismatch"
    assert verdict.passed is True, (
        "role consistency is now checked -- update or delete this test"
    )


def test_cross_store_mixing_is_detected_by_run_id(xs):
    """Case 9: records from two different stores spliced into one chain."""
    store_a = EvidenceStore(":memory:", run_id="run_AAAA")
    store_b = EvidenceStore(":memory:", run_id="run_BBBB")
    gw = PolicyGateway()

    AgentStub().run(xs.s1, gw, MockProductionDB(), store_a)
    records_a = store_a.get_all()
    AgentStub().run(xs.s2, gw, MockProductionDB(), store_b)
    records_b = store_b.get_all()
    gw.close()

    mixed = records_a + records_b
    for i, r in enumerate(mixed):
        r.seq = i

    chain_valid, break_seq, break_reason = verify_chain(mixed)

    assert chain_valid is False
    assert break_seq == 0
    assert "run_id_mismatch" in break_reason


def test_reusing_one_store_for_two_runs_is_a_harness_boundary(xs):
    """Case 9, second half: same run_id, so the chain has nothing to object to."""
    store = EvidenceStore(":memory:", run_id="run_CCCC")
    gw = PolicyGateway()

    AgentStub().run(xs.s1, gw, MockProductionDB(), store)
    AgentStub().run(xs.s2, gw, MockProductionDB(), store)
    gw.close()

    chain_valid, _, _ = verify_chain(store.get_all())

    assert chain_valid is True, (
        "reusing one store for two runs produces a valid chain; isolation is the "
        "caller's responsibility, not the chain's"
    )


def test_separate_stores_do_not_share_records(xs):
    """Case 10: two independent in-memory stores stay independent."""
    store_a = EvidenceStore(":memory:", run_id="iso_aaaa")
    store_b = EvidenceStore(":memory:", run_id="iso_bbbb")
    gw = PolicyGateway()

    AgentStub().run(xs.s1, gw, MockProductionDB(), store_a)
    AgentStub().run(xs.s2, gw, MockProductionDB(), store_b)
    gw.close()

    records_a = store_a.get_all()
    records_b = store_b.get_all()
    store_a.close()
    store_b.close()

    assert len(records_a) == 4
    assert len(records_b) == 4
    assert {r.entry_hash for r in records_a}.isdisjoint({r.entry_hash for r in records_b})


def test_sequential_runs_produce_independent_verdicts(xs):
    """Case 11: running both scenarios back to back changes neither verdict."""
    store1 = EvidenceStore(":memory:", run_id="seq_run_1")
    store2 = EvidenceStore(":memory:", run_id="seq_run_2")
    gw = PolicyGateway()

    db1 = MockProductionDB()
    before1 = db1.snapshot()
    i1, p1, e1, o1 = AgentStub().run(xs.s1, gw, db1, store1)
    after1 = db1.current_state()
    records1 = store1.get_all()

    db2 = MockProductionDB()
    before2 = db2.snapshot()
    i2, p2, e2, o2 = AgentStub().run(xs.s2, gw, db2, store2)
    after2 = db2.current_state()
    records2 = store2.get_all()
    gw.close()

    v1 = evaluate(xs.s1, i1, p1, e1, o1, records1,
                  actual_state_before=before1, actual_state_after=after1)
    v2 = evaluate(xs.s2, i2, p2, e2, o2, records2,
                  actual_state_before=before2, actual_state_after=after2)

    assert v1.passed is True, failed_checks(v1)
    assert v2.passed is True, failed_checks(v2)


def test_state_snapshots_from_another_scenario_are_rejected(xs):
    """Case 12: Scenario #1 evidence verified against Scenario #2's snapshots."""
    verdict = evaluate(xs.s1, xs.i1, xs.p1, xs.e1, xs.o1, xs.records1,
                       actual_state_before=xs.s2_before, actual_state_after=xs.s2_after)

    assert verdict.passed is False
    assert "independent_state_verification" in failed_checks(verdict)


def test_replayed_evidence_against_foreign_state_is_rejected(xs):
    """Case 13: a valid chain replayed with someone else's state snapshots.

    The chain itself is untouched and stays valid -- CHECK 1-6 pass. Only the
    independent state comparison notices, which is why replay protection and
    chain integrity are separate guarantees.
    """
    verdict = evaluate(xs.s1, xs.i1, xs.p1, xs.e1, xs.o1, xs.records1,
                       actual_state_before=xs.s2_before, actual_state_after=xs.s2_after)

    assert verdict.passed is False
    assert all(c["passed"] for c in verdict.checks[:6])
    assert "independent_state_verification" in failed_checks(verdict)


def test_checkpoint_is_derived_from_evidence_not_scenario(xs):
    """Case 14: two runs have different checkpoints, each matching its evidence."""
    checkpoint1 = compute_checkpoint(xs.records1)
    checkpoint2 = compute_checkpoint(xs.records2)

    verdict = evaluate(xs.s2, xs.i2, xs.p2, xs.e2, xs.o2, xs.records2,
                       actual_state_before=xs.s2_before, actual_state_after=xs.s2_after)

    assert checkpoint1 != checkpoint2
    assert verdict.final_checkpoint_hash == compute_checkpoint(xs.records2)


def test_neither_scenario_passes_with_the_others_evidence(xs):
    """Case 15: the fundamental cross-scenario question, both directions."""
    s1_with_s2 = evaluate(xs.s1, xs.i2, xs.p2, xs.e2, xs.o2, xs.records2,
                          actual_state_before=xs.s2_before, actual_state_after=xs.s2_after)
    s2_with_s1 = evaluate(xs.s2, xs.i1, xs.p1, xs.e1, xs.o1, xs.records1,
                          actual_state_before=xs.s1_before, actual_state_after=xs.s1_after)

    assert s1_with_s2.passed is False, failed_checks(s1_with_s2)
    assert s2_with_s1.passed is False, failed_checks(s2_with_s1)
