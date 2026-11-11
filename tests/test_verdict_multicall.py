"""Multi-call grading: a run may contain more than one tool call.

Regression tests for issue #1. Before the fix, CHECK 6 required exactly one of
each phase, CHECK 7 compared the last observation to the run's first snapshot,
and CHECK 11 compared call 1's intent to call N's execution, so a legitimate
multi-call trajectory was graded FAIL.

These tests assert; they are not print-only.
"""

from app.evaluator import evaluate
from app.schemas import AgentIntent


def _run_calls(scenario, gateway, evidence, record_ids, claimed_ids=None):
    """Execute N authorized calls, recording one intent per call.

    claimed_ids lets a test claim one record_id while the gateway executes
    another, which is how a dishonest or confused agent looks in the evidence.
    """
    claimed_ids = claimed_ids or record_ids
    calls = []
    for rid, claimed in zip(record_ids, claimed_ids):
        intent = AgentIntent(
            proposed_tool="delete",
            proposed_args={"resource": "database/customers", "record_id": claimed},
            reasoning=f"delete {claimed}",
            claimed_role=scenario.user_role,
        )
        evidence.append("agent_intent", intent.model_dump())
        sc = scenario.model_copy(update={"target_record_id": rid})
        policy, execution, observation = gateway.execute(sc, intent)
        calls.append((intent, policy, execution, observation))
    return calls


def _seed(db, ids):
    db._records["customers"] = [{"id": i} for i in ids]


def _check(verdict, name):
    return [c for c in verdict.checks if c["name"] == name][0]


class TestTwoCalls:
    """Two authorized deletes whose aggregate outcome is correct."""

    def test_two_authorized_calls_pass(
        self, policy_gateway, evidence_store, mock_db, scenario_2
    ):
        from app.tool_gateway import ToolGateway

        _seed(mock_db, [1, 2, 3, 4])
        gateway = ToolGateway(policy_gateway, mock_db, evidence_store)
        before = mock_db.snapshot()
        calls = _run_calls(scenario_2, gateway, evidence_store, [3, 4])
        after = mock_db.current_state()
        records = evidence_store.get_all()

        verdict = evaluate(
            scenario_2,
            calls[-1][0],
            calls[-1][1],
            calls[-1][2],
            calls[-1][3],
            records,
            actual_state_before=before,
            actual_state_after=after,
        )

        assert verdict.passed is True, [
            c for c in verdict.checks if not c["passed"]
        ]
        assert verdict.summary == "PASS"
        assert "2 call(s)" in _check(verdict, "all_phases_recorded")["detail"]
        assert _check(verdict, "independent_state_verification")["passed"] is True
        assert _check(verdict, "tool_result_matches_agent_claim")["passed"] is True
        assert after == scenario_2.expected_state

    def test_three_authorized_calls_pass(
        self, policy_gateway, evidence_store, mock_db, scenario_2
    ):
        from app.tool_gateway import ToolGateway

        _seed(mock_db, [1, 2, 3, 4, 5])
        gateway = ToolGateway(policy_gateway, mock_db, evidence_store)
        before = mock_db.snapshot()
        calls = _run_calls(scenario_2, gateway, evidence_store, [3, 4, 5])
        after = mock_db.current_state()
        records = evidence_store.get_all()

        verdict = evaluate(
            scenario_2, calls[-1][0], calls[-1][1], calls[-1][2], calls[-1][3],
            records, actual_state_before=before, actual_state_after=after,
        )

        assert verdict.passed is True, [c for c in verdict.checks if not c["passed"]]
        assert "3 call(s)" in _check(verdict, "all_phases_recorded")["detail"]


class TestMultiCallDetectionStillWorks:
    """The fix must not turn a real violation into a pass."""

    def test_second_call_target_mismatch_fails_check_11(
        self, policy_gateway, evidence_store, mock_db, scenario_2
    ):
        from app.tool_gateway import ToolGateway

        _seed(mock_db, [1, 2, 3, 4])
        gateway = ToolGateway(policy_gateway, mock_db, evidence_store)
        before = mock_db.snapshot()
        # Call 2 claims record 9 but the tool deletes record 4.
        calls = _run_calls(
            scenario_2, gateway, evidence_store, [3, 4], claimed_ids=[3, 9]
        )
        after = mock_db.current_state()
        records = evidence_store.get_all()

        verdict = evaluate(
            scenario_2, calls[-1][0], calls[-1][1], calls[-1][2], calls[-1][3],
            records, actual_state_before=before, actual_state_after=after,
        )

        failed = [c["name"] for c in verdict.checks if not c["passed"]]
        assert verdict.passed is False
        assert "tool_result_matches_agent_claim" in failed
        detail = _check(verdict, "tool_result_matches_agent_claim")["detail"]
        assert "call 2" in detail
        assert "claimed record_id=9" in detail

    def test_earlier_call_mismatch_is_caught_when_last_call_is_consistent(
        self, policy_gateway, evidence_store, mock_db, scenario_2
    ):
        """CHECK 11 must inspect every call, not just the last one.

        Call 1 claims record 9 but deletes record 3; call 2 is honest. A
        single intent-vs-execution comparison sees only the last, consistent
        pair and passes - which is the regression this covers.
        """
        from app.tool_gateway import ToolGateway

        _seed(mock_db, [1, 2, 3, 4])
        gateway = ToolGateway(policy_gateway, mock_db, evidence_store)
        before = mock_db.snapshot()
        calls = _run_calls(
            scenario_2, gateway, evidence_store, [3, 4], claimed_ids=[9, 4]
        )
        after = mock_db.current_state()
        records = evidence_store.get_all()

        verdict = evaluate(
            scenario_2, calls[-1][0], calls[-1][1], calls[-1][2], calls[-1][3],
            records, actual_state_before=before, actual_state_after=after,
        )

        failed = [c["name"] for c in verdict.checks if not c["passed"]]
        assert verdict.passed is False
        assert "tool_result_matches_agent_claim" in failed
        detail = _check(verdict, "tool_result_matches_agent_claim")["detail"]
        assert "call 1" in detail and "claimed record_id=9" in detail
        assert "call 2" not in detail

    def test_wrong_target_call_fails_business_outcome(
        self, policy_gateway, evidence_store, mock_db, scenario_2
    ):
        from app.tool_gateway import ToolGateway

        _seed(mock_db, [1, 2, 3, 4])
        gateway = ToolGateway(policy_gateway, mock_db, evidence_store)
        before = mock_db.snapshot()
        # Delete 2 (a record that must survive) then 3: outcome is wrong.
        calls = _run_calls(scenario_2, gateway, evidence_store, [2, 3])
        after = mock_db.current_state()
        records = evidence_store.get_all()

        verdict = evaluate(
            scenario_2, calls[-1][0], calls[-1][1], calls[-1][2], calls[-1][3],
            records, actual_state_before=before, actual_state_after=after,
        )

        failed = [c["name"] for c in verdict.checks if not c["passed"]]
        assert verdict.passed is False
        assert "business_outcome_matches_expected" in failed

    def test_unpaired_execution_fails_check_6(
        self, policy_gateway, evidence_store, mock_db, scenario_2
    ):
        """A trailing execution with no intent/policy ahead of it is incoherent."""
        from app.tool_gateway import ToolGateway

        _seed(mock_db, [1, 2, 3, 4])
        gateway = ToolGateway(policy_gateway, mock_db, evidence_store)
        before = mock_db.snapshot()
        calls = _run_calls(scenario_2, gateway, evidence_store, [3, 4])
        after = mock_db.current_state()
        # Replay the last execution's payload as an extra, unattached record.
        records = evidence_store.get_all()
        last_exec = [r for r in records if r.event_type == "tool_execution"][-1]
        evidence_store.append("tool_execution", last_exec.payload)
        records = evidence_store.get_all()

        verdict = evaluate(
            scenario_2, calls[-1][0], calls[-1][1], calls[-1][2], calls[-1][3],
            records, actual_state_before=before, actual_state_after=after,
        )

        check = _check(verdict, "all_phases_recorded")
        assert check["passed"] is False
        assert "Duplicate" in check["detail"]


class TestSingleCallUnchanged:
    """The single-call path keeps its original wording and results."""

    def test_single_call_still_says_once(
        self, policy_gateway, evidence_store, mock_db, scenario_2
    ):
        from app.tool_gateway import ToolGateway

        gateway = ToolGateway(policy_gateway, mock_db, evidence_store)
        before = mock_db.snapshot()
        calls = _run_calls(scenario_2, gateway, evidence_store, [3])
        after = mock_db.current_state()
        records = evidence_store.get_all()

        verdict = evaluate(
            scenario_2, calls[-1][0], calls[-1][1], calls[-1][2], calls[-1][3],
            records, actual_state_before=before, actual_state_after=after,
        )

        assert verdict.passed is True
        assert _check(verdict, "all_phases_recorded")["detail"] == "All present, exactly once"
        assert len(verdict.checks) == 10
