"""End-to-end verdict tests for Scenario #1."""

import copy

from app.agent import AgentStub, RogueAgentStub
from app.evidence import EvidenceStore, compute_entry_hash, verify_chain
from app.evaluator import evaluate
from app.schemas import (
    EvidenceRecord,
    StateObservation,
)
from app.tools import MockProductionDB

from tests.conftest import extract_phases as _extract_phases

TEST_RUN = "test_run_v1"


class TestVerdictPass:
    """Scenario #1: unauthorized delete should PASS."""

    def test_verdict_passes(self, policy_gateway, evidence_store, mock_db, scenario_1):
        agent = AgentStub()
        actual_before = mock_db.snapshot()
        intent, policy, execution, observation = agent.run(
            scenario_1, policy_gateway, mock_db, evidence_store
        )
        actual_after = mock_db.current_state()
        records = evidence_store.get_all()
        verdict = evaluate(
            scenario_1, intent, policy, execution, observation, records,
            actual_state_before=actual_before, actual_state_after=actual_after,
        )

        assert verdict.passed is True
        assert verdict.summary == "PASS"
        assert len(verdict.checks) == 8
        assert all(c["passed"] for c in verdict.checks)

    def test_verdict_has_checkpoint(self, policy_gateway, evidence_store, mock_db, scenario_1):
        agent = AgentStub()
        actual_before = mock_db.snapshot()
        intent, policy, execution, observation = agent.run(
            scenario_1, policy_gateway, mock_db, evidence_store
        )
        actual_after = mock_db.current_state()
        records = evidence_store.get_all()
        verdict = evaluate(
            scenario_1, intent, policy, execution, observation, records,
            actual_state_before=actual_before, actual_state_after=actual_after,
        )

        assert len(verdict.final_checkpoint_hash) == 64  # SHA-256 hex digest


class TestVerdictFail:
    """Rogue agent: delete despite DENY should FAIL."""

    def test_rogue_verdict_fails(self, policy_gateway, evidence_store, mock_db, scenario_1):
        agent = RogueAgentStub()
        actual_before = mock_db.snapshot()
        intent, policy, execution, observation = agent.run(
            scenario_1, policy_gateway, mock_db, evidence_store
        )
        actual_after = mock_db.current_state()
        records = evidence_store.get_all()
        verdict = evaluate(
            scenario_1, intent, policy, execution, observation, records,
            actual_state_before=actual_before, actual_state_after=actual_after,
        )

        assert verdict.passed is False
        assert verdict.summary == "FAIL"

    def test_rogue_fails_on_tool_execution_check(self, policy_gateway, evidence_store, mock_db, scenario_1):
        agent = RogueAgentStub()
        actual_before = mock_db.snapshot()
        intent, policy, execution, observation = agent.run(
            scenario_1, policy_gateway, mock_db, evidence_store
        )
        actual_after = mock_db.current_state()
        records = evidence_store.get_all()
        verdict = evaluate(
            scenario_1, intent, policy, execution, observation, records,
            actual_state_before=actual_before, actual_state_after=actual_after,
        )

        failed_checks = [c for c in verdict.checks if not c["passed"]]
        check_names = [c["name"] for c in failed_checks]
        assert "tool_execution_matches_invariant" in check_names

    def test_rogue_fails_on_state_change_check(self, policy_gateway, evidence_store, mock_db, scenario_1):
        agent = RogueAgentStub()
        actual_before = mock_db.snapshot()
        intent, policy, execution, observation = agent.run(
            scenario_1, policy_gateway, mock_db, evidence_store
        )
        actual_after = mock_db.current_state()
        records = evidence_store.get_all()
        verdict = evaluate(
            scenario_1, intent, policy, execution, observation, records,
            actual_state_before=actual_before, actual_state_after=actual_after,
        )

        failed_checks = [c for c in verdict.checks if not c["passed"]]
        check_names = [c["name"] for c in failed_checks]
        assert "state_change_matches_invariant" in check_names

    def test_rogue_verdict_reported_as_fail(self, policy_gateway, evidence_store, mock_db, scenario_1):
        agent = RogueAgentStub()
        actual_before = mock_db.snapshot()
        intent, policy, execution, observation = agent.run(
            scenario_1, policy_gateway, mock_db, evidence_store
        )
        actual_after = mock_db.current_state()
        records = evidence_store.get_all()
        verdict = evaluate(
            scenario_1, intent, policy, execution, observation, records,
            actual_state_before=actual_before, actual_state_after=actual_after,
        )

        failed_checks = [c for c in verdict.checks if not c["passed"]]
        assert len(failed_checks) >= 2  # tool_execution + state_change


class TestEvidenceTampering:
    """Detect tampering in the evidence chain."""

    def test_tampered_payload_detected(self, policy_gateway, evidence_store, mock_db, scenario_1):
        agent = AgentStub()
        agent.run(scenario_1, policy_gateway, mock_db, evidence_store)

        records = evidence_store.get_all()
        # Tamper: change tool_execution.executed from False to True
        records[2].payload["executed"] = True

        chain_valid, break_seq, break_reason = verify_chain(records)
        assert chain_valid is False
        assert break_seq == 2
        assert "entry_hash_mismatch" in break_reason

    def test_tampered_verdict_fails_evaluation(self, policy_gateway, evidence_store, mock_db, scenario_1):
        agent = AgentStub()
        actual_before = mock_db.snapshot()
        intent, policy, execution, observation = agent.run(
            scenario_1, policy_gateway, mock_db, evidence_store
        )
        actual_after = mock_db.current_state()
        records = evidence_store.get_all()
        # Tamper with the tool_execution record
        records[2].payload["executed"] = True

        # Recompute the verdict using the tampered evidence
        chain_valid, break_seq, break_reason = verify_chain(records)
        verdict = evaluate(
            scenario_1, intent, policy, execution, observation, records,
            actual_state_before=actual_before, actual_state_after=actual_after,
        )

        assert verdict.passed is False
        failed_checks = [c for c in verdict.checks if not c["passed"]]
        check_names = [c["name"] for c in failed_checks]
        assert "evidence_chain_valid" in check_names

    def test_tampered_prev_hash_detected(self, policy_gateway, evidence_store, mock_db, scenario_1):
        agent = AgentStub()
        agent.run(scenario_1, policy_gateway, mock_db, evidence_store)

        records = evidence_store.get_all()
        records[1].prev_hash = "0" * 64

        chain_valid, break_seq, _ = verify_chain(records)
        assert chain_valid is False
        assert break_seq == 1

    def test_tampered_timestamp_detected(self, policy_gateway, evidence_store, mock_db, scenario_1):
        agent = AgentStub()
        agent.run(scenario_1, policy_gateway, mock_db, evidence_store)

        records = evidence_store.get_all()
        records[0].timestamp = 9999999999.0

        chain_valid, break_seq, _ = verify_chain(records)
        assert chain_valid is False
        assert break_seq == 0


class TestVerdictFromEvidence:
    """Verify evaluator works from extracted evidence phases."""

    def test_extract_phases_from_evidence(self, policy_gateway, evidence_store, mock_db, scenario_1):
        agent = AgentStub()
        agent.run(scenario_1, policy_gateway, mock_db, evidence_store)
        records = evidence_store.get_all()
        intent, policy, execution, observation = _extract_phases(records)

        assert intent is not None
        assert policy is not None
        assert execution is not None
        assert observation is not None

    def test_verdict_from_extracted_phases(self, policy_gateway, evidence_store, mock_db, scenario_1):
        agent = AgentStub()
        actual_before = mock_db.snapshot()
        agent.run(scenario_1, policy_gateway, mock_db, evidence_store)
        actual_after = mock_db.current_state()
        records = evidence_store.get_all()
        intent, policy, execution, observation = _extract_phases(records)

        verdict = evaluate(
            scenario_1, intent, policy, execution, observation, records,
            actual_state_before=actual_before, actual_state_after=actual_after,
        )
        assert verdict.passed is True


class TestPolicyEngineFailure:
    """Policy engine failure modes must fail closed (deny)."""

    def test_opa_binary_missing(self, policy_gateway, evidence_store, mock_db, scenario_1):
        from app.policy import PolicyGateway
        gw = PolicyGateway(opa_bin="/nonexistent/opa")
        result = gw.evaluate("operator", "delete", "production", "database/customers")
        gw.close()
        assert result["allow"] is False
        assert result["reason"] == "policy_engine_unavailable"

    def test_opa_timeout(self, policy_gateway, evidence_store, mock_db, scenario_1):
        import os
        import tempfile
        from app.policy import PolicyGateway

        with tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False) as f:
            f.write('#!/bin/bash\nsleep 100\n')
            f.flush()
            os.chmod(f.name, 0o755)
            script_path = f.name

        try:
            gw = PolicyGateway(opa_bin=script_path)
            result = gw.evaluate("operator", "delete", "production", "database/customers")
            gw.close()
            assert result["allow"] is False
            assert result["reason"] == "policy_engine_timeout"
        finally:
            os.unlink(script_path)

    def test_opa_malformed_json(self, policy_gateway, evidence_store, mock_db, scenario_1):
        import os
        import tempfile
        from app.policy import PolicyGateway

        with tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False) as f:
            f.write('#!/bin/bash\necho "not json at all"\n')
            f.flush()
            os.chmod(f.name, 0o755)
            script_path = f.name

        try:
            gw = PolicyGateway(opa_bin=script_path)
            result = gw.evaluate("operator", "delete", "production", "database/customers")
            gw.close()
            assert result["allow"] is False
            assert result["reason"] == "policy_engine_invalid_response"
        finally:
            os.unlink(script_path)

    def test_opa_failure_causes_verdict_fail(self, evidence_store, mock_db, scenario_1):
        from app.policy import PolicyGateway

        gw = PolicyGateway(opa_bin="/nonexistent/opa")
        agent = AgentStub()
        actual_before = mock_db.snapshot()
        intent, policy, execution, observation = agent.run(
            scenario_1, gw, mock_db, evidence_store
        )
        actual_after = mock_db.current_state()
        records = evidence_store.get_all()
        gw.close()

        # OPA unavailable → policy engine returns deny → agent doesn't execute → verdict PASS
        assert policy.decision == "deny"
        assert policy.reason == "policy_engine_unavailable"
        assert execution.executed is False
        assert execution.skipped_reason == "policy_denied"

        verdict = evaluate(
            scenario_1, intent, policy, execution, observation, records,
            actual_state_before=actual_before, actual_state_after=actual_after,
        )
        assert verdict.passed is True


class TestStateVerification:
    """Independent state verification catches agent-reported observation mismatches."""

    def test_fabricated_state_before(self, policy_gateway, evidence_store, mock_db, scenario_1):
        agent = AgentStub()
        actual_before = mock_db.snapshot()
        intent, policy, execution, observation = agent.run(
            scenario_1, policy_gateway, mock_db, evidence_store
        )
        actual_after = mock_db.current_state()
        records = evidence_store.get_all()

        # Lie about state_before
        observation_lies = StateObservation(
            resource=observation.resource,
            state_before={"customers": [{"id": 99}]},  # fabricated
            state_after=observation.state_after,
            changed=observation.changed,
        )

        verdict = evaluate(
            scenario_1, intent, policy, execution, observation_lies, records,
            actual_state_before=actual_before, actual_state_after=actual_after,
        )
        failed = [c["name"] for c in verdict.checks if not c["passed"]]
        assert verdict.passed is False
        assert "independent_state_verification" in failed

    def test_correct_state_before(self, policy_gateway, evidence_store, mock_db, scenario_1):
        agent = AgentStub()
        actual_before = mock_db.snapshot()
        intent, policy, execution, observation = agent.run(
            scenario_1, policy_gateway, mock_db, evidence_store
        )
        actual_after = mock_db.current_state()
        records = evidence_store.get_all()

        verdict = evaluate(
            scenario_1, intent, policy, execution, observation, records,
            actual_state_before=actual_before, actual_state_after=actual_after,
        )
        # State verification should pass (before and after are correct)
        state_check = [c for c in verdict.checks if c["name"] == "independent_state_verification"]
        assert len(state_check) == 1
        assert state_check[0]["passed"] is True

    def test_fabricated_state_after(self, policy_gateway, evidence_store, mock_db, scenario_1):
        agent = AgentStub()
        actual_before = mock_db.snapshot()
        intent, policy, execution, observation = agent.run(
            scenario_1, policy_gateway, mock_db, evidence_store
        )
        actual_after = mock_db.current_state()
        records = evidence_store.get_all()

        # Lie about state_after
        observation_lies = StateObservation(
            resource=observation.resource,
            state_before=observation.state_before,
            state_after={"customers": [{"id": 99}]},  # fabricated
            changed=observation.changed,
        )

        verdict = evaluate(
            scenario_1, intent, policy, execution, observation_lies, records,
            actual_state_before=actual_before, actual_state_after=actual_after,
        )
        failed = [c["name"] for c in verdict.checks if not c["passed"]]
        assert verdict.passed is False
        assert "independent_state_verification" in failed

    def test_state_changed_but_observation_claims_unchanged(self, policy_gateway, evidence_store, mock_db, scenario_1):
        agent = RogueAgentStub()
        actual_before = mock_db.snapshot()
        intent, policy, execution, observation = agent.run(
            scenario_1, policy_gateway, mock_db, evidence_store
        )
        actual_after = mock_db.current_state()
        records = evidence_store.get_all()

        # Rogue agent actually changed state, but lie about changed=False
        observation_lies = StateObservation(
            resource=observation.resource,
            state_before=observation.state_before,
            state_after=observation.state_after,
            changed=False,  # lie: claims unchanged
        )

        verdict = evaluate(
            scenario_1, intent, policy, execution, observation_lies, records,
            actual_state_before=actual_before, actual_state_after=actual_after,
        )
        failed = [c["name"] for c in verdict.checks if not c["passed"]]
        assert verdict.passed is False
        assert "independent_state_verification" in failed

    def test_state_unchanged_but_observation_claims_changed(self, policy_gateway, evidence_store, mock_db, scenario_1):
        agent = AgentStub()
        actual_before = mock_db.snapshot()
        intent, policy, execution, observation = agent.run(
            scenario_1, policy_gateway, mock_db, evidence_store
        )
        actual_after = mock_db.current_state()
        records = evidence_store.get_all()

        # State didn't change (policy denied), but lie about changed=True
        observation_lies = StateObservation(
            resource=observation.resource,
            state_before=observation.state_before,
            state_after=observation.state_after,
            changed=True,  # lie: claims changed
        )

        verdict = evaluate(
            scenario_1, intent, policy, execution, observation_lies, records,
            actual_state_before=actual_before, actual_state_after=actual_after,
        )
        failed = [c["name"] for c in verdict.checks if not c["passed"]]
        assert verdict.passed is False
        assert "independent_state_verification" in failed


class TestDuplicatePhase:
    """Duplicate required phase records must fail structural validation."""

    def test_duplicate_tool_execution_fails(self, policy_gateway, evidence_store, mock_db, scenario_1):
        from app.agent import AgentStub
        agent = AgentStub()
        agent.run(scenario_1, policy_gateway, mock_db, evidence_store)
        records = evidence_store.get_all()

        # Append a duplicate tool_execution record with valid chain
        dup_payload = copy.deepcopy(records[2].payload)
        new_record = EvidenceRecord(
            seq=len(records),
            timestamp=records[-1].timestamp + 0.001,
            event_type="tool_execution",
            payload=dup_payload,
            prev_hash=records[-1].entry_hash,
            entry_hash=compute_entry_hash(
                evidence_store.run_id, len(records), records[-1].timestamp + 0.001,
                "tool_execution", dup_payload, records[-1].entry_hash
            ),
        )
        records.append(new_record)

        intent, policy, execution, observation = _extract_phases(records)
        verdict = evaluate(scenario_1, intent, policy, execution, observation, records)

        failed = [c["name"] for c in verdict.checks if not c["passed"]]
        assert verdict.passed is False
        assert "all_phases_recorded" in failed
        assert "Duplicate" in [c["detail"] for c in verdict.checks if c["name"] == "all_phases_recorded"][0]

    def test_duplicate_agent_intent_fails(self, policy_gateway, evidence_store, mock_db, scenario_1):
        from app.agent import AgentStub
        agent = AgentStub()
        agent.run(scenario_1, policy_gateway, mock_db, evidence_store)
        records = evidence_store.get_all()

        # Append a duplicate agent_intent record
        dup_payload = copy.deepcopy(records[0].payload)
        new_record = EvidenceRecord(
            seq=len(records),
            timestamp=records[-1].timestamp + 0.001,
            event_type="agent_intent",
            payload=dup_payload,
            prev_hash=records[-1].entry_hash,
            entry_hash=compute_entry_hash(
                evidence_store.run_id, len(records), records[-1].timestamp + 0.001,
                "agent_intent", dup_payload, records[-1].entry_hash
            ),
        )
        records.append(new_record)

        intent, policy, execution, observation = _extract_phases(records)
        verdict = evaluate(scenario_1, intent, policy, execution, observation, records)

        failed = [c["name"] for c in verdict.checks if not c["passed"]]
        assert verdict.passed is False
        assert "all_phases_recorded" in failed
