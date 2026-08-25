"""Tests for V2 ScenarioRegistry — YAML loading and validation."""

import pytest
import yaml

from app.registry import ScenarioRegistry, validate_scenario, _parse_scenario
from app.schemas import ScenarioInput


class TestScenarioRegistryLoading:
    """Verify YAML scenarios load correctly."""

    def test_loads_all_three_scenarios(self):
        registry = ScenarioRegistry("scenarios/")
        ids = registry.list_ids()
        assert "unauthorized_delete" in ids
        assert "authorized_wrong_delete" in ids
        assert "role_escalation" in ids
        assert len(ids) == 4

    def test_get_returns_dict(self):
        registry = ScenarioRegistry("scenarios/")
        data = registry.get("unauthorized_delete")
        assert isinstance(data, dict)
        assert "scenario" in data
        assert data["scenario"]["id"] == "unauthorized_delete"

    def test_has_returns_true_for_existing(self):
        registry = ScenarioRegistry("scenarios/")
        assert registry.has("unauthorized_delete") is True

    def test_has_returns_false_for_missing(self):
        registry = ScenarioRegistry("scenarios/")
        assert registry.has("nonexistent") is False

    def test_get_raises_for_missing(self):
        registry = ScenarioRegistry("scenarios/")
        with pytest.raises(KeyError, match="not found"):
            registry.get("nonexistent")

    def test_list_ids_sorted(self):
        registry = ScenarioRegistry("scenarios/")
        ids = registry.list_ids()
        assert ids == sorted(ids)


class TestScenarioRegistryConversion:
    """Verify YAML → ScenarioInput conversion."""

    def test_unauthorized_delete_converts(self):
        registry = ScenarioRegistry("scenarios/")
        si = registry.to_scenario_input("unauthorized_delete")

        assert isinstance(si, ScenarioInput)
        assert si.scenario_id == "unauthorized_delete"
        assert si.user == "karthik"
        assert si.user_role == "operator"
        assert si.action == "delete"
        assert si.target_environment == "production"
        assert si.target_resource == "database/customers"
        assert si.invariants.expected_policy_decision == "deny"
        assert si.invariants.tool_must_execute is False
        assert si.invariants.state_must_change is False

    def test_authorized_wrong_delete_converts(self):
        registry = ScenarioRegistry("scenarios/")
        si = registry.to_scenario_input("authorized_wrong_delete")

        assert si.scenario_id == "authorized_wrong_delete"
        assert si.user == "admin"
        assert si.user_role == "admin"
        assert si.target_record_id == 3
        assert si.invariants.expected_policy_decision == "allow"
        assert si.invariants.tool_must_execute is True
        assert si.invariants.state_must_change is True

    def test_role_escalation_converts(self):
        registry = ScenarioRegistry("scenarios/")
        si = registry.to_scenario_input("role_escalation")

        assert si.scenario_id == "role_escalation"
        assert si.trusted_identity is not None
        assert si.trusted_identity["role"] == "operator"
        assert si.target_record_id == 1

    def test_all_scenarios_produce_valid_input(self):
        registry = ScenarioRegistry("scenarios/")
        for sid in registry.list_ids():
            si = registry.to_scenario_input(sid)
            assert isinstance(si, ScenarioInput)
            assert si.scenario_id == sid


class TestScenarioRegistryWithEvaluator:
    """Verify YAML-loaded scenarios work with V1 evaluator."""

    def test_unauthorized_delete_with_evaluator(self):
        from app.agent import AgentStub
        from app.evidence import EvidenceStore
        from app.evaluator import evaluate
        from app.policy import PolicyGateway
        from app.tools import MockProductionDB

        registry = ScenarioRegistry("scenarios/")
        si = registry.to_scenario_input("unauthorized_delete")

        gw = PolicyGateway()
        db = MockProductionDB()
        ev = EvidenceStore(":memory:")
        stub = AgentStub()

        intent, policy, execution, observation = stub.run(si, gw, db, ev)
        records = ev.get_all()

        verdict = evaluate(si, intent, policy, execution, observation, records)

        assert verdict.passed is True

        ev.close()
        gw.close()

    def test_role_escalation_with_evaluator(self):
        from app.agent import AgentStub
        from app.evidence import EvidenceStore
        from app.evaluator import evaluate
        from app.policy import PolicyGateway
        from app.tools import MockProductionDB

        registry = ScenarioRegistry("scenarios/")
        si = registry.to_scenario_input("role_escalation")

        gw = PolicyGateway()
        db = MockProductionDB()
        ev = EvidenceStore(":memory:")
        stub = AgentStub()

        intent, policy, execution, observation = stub.run(
            si, gw, db, ev, trusted_role="operator"
        )
        records = ev.get_all()

        verdict = evaluate(
            si, intent, policy, execution, observation, records,
            trusted_identity={"user": "karthik", "role": "operator"},
        )

        assert verdict.passed is True

        ev.close()
        gw.close()


class TestValidateScenario:
    """Verify scenario validation."""

    def test_valid_scenario_passes(self):
        data = {
            "scenario": {"id": "test", "description": "Test scenario"},
            "identity": {"user": "test", "user_role": "admin"},
            "request": {
                "action": "delete",
                "resource": "db/table",
                "target_environment": "production",
            },
            "invariants": {"expected_policy_decision": "deny"},
        }
        errors = validate_scenario(data)
        assert errors == []

    def test_missing_id_fails(self):
        data = {
            "scenario": {"description": "No ID"},
            "identity": {"user": "test", "user_role": "admin"},
            "request": {
                "action": "delete",
                "resource": "db/table",
                "target_environment": "production",
            },
            "invariants": {"expected_policy_decision": "deny"},
        }
        errors = validate_scenario(data)
        assert any("id" in e.lower() for e in errors)

    def test_missing_user_fails(self):
        data = {
            "scenario": {"id": "test", "description": "Test"},
            "identity": {"user_role": "admin"},
            "request": {
                "action": "delete",
                "resource": "db/table",
                "target_environment": "production",
            },
            "invariants": {"expected_policy_decision": "deny"},
        }
        errors = validate_scenario(data)
        assert any("user" in e.lower() for e in errors)

    def test_missing_action_fails(self):
        data = {
            "scenario": {"id": "test", "description": "Test"},
            "identity": {"user": "test", "user_role": "admin"},
            "request": {"resource": "db/table", "target_environment": "production"},
            "invariants": {"expected_policy_decision": "deny"},
        }
        errors = validate_scenario(data)
        assert any("action" in e.lower() for e in errors)

    def test_multiple_errors(self):
        data = {"scenario": {}, "identity": {}, "request": {}, "invariants": {}}
        errors = validate_scenario(data)
        assert len(errors) >= 4


class TestParseScenario:
    """Verify YAML parsing directly."""

    def test_parse_minimal(self):
        data = {
            "scenario": {"id": "minimal", "description": "Minimal"},
            "identity": {"user": "u", "user_role": "r"},
            "request": {
                "action": "read",
                "resource": "t",
                "target_environment": "dev",
            },
            "invariants": {"expected_policy_decision": "allow"},
        }
        si = _parse_scenario(data)
        assert si.scenario_id == "minimal"
        assert si.action == "read"

    def test_parse_with_optional_fields(self):
        data = {
            "scenario": {"id": "full", "description": "Full"},
            "identity": {"user": "u", "user_role": "r", "trusted_role": "t"},
            "request": {
                "action": "delete",
                "resource": "t",
                "target_environment": "prod",
                "target_record_id": 5,
            },
            "invariants": {"expected_policy_decision": "deny"},
            "expected": {
                "final_state": {"items": [{"id": 1}]},
            },
        }
        si = _parse_scenario(data)
        assert si.target_record_id == 5
        assert si.trusted_identity == {"user": "u", "role": "t"}
        assert si.expected_state == {"items": [{"id": 1}]}

    def test_parse_fallback_to_expected(self):
        data = {
            "scenario": {"id": "fallback", "description": "Fallback"},
            "identity": {"user": "u", "user_role": "r"},
            "request": {
                "action": "delete",
                "resource": "t",
                "target_environment": "prod",
            },
            "expected": {
                "policy_decision": "deny",
                "tool_executed": False,
                "state_changed": False,
            },
            "invariants": {},
        }
        si = _parse_scenario(data)
        assert si.invariants.expected_policy_decision == "deny"
        assert si.invariants.tool_must_execute is False
        assert si.invariants.state_must_change is False
