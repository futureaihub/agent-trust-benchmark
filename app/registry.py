"""V2 ScenarioRegistry — YAML-based scenario management.

Loads scenario definitions from YAML files, validates them against
the expected schema, and provides lookup by scenario ID.

The registry converts YAML definitions into ScenarioInput objects
compatible with the V1 evaluator.
"""

from __future__ import annotations

import os
from pathlib import Path

import yaml

from app.schemas import Invariants, ScenarioInput


class ScenarioRegistry:
    """Registry of benchmark scenarios loaded from YAML files.

    Supports:
    - Loading from a directory of YAML files
    - Lookup by scenario_id
    - Validation of required fields
    - Conversion to ScenarioInput for V1 evaluator compatibility

    Usage:
        registry = ScenarioRegistry("scenarios/")
        scenario = registry.get("unauthorized_delete")
        scenario_input = registry.to_scenario_input("unauthorized_delete")
    """

    def __init__(self, scenarios_dir: str | Path | None = None):
        """Load scenarios from a directory.

        Args:
            scenarios_dir: Path to directory containing YAML scenario files.
                If None, uses the default scenarios/ directory.
        """
        if scenarios_dir is None:
            scenarios_dir = Path(__file__).parent.parent / "scenarios"
        self._dir = Path(scenarios_dir)
        self._scenarios: dict[str, dict] = {}
        self._load_all()

    def _load_all(self) -> None:
        """Load all YAML files from the scenarios directory."""
        if not self._dir.exists():
            return

        for path in sorted(self._dir.glob("*.yaml")):
            try:
                with open(path) as f:
                    data = yaml.safe_load(f)
                if data and "scenario" in data:
                    sid = data["scenario"]["id"]
                    self._scenarios[sid] = data
            except (yaml.YAMLError, KeyError, TypeError):
                continue

    def list_ids(self) -> list[str]:
        """Return all loaded scenario IDs."""
        return sorted(self._scenarios.keys())

    def get(self, scenario_id: str) -> dict:
        """Get raw scenario definition by ID.

        Raises:
            KeyError: If scenario_id not found.
        """
        if scenario_id not in self._scenarios:
            available = ", ".join(self.list_ids())
            raise KeyError(
                f"Scenario '{scenario_id}' not found. Available: {available}"
            )
        return self._scenarios[scenario_id]

    def has(self, scenario_id: str) -> bool:
        """Check if a scenario exists."""
        return scenario_id in self._scenarios

    def to_scenario_input(self, scenario_id: str) -> ScenarioInput:
        """Convert a YAML scenario to a V1-compatible ScenarioInput.

        This allows YAML-defined scenarios to be used with the existing
        V1 evaluator without modification.

        Raises:
            KeyError: If scenario_id not found.
            ValueError: If required fields are missing.
        """
        data = self.get(scenario_id)
        return _parse_scenario(data)


def _parse_scenario(data: dict) -> ScenarioInput:
    """Parse a YAML scenario dict into a ScenarioInput.

    Expected YAML structure:
        scenario:
            id: ...
            version: ...
            description: ...
        identity:
            user: ...
            user_role: ...
            trusted_role: ... (optional)
        request:
            action: ...
            resource: ...
            target_environment: ...
            target_record_id: ... (optional)
        state:
            initial: ... (optional)
        expected:
            policy_decision: ...
            tool_executed: ...
            state_changed: ...
            final_state: ... (optional)
        invariants:
            expected_policy_decision: ...
            tool_must_execute: ...
            state_must_change: ...
    """
    scenario = data.get("scenario", {})
    identity = data.get("identity", {})
    request = data.get("request", {})
    expected = data.get("expected", {})
    invariants = data.get("invariants", {})

    if not scenario.get("id"):
        raise ValueError("Scenario missing 'scenario.id'")
    if not identity.get("user"):
        raise ValueError(f"Scenario '{scenario['id']}' missing 'identity.user'")
    if not identity.get("user_role"):
        raise ValueError(f"Scenario '{scenario['id']}' missing 'identity.user_role'")
    if not request.get("action"):
        raise ValueError(f"Scenario '{scenario['id']}' missing 'request.action'")
    if not request.get("target_environment"):
        raise ValueError(
            f"Scenario '{scenario['id']}' missing 'request.target_environment'"
        )
    if not request.get("resource"):
        raise ValueError(f"Scenario '{scenario['id']}' missing 'request.resource'")

    # Build invariants
    inv = Invariants(
        expected_policy_decision=invariants.get(
            "expected_policy_decision",
            expected.get("policy_decision", "deny"),
        ),
        tool_must_execute=invariants.get(
            "tool_must_execute",
            expected.get("tool_executed", False),
        ),
        state_must_change=invariants.get(
            "state_must_change",
            expected.get("state_changed", False),
        ),
    )

    # Build ScenarioInput
    kwargs = {
        "scenario_id": scenario["id"],
        "description": scenario.get("description", ""),
        "user": identity["user"],
        "user_role": identity["user_role"],
        "action": request["action"],
        "target_environment": request["target_environment"],
        "target_resource": request["resource"],
        "invariants": inv,
    }

    if request.get("target_record_id") is not None:
        kwargs["target_record_id"] = request["target_record_id"]

    if expected.get("final_state") is not None:
        kwargs["expected_state"] = expected["final_state"]

    if identity.get("trusted_role") is not None:
        kwargs["trusted_identity"] = {
            "user": identity["user"],
            "role": identity["trusted_role"],
        }

    if data.get("available_tools") is not None:
        kwargs["available_tools"] = data["available_tools"]

    return ScenarioInput(**kwargs)


def validate_scenario(data: dict) -> list[str]:
    """Validate a scenario definition and return any error messages.

    Returns empty list if valid. Returns list of error strings if invalid.
    """
    errors = []

    scenario = data.get("scenario", {})
    identity = data.get("identity", {})
    request = data.get("request", {})
    invariants = data.get("invariants", {})

    if not scenario.get("id"):
        errors.append("Missing 'scenario.id'")
    if not scenario.get("description"):
        errors.append("Missing 'scenario.description'")
    if not identity.get("user"):
        errors.append("Missing 'identity.user'")
    if not identity.get("user_role"):
        errors.append("Missing 'identity.user_role'")
    if not request.get("action"):
        errors.append("Missing 'request.action'")
    if not request.get("target_environment"):
        errors.append("Missing 'request.target_environment'")
    if not request.get("resource"):
        errors.append("Missing 'request.resource'")
    if not invariants.get("expected_policy_decision"):
        errors.append("Missing 'invariants.expected_policy_decision'")

    return errors
