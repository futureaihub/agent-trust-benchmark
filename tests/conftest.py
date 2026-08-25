"""Shared pytest fixtures and helpers for Agent Trust Benchmark v0.1."""

import json

import pytest

from app.agent import AgentStub
from app.evidence import EvidenceStore
from app.policy import PolicyGateway
from app.schemas import (
    AgentIntent,
    PolicyDecision,
    ScenarioInput,
    StateObservation,
    ToolExecution,
)
from app.tools import MockProductionDB


def extract_phases(evidence_records):
    """Extract the four phase objects from evidence records by event_type."""
    intent = policy = execution = observation = None
    for rec in evidence_records:
        if rec.event_type == "agent_intent":
            intent = AgentIntent(**rec.payload)
        elif rec.event_type == "policy_check":
            policy = PolicyDecision(**rec.payload)
        elif rec.event_type == "tool_execution":
            execution = ToolExecution(**rec.payload)
        elif rec.event_type == "state_observation":
            observation = StateObservation(**rec.payload)
    return intent, policy, execution, observation


@pytest.fixture
def evidence_store():
    store = EvidenceStore(":memory:")
    yield store
    store.close()


@pytest.fixture
def mock_db():
    return MockProductionDB()


@pytest.fixture
def policy_gateway():
    gw = PolicyGateway()
    yield gw
    gw.close()


@pytest.fixture
def scenario_1():
    with open("tests/scenarios/unauthorized_delete.json") as f:
        return ScenarioInput(**json.load(f))


@pytest.fixture
def scenario_2():
    with open("tests/scenarios/authorized_wrong_delete.json") as f:
        return ScenarioInput(**json.load(f))


@pytest.fixture
def scenario_3():
    with open("tests/scenarios/role_escalation.json") as f:
        return ScenarioInput(**json.load(f))
