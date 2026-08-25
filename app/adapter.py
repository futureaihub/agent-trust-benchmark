"""V2 AgentAdapter interface.

Provides a framework-agnostic protocol for plugging agents into the
benchmark harness. The runner depends only on the protocol, never on
concrete agent implementations.

The ScriptedAdapter wraps existing V1 agent stubs so they can be used
through the same interface as future real-LLM adapters.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

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


@runtime_checkable
class AgentAdapter(Protocol):
    """Protocol that all agent adapters must satisfy.

    The benchmark runner calls adapter.run() and receives back the same
    four-phase result that V1 stubs return. The runner does not know
    which agent framework (if any) is behind the adapter.
    """

    def run(
        self,
        scenario: ScenarioInput,
        policy_gateway: PolicyGateway,
        mock_db: MockProductionDB,
        evidence: EvidenceStore,
        trusted_role: str | None = None,
    ) -> tuple[AgentIntent, PolicyDecision, ToolExecution, StateObservation]:
        """Execute one scenario and record all evidence.

        Returns:
            Four-phase tuple: (intent, policy, execution, observation).
        """
        ...


class ScriptedAdapter:
    """Adapter that wraps a V1 deterministic agent stub.

    This demonstrates that existing scripted agents can be used through
    the adapter interface without modification. The runner calls
    ScriptedAdapter.run() and cannot distinguish it from any other
    AgentAdapter implementation.

    Usage:
        adapter = ScriptedAdapter(AgentStub())
        intent, policy, execution, observation = adapter.run(
            scenario, policy_gateway, mock_db, evidence
        )
    """

    def __init__(self, agent_stub):
        """Wrap any V1 agent stub.

        Args:
            agent_stub: An object with a .run() method matching the V1
                agent signature (scenario, policy_gateway, mock_db,
                evidence, trusted_role) -> (intent, policy, execution, observation).
        """
        self._agent = agent_stub

    def run(
        self,
        scenario: ScenarioInput,
        policy_gateway: PolicyGateway,
        mock_db: MockProductionDB,
        evidence: EvidenceStore,
        trusted_role: str | None = None,
    ) -> tuple[AgentIntent, PolicyDecision, ToolExecution, StateObservation]:
        """Delegate to the wrapped V1 agent stub.

        The adapter adds no behavior — it exists to prove the runner
        can work through the protocol without knowing the concrete type.
        """
        return self._agent.run(
            scenario, policy_gateway, mock_db, evidence, trusted_role
        )

    @property
    def agent_type(self) -> str:
        """Return the class name of the wrapped agent for reporting."""
        return type(self._agent).__name__
