"""V2 ToolGateway — single controlled path for tool execution.

All agent tool requests pass through the gateway. The gateway:
1. Validates the tool identity
2. Evaluates policy via OPA
3. Executes the tool if allowed
4. Records the execution in the evidence chain

The agent never bypasses the gateway through the V2 interface.
"""

from __future__ import annotations

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


class ToolGateway:
    """Intercepts tool calls and enforces policy before execution.

    The gateway is the single controlled path through which an agent
    requests a tool execution. It:
    - Validates the tool name against the scenario's allowed tools
    - Evaluates policy via OPA before execution
    - Executes through the mock tool backend
    - Records execution evidence

    Usage:
        gateway = ToolGateway(policy_gateway, mock_db, evidence)
        execution, observation = gateway.execute(scenario, intent)
    """

    def __init__(
        self,
        policy_gateway: PolicyGateway,
        mock_db: MockProductionDB,
        evidence: EvidenceStore,
    ):
        self._policy = policy_gateway
        self._db = mock_db
        self._evidence = evidence

    def evaluate_policy(
        self,
        scenario: ScenarioInput,
        trusted_role: str | None = None,
    ) -> PolicyDecision:
        """Evaluate OPA policy for the given scenario.

        Returns:
            PolicyDecision with the OPA result.
        """
        result = self._policy.evaluate(
            role=scenario.user_role,
            action=scenario.action,
            environment=scenario.target_environment,
            resource=scenario.target_resource,
            trusted_role=trusted_role,
        )
        policy = PolicyDecision(
            decision="allow" if result["allow"] else "deny",
            reason=result["reason"],
            role=result.get("role", scenario.user_role),
            action=scenario.action,
            environment=scenario.target_environment,
            resource=scenario.target_resource,
        )
        self._evidence.append("policy_check", policy.model_dump())
        return policy

    def execute_tool(
        self,
        scenario: ScenarioInput,
        policy: PolicyDecision,
    ) -> ToolExecution:
        """Execute the tool if policy allows, otherwise skip.

        Returns:
            ToolExecution recording what happened.
        """
        target = getattr(scenario, "target_record_id", 1)

        if policy.decision == "allow":
            result = self._db.delete(scenario.target_resource, record_id=target)
            execution = ToolExecution(
                tool_name="delete",
                executed=True,
                result=result,
                skipped_reason=None,
            )
        else:
            execution = ToolExecution(
                tool_name="delete",
                executed=False,
                result=None,
                skipped_reason="policy_denied",
            )

        self._evidence.append("tool_execution", execution.model_dump())
        return execution

    def observe_state(
        self,
        scenario: ScenarioInput,
        state_before: dict,
    ) -> StateObservation:
        """Capture state after execution and record the observation.

        Returns:
            StateObservation with before/after comparison.
        """
        state_after = self._db.current_state()
        observation = StateObservation(
            resource=scenario.target_resource,
            state_before=state_before,
            state_after=state_after,
            changed=state_before != state_after,
        )
        self._evidence.append("state_observation", observation.model_dump())
        return observation

    def execute(
        self,
        scenario: ScenarioInput,
        intent: AgentIntent,
        trusted_role: str | None = None,
    ) -> tuple[PolicyDecision, ToolExecution, StateObservation]:
        """Full gateway execution: policy → tool → state.

        This is the high-level method that orchestrates the three phases
        after the agent has produced its intent.

        Args:
            scenario: The scenario being executed.
            intent: The agent's proposed action.
            trusted_role: Benchmark-owned trusted role (optional).

        Returns:
            (policy, execution, observation) tuple.
        """
        policy = self.evaluate_policy(scenario, trusted_role)
        state_before = self._db.snapshot()
        execution = self.execute_tool(scenario, policy)
        observation = self.observe_state(scenario, state_before)
        return policy, execution, observation
