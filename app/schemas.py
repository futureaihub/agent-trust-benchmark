"""All Pydantic models for Agent Trust Benchmark v0.1."""

from pydantic import BaseModel


class Invariants(BaseModel):
    """What must be true about the outcome for a passing verdict."""

    expected_policy_decision: str  # "allow" or "deny"
    tool_must_execute: bool
    state_must_change: bool


class ScenarioInput(BaseModel):
    """Scenario definition. Declares invariants, not agent implementation."""

    scenario_id: str
    description: str
    user: str
    user_role: str
    action: str
    target_environment: str
    target_resource: str
    invariants: Invariants
    target_record_id: int | None = None
    expected_state: dict | None = None
    trusted_identity: dict | None = None  # Benchmark-owned, NOT agent-controlled
    available_tools: list[dict] | None = None  # V2: tool schemas for LLM agents


# --- Execution phase models ---


class AgentIntent(BaseModel):
    """What the agent proposed to do."""

    proposed_tool: str | None
    proposed_args: dict | None
    reasoning: str | None  # Metadata only. NOT used by evaluator.
    claimed_role: str | None = None  # Untrusted self-reported identity


class PolicyDecision(BaseModel):
    """Result from OPA policy evaluation."""

    decision: str
    reason: str
    role: str
    action: str
    environment: str
    resource: str


class ToolExecution(BaseModel):
    """Whether the tool actually ran."""

    tool_name: str | None
    executed: bool
    result: dict | None
    skipped_reason: str | None


class StateObservation(BaseModel):
    """Production state before and after the action."""

    resource: str
    state_before: dict
    state_after: dict
    changed: bool


class Verdict(BaseModel):
    """Final evaluation result."""

    passed: bool
    checks: list[dict]
    final_checkpoint_hash: str
    summary: str


# --- Evidence ---


class EvidenceRecord(BaseModel):
    """One immutable row in the evidence chain."""

    seq: int
    timestamp: float
    event_type: str
    payload: dict
    prev_hash: str
    entry_hash: str
