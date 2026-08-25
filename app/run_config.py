"""V2 RunConfig — configuration for real-LLM agent execution.

RunConfig carries model/provider settings, cost controls, and tool
definitions needed by a real LLM agent. The adapter protocol accepts
it as an optional parameter, keeping V1 adapters backward-compatible.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class RunConfig:
    """Configuration for a real-LLM agent run.

    Attributes:
        model: Model identifier (e.g., "gpt-4o-mini").
        api_key: API key. Reads OPENAI_API_KEY from env if None.
        base_url: Optional base URL for proxies or custom endpoints.
        system_prompt: System instructions for the agent.
        max_turns: Maximum LLM→tool-call rounds before aborting.
        max_tokens: Maximum tokens per LLM response.
        temperature: Sampling temperature (0.0 = near-deterministic).
        tool_timeout: Seconds to wait for tool execution.
        model_timeout: Seconds to wait for LLM API response.
        max_retries: Retry attempts on transient API errors.
        per_run_cost_cap: Hard USD cap per run (None = no cap).
    """

    model: str = "gpt-4o-mini"
    api_key: str | None = None
    base_url: str | None = None
    system_prompt: str | None = None
    max_turns: int = 10
    max_tokens: int = 1000
    temperature: float = 0.0
    tool_timeout: float = 5.0
    model_timeout: float = 30.0
    max_retries: int = 3
    per_run_cost_cap: float | None = None

    def resolve_api_key(self) -> str | None:
        """Return the API key, resolving from env if not set."""
        return self.api_key or os.environ.get("OPENAI_API_KEY")

    def __post_init__(self) -> None:
        if self.max_turns < 1:
            raise ValueError(f"max_turns must be >= 1, got {self.max_turns}")
        if self.max_tokens < 1:
            raise ValueError(f"max_tokens must be >= 1, got {self.max_tokens}")
        if self.temperature < 0.0 or self.temperature > 2.0:
            raise ValueError(
                f"temperature must be 0.0-2.0, got {self.temperature}"
            )
        if self.max_retries < 0:
            raise ValueError(f"max_retries must be >= 0, got {self.max_retries}")
