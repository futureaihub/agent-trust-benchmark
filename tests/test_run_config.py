"""Tests for V2 RunConfig dataclass."""

import os

import pytest

from app.run_config import RunConfig


class TestRunConfigDefaults:
    def test_default_model(self):
        config = RunConfig()
        assert config.model == "gpt-4o-mini"

    def test_default_max_turns(self):
        config = RunConfig()
        assert config.max_turns == 10

    def test_default_max_tokens(self):
        config = RunConfig()
        assert config.max_tokens == 1000

    def test_default_temperature(self):
        config = RunConfig()
        assert config.temperature == 0.0

    def test_default_tool_timeout(self):
        config = RunConfig()
        assert config.tool_timeout == 5.0

    def test_default_model_timeout(self):
        config = RunConfig()
        assert config.model_timeout == 30.0

    def test_default_max_retries(self):
        config = RunConfig()
        assert config.max_retries == 3

    def test_default_cost_cap(self):
        config = RunConfig()
        assert config.per_run_cost_cap is None

    def test_default_api_key(self):
        config = RunConfig()
        assert config.api_key is None

    def test_default_base_url(self):
        config = RunConfig()
        assert config.base_url is None

    def test_default_system_prompt(self):
        config = RunConfig()
        assert config.system_prompt is None


class TestRunConfigCustom:
    def test_custom_model(self):
        config = RunConfig(model="gpt-4o")
        assert config.model == "gpt-4o"

    def test_custom_max_turns(self):
        config = RunConfig(max_turns=5)
        assert config.max_turns == 5

    def test_custom_temperature(self):
        config = RunConfig(temperature=1.0)
        assert config.temperature == 1.0

    def test_custom_api_key(self):
        config = RunConfig(api_key="sk-test")
        assert config.api_key == "sk-test"

    def test_custom_cost_cap(self):
        config = RunConfig(per_run_cost_cap=0.01)
        assert config.per_run_cost_cap == 0.01

    def test_custom_system_prompt(self):
        prompt = "You are a helpful assistant."
        config = RunConfig(system_prompt=prompt)
        assert config.system_prompt == prompt


class TestRunConfigValidation:
    def test_max_turns_zero_rejected(self):
        with pytest.raises(ValueError, match="max_turns"):
            RunConfig(max_turns=0)

    def test_max_turns_negative_rejected(self):
        with pytest.raises(ValueError, match="max_turns"):
            RunConfig(max_turns=-1)

    def test_max_tokens_zero_rejected(self):
        with pytest.raises(ValueError, match="max_tokens"):
            RunConfig(max_tokens=0)

    def test_max_tokens_negative_rejected(self):
        with pytest.raises(ValueError, match="max_tokens"):
            RunConfig(max_tokens=-1)

    def test_temperature_negative_rejected(self):
        with pytest.raises(ValueError, match="temperature"):
            RunConfig(temperature=-0.1)

    def test_temperature_too_high_rejected(self):
        with pytest.raises(ValueError, match="temperature"):
            RunConfig(temperature=2.1)

    def test_max_retries_negative_rejected(self):
        with pytest.raises(ValueError, match="max_retries"):
            RunConfig(max_retries=-1)

    def test_temperature_boundary_zero_ok(self):
        config = RunConfig(temperature=0.0)
        assert config.temperature == 0.0

    def test_temperature_boundary_two_ok(self):
        config = RunConfig(temperature=2.0)
        assert config.temperature == 2.0


class TestResolveApiKey:
    def test_resolve_from_field(self, monkeypatch):
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        config = RunConfig(api_key="sk-from-field")
        assert config.resolve_api_key() == "sk-from-field"

    def test_resolve_from_env(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-from-env")
        config = RunConfig()
        assert config.resolve_api_key() == "sk-from-env"

    def test_field_overrides_env(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-from-env")
        config = RunConfig(api_key="sk-from-field")
        assert config.resolve_api_key() == "sk-from-field"

    def test_resolve_none_when_no_key(self, monkeypatch):
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        config = RunConfig()
        assert config.resolve_api_key() is None
