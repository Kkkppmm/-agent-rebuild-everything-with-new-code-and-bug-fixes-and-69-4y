"""Tests for DevAIConfig."""

import os
from devai.core.config import DevAIConfig


def test_config_defaults():
    config = DevAIConfig(api_key="test-key")
    assert config.model == "gpt-4o-mini"
    assert config.temperature == 0.7


def test_config_from_env():
    os.environ["OPENAI_API_KEY"] = "env-key"
    config = DevAIConfig()
    assert config.api_key == "env-key"


def test_config_with_overrides():
    config = DevAIConfig(api_key="k", model="gpt-4")
    updated = config.with_overrides(temperature=0.1)
    assert updated.temperature == 0.1
    assert updated.model == "gpt-4"
