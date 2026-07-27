"""Tests for DevAI config."""


import pytest

from devai.core.config import DevAIConfig


def test_default_config():
    config = DevAIConfig(api_key="test-key")
    assert config.model == "gpt-4o-mini"
    assert config.max_tokens == 4096


def test_validate_missing_key():
    config = DevAIConfig(api_key="")
    with pytest.raises(ValueError, match="API key"):
        config.validate()


def test_env_override(monkeypatch):
    monkeypatch.setenv("DEVAI_MODEL", "gpt-4")
    config = DevAIConfig(api_key="k")
    assert config.model == "gpt-4"
