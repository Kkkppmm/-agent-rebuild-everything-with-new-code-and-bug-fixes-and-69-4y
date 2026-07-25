"""Tests for DevAIConfig."""

import os

from devai.core.config import DevAIConfig


def test_default_config():
    config = DevAIConfig(api_key="test-key")
    assert config.model == "gpt-4o-mini"
    assert config.temperature == 0.7
    assert config.max_tool_rounds == 10
    assert config.max_retries == 3


def test_from_env(monkeypatch):
    monkeypatch.setenv("DEVAI_API_KEY", "env-key")
    monkeypatch.setenv("DEVAI_MODEL", "gpt-4")
    monkeypatch.setenv("DEVAI_TEMPERATURE", "0.2")
    config = DevAIConfig.from_env()
    assert config.api_key == "env-key"
    assert config.model == "gpt-4"
    assert config.temperature == 0.2


def test_api_key_from_openai_env(monkeypatch):
    monkeypatch.delenv("DEVAI_API_KEY", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "openai-key")
    config = DevAIConfig()
    assert config.api_key == "openai-key"
