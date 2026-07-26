"""Tests for DevAIConfig."""

import os

from devai.core.config import DevAIConfig


def test_default_config():
    config = DevAIConfig(api_key="test-key")
    assert config.model == "gpt-4o-mini"
    assert config.temperature == 0.7


def test_from_env(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "env-key")
    monkeypatch.setenv("DEVAI_MODEL", "gpt-4o")
    config = DevAIConfig.from_env()
    assert config.api_key == "env-key"
    assert config.model == "gpt-4o"


def test_api_key_from_env(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("DEVAI_API_KEY", raising=False)
    config = DevAIConfig()
    assert config.api_key is None
