"""Tests for DevAI configuration."""

import os

import pytest

from devai.core.config import DevAIConfig
from devai.core.exceptions import ConfigurationError


def test_default_config():
    config = DevAIConfig(api_key="test-key")
    assert config.model == "gpt-4o-mini"
    assert config.max_tokens == 4096
    assert config.temperature == 0.2


def test_config_from_env(monkeypatch):
    monkeypatch.setenv("DEVAI_API_KEY", "env-key")
    monkeypatch.setenv("DEVAI_MODEL", "gpt-4")
    monkeypatch.setenv("DEVAI_BASE_URL", "https://custom.api/v1")
    config = DevAIConfig()
    assert config.api_key == "env-key"
    assert config.model == "gpt-4"
    assert config.base_url == "https://custom.api/v1"


def test_validate_missing_key():
    config = DevAIConfig(api_key=None)
    with pytest.raises(ConfigurationError):
        config.validate()


def test_to_dict():
    config = DevAIConfig(api_key="key", model="test-model")
    d = config.to_dict()
    assert d["model"] == "test-model"
    assert "api_key" not in d
