"""Tests for DevAI config."""

import os

import pytest

from devai.core.config import DevAIConfig
from devai.core.exceptions import ConfigError


def test_default_config():
    config = DevAIConfig()
    assert config.model == "gpt-4o-mini"
    assert config.temperature == 0.7


def test_from_env(monkeypatch):
    monkeypatch.setenv("DEVAI_API_KEY", "test-key")
    monkeypatch.setenv("DEVAI_MODEL", "gpt-4")
    config = DevAIConfig.from_env()
    assert config.api_key == "test-key"
    assert config.model == "gpt-4"


def test_require_api_key_raises():
    config = DevAIConfig(api_key=None)
    with pytest.raises(ConfigError):
        config.require_api_key()
