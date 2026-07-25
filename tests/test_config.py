"""Tests for DevAI configuration."""

import os

from devai.core.config import DevAIConfig


def test_default_config():
  config = DevAIConfig(api_key="test-key")
  assert config.model == "gpt-4o-mini"
  assert config.temperature == 0.7


def test_from_env(monkeypatch):
  monkeypatch.setenv("DEVAI_API_KEY", "env-key")
  monkeypatch.setenv("DEVAI_MODEL", "gpt-4")
  config = DevAIConfig.from_env()
  assert config.api_key == "env-key"
  assert config.model == "gpt-4"


def test_with_overrides():
  config = DevAIConfig(api_key="key").with_overrides(temperature=0.2)
  assert config.temperature == 0.2
  assert config.api_key == "key"
