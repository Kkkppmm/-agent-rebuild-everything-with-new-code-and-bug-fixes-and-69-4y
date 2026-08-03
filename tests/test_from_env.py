"""Tests for DevAI.from_env() and DevAIConfig.from_env()."""

from devai import DevAI
from devai.core.config import DevAIConfig


class TestFromEnv:
    def test_config_from_env_openai(self, monkeypatch):
        monkeypatch.setenv("DEVAI_API_KEY", "test-key")
        monkeypatch.setenv("DEVAI_MODEL", "gpt-4o")
        monkeypatch.setenv("DEVAI_PROVIDER", "openai")
        config = DevAIConfig.from_env()
        assert config.api_key == "test-key"
        assert config.model == "gpt-4o"

    def test_config_from_env_mock(self, monkeypatch):
        monkeypatch.setenv("DEVAI_PROVIDER", "mock")
        config = DevAIConfig.from_env()
        assert config.api_key == "mock"

    def test_config_overrides_env(self, monkeypatch):
        monkeypatch.setenv("DEVAI_MODEL", "gpt-4o")
        config = DevAIConfig.from_env(model="gpt-4o-mini")
        assert config.model == "gpt-4o-mini"

    def test_devai_from_env_mock(self, monkeypatch):
        monkeypatch.setenv("DEVAI_PROVIDER", "mock")
        ai = DevAI.from_env()
        assert ai.review("def x(): pass") is not None

    def test_devai_from_env_openai(self, monkeypatch):
        monkeypatch.setenv("DEVAI_API_KEY", "test-key")
        monkeypatch.setenv("DEVAI_PROVIDER", "openai")
        ai = DevAI.from_env()
        assert ai.runtime.config.api_key == "test-key"
