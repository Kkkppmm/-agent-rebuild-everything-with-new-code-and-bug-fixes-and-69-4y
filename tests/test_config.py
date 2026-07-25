"""Tests for config."""


from devai.core.config import DevAIConfig


def test_config_defaults():
    config = DevAIConfig()
    assert config.model == "gpt-4o-mini"
    assert config.temperature == 0.7


def test_config_from_env(monkeypatch):
    monkeypatch.setenv("DEVAI_API_KEY", "test-key")
    monkeypatch.setenv("DEVAI_MODEL", "gpt-4o")
    config = DevAIConfig.from_env()
    assert config.api_key == "test-key"
    assert config.model == "gpt-4o"


def test_config_with_overrides():
    config = DevAIConfig(model="a").with_overrides(model="b", temperature=0.1)
    assert config.model == "b"
    assert config.temperature == 0.1
