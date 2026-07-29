"""Tests for config file loading."""

from pathlib import Path

import pytest

from devai.config_file import config_file_template, find_config_file, load_config_file
from devai.core import DevAIConfig


class TestConfigFile:
    def test_template(self):
        template = config_file_template()
        assert "model:" in template

    def test_find_and_load(self, tmp_path: Path):
        config_path = tmp_path / ".devai.yaml"
        config_path.write_text("model: test-model\ntemperature: 0.5\n")
        found = find_config_file(tmp_path)
        assert found == config_path
        config = load_config_file(found)
        assert isinstance(config, DevAIConfig)
        assert config.model == "test-model"
        assert config.temperature == 0.5

    def test_load_json(self, tmp_path: Path):
        config_path = tmp_path / ".devai.json"
        config_path.write_text('{"model": "json-model", "max_tokens": 2048}')
        config = load_config_file(config_path)
        assert config.model == "json-model"
        assert config.max_tokens == 2048

    def test_missing_config(self):
        with pytest.raises(FileNotFoundError):
            load_config_file()
