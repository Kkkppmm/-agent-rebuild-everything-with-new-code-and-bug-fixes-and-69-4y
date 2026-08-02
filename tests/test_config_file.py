"""Tests for config file loading."""

import json
from pathlib import Path

import pytest

from devai.config_file import (
    CONFIG_FILENAMES,
    config_file_template,
    find_config_file,
    load_config_file,
)
from devai.core.exceptions import ConfigError
from devai.runtime import DevRuntime


class TestConfigFile:
    def test_find_config_file(self, tmp_path):
        config_path = tmp_path / ".devai.yaml"
        config_path.write_text("model: test-model\n", encoding="utf-8")
        nested = tmp_path / "src" / "pkg"
        nested.mkdir(parents=True)
        found = find_config_file(nested)
        assert found == config_path

    def test_load_json_config(self, tmp_path):
        path = tmp_path / "devai.json"
        path.write_text(
            json.dumps({"provider": "mock", "model": "bench-model"}),
            encoding="utf-8",
        )
        config = load_config_file(path)
        assert config.api_key == "mock"
        assert config.model == "bench-model"

    def test_load_yaml_config(self, tmp_path):
        pytest.importorskip("yaml")
        path = tmp_path / ".devai.yaml"
        path.write_text("provider: ollama\nmodel: codellama\n", encoding="utf-8")
        config = load_config_file(path)
        assert config.model == "codellama"
        assert "11434" in config.base_url

    def test_load_with_overrides(self, tmp_path):
        path = tmp_path / "devai.json"
        path.write_text(json.dumps({"provider": "mock", "model": "a"}), encoding="utf-8")
        config = load_config_file(path, overrides={"model": "b"})
        assert config.model == "b"

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(ConfigError):
            load_config_file(tmp_path / "missing.json")

    def test_template_contains_provider(self):
        body = config_file_template(provider="ollama", model="llama3.2")
        assert "provider: ollama" in body
        assert "model: llama3.2" in body

    def test_config_filenames_not_empty(self):
        assert ".devai.yaml" in CONFIG_FILENAMES


class TestDevRuntimeFromProject:
    def test_from_project_mock(self, tmp_path):
        runtime = DevRuntime.from_project(tmp_path, use_mock=True)
        assert runtime.config.api_key == "mock"

    def test_from_project_loads_config(self, tmp_path):
        path = tmp_path / ".devai.yaml"
        path.write_text("provider: mock\nmodel: project-model\n", encoding="utf-8")
        runtime = DevRuntime.from_project(tmp_path)
        assert runtime.config.model == "project-model"
