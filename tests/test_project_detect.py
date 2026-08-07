"""Tests for ProjectDetector."""

from pathlib import Path

from devai import DevAI, ProjectDetector, ProjectProfile


class TestProjectProfile:
    def test_summary(self):
        profile = ProjectProfile(
            root="/tmp/proj",
            languages=["python"],
            frameworks=["fastapi"],
            package_managers=["pip"],
        )
        assert "python" in profile.summary
        assert "fastapi" in profile.summary

    def test_primary_language(self):
        profile = ProjectProfile(root=".", languages=["python", "javascript"])
        assert profile.primary_language == "python"

    def test_to_context(self):
        profile = ProjectProfile(root="/proj", languages=["python"], has_git=True)
        ctx = profile.to_context()
        assert "python" in ctx
        assert "Git: yes" in ctx


class TestProjectDetector:
    def test_detect_python_project(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "demo"\nrequires-python = ">=3.11"\n'
        )
        (tmp_path / "main.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n")
        (tmp_path / "tests").mkdir()
        (tmp_path / ".git").mkdir()

        profile = ProjectDetector().detect(tmp_path)
        assert "python" in profile.languages
        assert "fastapi" in profile.frameworks
        assert profile.has_git
        assert profile.has_tests
        assert profile.python_version == "3.11"

    def test_detect_node_project(self, tmp_path: Path):
        (tmp_path / "package.json").write_text('{"dependencies": {"react": "18.0.0", "next": "14.0.0"}}')
        (tmp_path / "index.js").write_text("console.log('hi')")

        profile = ProjectDetector().detect(tmp_path)
        assert "javascript" in profile.languages
        assert "react" in profile.frameworks
        assert "next.js" in profile.frameworks
        assert "npm" in profile.package_managers

    def test_detect_missing_path(self):
        import pytest

        with pytest.raises(FileNotFoundError):
            ProjectDetector().detect("/nonexistent/path/xyz")

    def test_facade_detect_project(self, tmp_path: Path):
        (tmp_path / "setup.py").write_text("from setuptools import setup\nsetup(name='x')\n")
        (tmp_path / "app.py").write_text("from flask import Flask\napp = Flask(__name__)\n")

        ai = DevAI.mock()
        profile = ai.detect_project(tmp_path)
        assert isinstance(profile, ProjectProfile)
        assert "python" in profile.languages
        assert "flask" in profile.frameworks
