"""Tests for v7.68.0 Django, FastAPI, and Flask analyzer integration."""

from pathlib import Path

from devai import DevAI, DjangoAnalyzer, FastAPIAnalyzer, FlaskAnalyzer
from devai.project_health import ProjectHealth

HARDENED_DJANGO_SETTINGS = """\
import os

DEBUG = os.environ.get("DJANGO_DEBUG", "false").lower() == "true"
SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]
ALLOWED_HOSTS = os.environ.get("DJANGO_ALLOWED_HOSTS", "").split(",")
"""

HARDENED_FASTAPI_APP = """\
import os
from fastapi import FastAPI

DEBUG = os.environ.get("FASTAPI_DEBUG", "false").lower() == "true"
app = FastAPI(docs_url="/docs" if DEBUG else None)
"""

HARDENED_FLASK_APP = """\
import os
from flask import Flask

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ["FLASK_SECRET_KEY"]
"""


class TestV768WebFrameworkIntegration:
    def test_facade_django(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(HARDENED_DJANGO_SETTINGS, encoding="utf-8")
        analyzer = DevAI.mock().django(tmp_path)
        assert isinstance(analyzer, DjangoAnalyzer)
        assert analyzer.stats.configs == 1

    def test_facade_fastapi(self, tmp_path: Path):
        (tmp_path / "main.py").write_text(HARDENED_FASTAPI_APP, encoding="utf-8")
        analyzer = DevAI.mock().fastapi(tmp_path)
        assert isinstance(analyzer, FastAPIAnalyzer)
        assert analyzer.stats.configs == 1

    def test_facade_flask(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(HARDENED_FLASK_APP, encoding="utf-8")
        analyzer = DevAI.mock().flask(tmp_path)
        assert isinstance(analyzer, FlaskAnalyzer)
        assert analyzer.stats.configs == 1

    def test_project_health_includes_django_category(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(HARDENED_DJANGO_SETTINGS, encoding="utf-8")
        report = ProjectHealth(str(tmp_path)).analyze()
        names = {cat.name for cat in report.categories}
        assert "django" in names

    def test_project_health_includes_fastapi_category(self, tmp_path: Path):
        (tmp_path / "main.py").write_text(HARDENED_FASTAPI_APP, encoding="utf-8")
        report = ProjectHealth(str(tmp_path)).analyze()
        names = {cat.name for cat in report.categories}
        assert "fastapi" in names

    def test_project_health_includes_flask_category(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(HARDENED_FLASK_APP, encoding="utf-8")
        report = ProjectHealth(str(tmp_path)).analyze()
        names = {cat.name for cat in report.categories}
        assert "flask" in names

    def test_public_exports(self):
        from devai import (
            DjangoFinding,
            DjangoInfo,
            DjangoStats,
            FastAPIFinding,
            FastAPIInfo,
            FastAPIStats,
            FlaskFinding,
            FlaskInfo,
            FlaskStats,
        )

        assert DjangoAnalyzer is not None
        assert FastAPIAnalyzer is not None
        assert FlaskAnalyzer is not None
        assert DjangoFinding is not None
        assert FastAPIFinding is not None
        assert FlaskFinding is not None
        assert DjangoInfo is not None
        assert FastAPIInfo is not None
        assert FlaskInfo is not None
        assert DjangoStats is not None
        assert FastAPIStats is not None
        assert FlaskStats is not None
