"""Tests for v6.3.0 security analyzers."""

from pathlib import Path

from devai import (
    HeaderInjectionAnalyzer,
    MassAssignmentAnalyzer,
    SecurityScanner,
)


class TestHeaderInjectionAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "def view():\n    return 'ok'\n",
            encoding="utf-8",
        )
        assert HeaderInjectionAnalyzer(str(tmp_path)).analyze() == []

    def test_detects_set_cookie_user_value(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "from flask import request, response\n"
            "def view():\n"
            "    response.set_cookie('sid', request.args.get('val'))\n",
            encoding="utf-8",
        )
        findings = HeaderInjectionAnalyzer(str(tmp_path)).analyze()
        assert len(findings) >= 1
        assert any(f.pattern == "cookie_value_injection" for f in findings)

    def test_detects_response_header_user_value(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "from flask import request\n"
            "def view(response):\n"
            "    response.headers.set('X-Custom', request.args.get('h'))\n",
            encoding="utf-8",
        )
        findings = HeaderInjectionAnalyzer(str(tmp_path)).analyze()
        assert any("user_value" in f.pattern for f in findings)


class TestMassAssignmentAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "models.py").write_text(
            "class User:\n    def __init__(self, name):\n        self.name = name\n",
            encoding="utf-8",
        )
        assert MassAssignmentAnalyzer(str(tmp_path)).analyze() == []

    def test_detects_model_from_request_dict(self, tmp_path: Path):
        (tmp_path / "views.py").write_text(
            "from flask import request\n"
            "class User:\n    pass\n"
            "def create_user():\n"
            "    user = User(**request.json)\n",
            encoding="utf-8",
        )
        findings = MassAssignmentAnalyzer(str(tmp_path)).analyze()
        assert len(findings) >= 1
        assert any(f.pattern == "model_from_request_dict" for f in findings)

    def test_detects_orm_create_from_request(self, tmp_path: Path):
        (tmp_path / "views.py").write_text(
            "from flask import request\n"
            "class User:\n"
            "    objects = None\n"
            "def create_user():\n"
            "    User.objects.create(**request.form)\n",
            encoding="utf-8",
        )
        findings = MassAssignmentAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "orm_create_from_request" for f in findings)

    def test_detects_update_from_request(self, tmp_path: Path):
        (tmp_path / "views.py").write_text(
            "from flask import request\n"
            "def update_profile(user):\n"
            "    user.update(request.json)\n",
            encoding="utf-8",
        )
        findings = MassAssignmentAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "update_from_request" for f in findings)


class TestSecurityScannerV63:
    def test_includes_new_checks(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "from flask import request, response\n"
            "class User:\n"
            "    objects = None\n"
            "def view():\n"
            "    response.set_cookie('sid', request.args.get('v'))\n"
            "    User.objects.create(**request.json)\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path)).scan()
        names = {cat.name for cat in report.categories}
        assert "header_injection" in names
        assert "mass_assignment" in names
