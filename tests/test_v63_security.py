"""Tests for v6.3.0 security analyzers."""

from pathlib import Path

from devai import (
    HeaderInjectionAnalyzer,
    MassAssignmentAnalyzer,
)


class TestHeaderInjectionAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "def view():\n    return {'status': 'ok'}\n",
            encoding="utf-8",
        )
        assert HeaderInjectionAnalyzer(str(tmp_path)).analyze() == []

    def test_detects_redirect_user_input(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "from flask import redirect, request\n"
            "def view():\n"
            "    return redirect(request.args.get('next'))\n",
            encoding="utf-8",
        )
        findings = HeaderInjectionAnalyzer(str(tmp_path)).analyze()
        assert len(findings) >= 1
        assert any(f.pattern == "redirect_user_input" for f in findings)

    def test_detects_header_user_input(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "from flask import make_response, request\n"
            "def view():\n"
            "    resp = make_response('ok')\n"
            "    resp.headers['X-Custom'] = request.args.get('name')\n"
            "    return resp\n",
            encoding="utf-8",
        )
        findings = HeaderInjectionAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern in {"header_subscript_assign", "header_user_input"} for f in findings)


class TestMassAssignmentAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "def create_user(name, email):\n    return {'name': name, 'email': email}\n",
            encoding="utf-8",
        )
        assert MassAssignmentAnalyzer(str(tmp_path)).analyze() == []

    def test_detects_kwargs_unpack(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "from flask import request\n"
            "class User:\n"
            "    def __init__(self, **kwargs):\n"
            "        self.__dict__.update(kwargs)\n"
            "def create():\n"
            "    return User(**request.json)\n",
            encoding="utf-8",
        )
        findings = MassAssignmentAnalyzer(str(tmp_path)).analyze()
        assert len(findings) >= 1
        assert any(f.pattern == "kwargs_unpack_request" for f in findings)

    def test_detects_dict_update(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "from flask import request\n"
            "def update_user(user):\n"
            "    user.__dict__.update(request.json)\n",
            encoding="utf-8",
        )
        findings = MassAssignmentAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "dict_update_request" for f in findings)
