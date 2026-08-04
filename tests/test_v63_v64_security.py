"""Tests for v6.3.0 and v6.4.0 security analyzers."""

from pathlib import Path

from devai import (
    FilePermissionAnalyzer,
    HeaderInjectionAnalyzer,
    InformationDisclosureAnalyzer,
    MassAssignmentAnalyzer,
)


class TestHeaderInjectionAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "def view():\n    return 'ok'\n",
            encoding="utf-8",
        )
        assert HeaderInjectionAnalyzer(str(tmp_path)).analyze() == []

    def test_detects_response_header_assign(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "from flask import request, make_response\n"
            "def view():\n"
            "    resp = make_response()\n"
            "    resp.headers['X-Custom'] = request.args.get('val')\n"
            "    return resp\n",
            encoding="utf-8",
        )
        findings = HeaderInjectionAnalyzer(str(tmp_path)).analyze()
        assert len(findings) >= 1
        assert any(f.pattern == "response_header_assign" for f in findings)

    def test_detects_redirect_user_input(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "from flask import redirect, request\n"
            "def view():\n"
            "    return redirect(request.args.get('url'))\n",
            encoding="utf-8",
        )
        findings = HeaderInjectionAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "redirect_user_input" for f in findings)


class TestMassAssignmentAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "models.py").write_text(
            "class User:\n    def create(self, name):\n        pass\n",
            encoding="utf-8",
        )
        assert MassAssignmentAnalyzer(str(tmp_path)).analyze() == []

    def test_detects_orm_unpack_request(self, tmp_path: Path):
        (tmp_path / "views.py").write_text(
            "from django.http import request\n"
            "def create_user():\n"
            "    User.objects.create(**request.data)\n",
            encoding="utf-8",
        )
        findings = MassAssignmentAnalyzer(str(tmp_path)).analyze()
        assert len(findings) >= 1
        assert any(f.pattern == "orm_unpack_request" for f in findings)

    def test_detects_setattr_request(self, tmp_path: Path):
        (tmp_path / "views.py").write_text(
            "def update(obj, request):\n"
            "    setattr(obj, 'name', request.data)\n",
            encoding="utf-8",
        )
        findings = MassAssignmentAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "setattr_request" for f in findings)


class TestFilePermissionAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "file.py").write_text(
            "import os\n\ndef write(path):\n    os.chmod(path, 0o600)\n",
            encoding="utf-8",
        )
        assert FilePermissionAnalyzer(str(tmp_path)).analyze() == []

    def test_detects_chmod_777(self, tmp_path: Path):
        (tmp_path / "file.py").write_text(
            "import os\n\ndef write(path):\n    os.chmod(path, 0o777)\n",
            encoding="utf-8",
        )
        findings = FilePermissionAnalyzer(str(tmp_path)).analyze()
        assert len(findings) >= 1
        assert any(f.pattern == "chmod_world_writable" for f in findings)

    def test_detects_makedirs_world_writable(self, tmp_path: Path):
        (tmp_path / "file.py").write_text(
            "import os\n\ndef setup(path):\n    os.makedirs(path, mode=0o777)\n",
            encoding="utf-8",
        )
        findings = FilePermissionAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "makedirs_world_writable" for f in findings)


class TestInformationDisclosureAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "def view():\n    return {'status': 'ok'}\n",
            encoding="utf-8",
        )
        assert InformationDisclosureAnalyzer(str(tmp_path)).analyze() == []

    def test_detects_return_exception_string(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "def view():\n"
            "    try:\n"
            "        risky()\n"
            "    except Exception as e:\n"
            "        return str(e)\n",
            encoding="utf-8",
        )
        findings = InformationDisclosureAnalyzer(str(tmp_path)).analyze()
        assert len(findings) >= 1
        assert any(f.pattern == "return_exception_string" for f in findings)

    def test_detects_print_sensitive(self, tmp_path: Path):
        (tmp_path / "auth.py").write_text(
            "def login(password):\n    print(password)\n",
            encoding="utf-8",
        )
        findings = InformationDisclosureAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "print_sensitive" for f in findings)
