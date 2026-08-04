"""Tests for v6.4.0 security analyzers."""

from pathlib import Path

from devai import (
    FilePermissionAnalyzer,
    HeaderInjectionAnalyzer,
    InformationDisclosureAnalyzer,
    MassAssignmentAnalyzer,
    SecurityScanner,
)


class TestHeaderInjectionAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "def view():\n    return {'ok': True}\n",
            encoding="utf-8",
        )
        assert HeaderInjectionAnalyzer(str(tmp_path)).analyze() == []

    def test_detects_response_header_assign(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "from flask import request, make_response\n"
            "def view():\n"
            "    resp = make_response('ok')\n"
            "    resp.headers['X-Custom'] = request.args.get('name')\n"
            "    return resp\n",
            encoding="utf-8",
        )
        findings = HeaderInjectionAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "response_header_assign" for f in findings)

    def test_detects_set_header(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "def set_hdr(response, user_input):\n"
            "    response.set_header('Location', user_input)\n",
            encoding="utf-8",
        )
        findings = HeaderInjectionAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "set_header_user_value" for f in findings)


class TestMassAssignmentAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "views.py").write_text(
            "def create_user(name):\n    return {'name': name}\n",
            encoding="utf-8",
        )
        assert MassAssignmentAnalyzer(str(tmp_path)).analyze() == []

    def test_detects_orm_kwargs_unpack(self, tmp_path: Path):
        (tmp_path / "views.py").write_text(
            "class User:\n"
            "    @classmethod\n"
            "    def create(cls, **kwargs):\n        pass\n\n"
            "def register(request):\n"
            "    return User.create(**request.json)\n",
            encoding="utf-8",
        )
        findings = MassAssignmentAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "orm_kwargs_unpack" for f in findings)

    def test_detects_dict_unpack(self, tmp_path: Path):
        (tmp_path / "views.py").write_text(
            "def update_record(model, data):\n"
            "    return model.update(**data)\n",
            encoding="utf-8",
        )
        findings = MassAssignmentAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "orm_kwargs_unpack" for f in findings)


class TestFilePermissionAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "io.py").write_text(
            "def write_file(path, content):\n"
            "  with open(path, 'w') as f:\n"
            "    f.write(content)\n",
            encoding="utf-8",
        )
        assert FilePermissionAnalyzer(str(tmp_path)).analyze() == []

    def test_detects_chmod_world_writable(self, tmp_path: Path):
        (tmp_path / "io.py").write_text(
            "import os\n\ndef make_public(path):\n    os.chmod(path, 0o777)\n",
            encoding="utf-8",
        )
        findings = FilePermissionAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "chmod_world_writable" for f in findings)

    def test_detects_makedirs_mode(self, tmp_path: Path):
        (tmp_path / "io.py").write_text(
            "import os\n\ndef ensure_dir(path):\n    os.makedirs(path, mode=0o777)\n",
            encoding="utf-8",
        )
        findings = FilePermissionAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "makedirs_world_writable" for f in findings)


class TestInformationDisclosureAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "api.py").write_text(
            "def health():\n    return {'status': 'ok'}\n",
            encoding="utf-8",
        )
        assert InformationDisclosureAnalyzer(str(tmp_path)).analyze() == []

    def test_detects_sensitive_response_field(self, tmp_path: Path):
        (tmp_path / "api.py").write_text(
            "def login(user):\n    return {'username': user, 'password': user.password}\n",
            encoding="utf-8",
        )
        findings = InformationDisclosureAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "sensitive_field_in_response" for f in findings)

    def test_detects_sensitive_logging(self, tmp_path: Path):
        (tmp_path / "api.py").write_text(
            "import logging\n"
            "log = logging.getLogger(__name__)\n"
            "def auth(token):\n"
            "    log.info(f'Auth with {token=}')\n",
            encoding="utf-8",
        )
        findings = InformationDisclosureAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "sensitive_data_logged" for f in findings)


class TestSecurityScannerV64:
    def test_includes_new_checks(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("def ok(): return 1\n", encoding="utf-8")
        report = SecurityScanner(str(tmp_path)).scan()
        names = {cat.name for cat in report.categories}
        assert "header_injection" in names
        assert "mass_assignment" in names
        assert "file_permissions" in names
        assert "information_disclosure" in names

    def test_recommendations_for_header_injection(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "def set_hdr(response, user_input):\n"
            "    response.set_header('X', user_input)\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("header_injection",)).scan()
        assert any("header" in rec.lower() for rec in report.recommendations)
