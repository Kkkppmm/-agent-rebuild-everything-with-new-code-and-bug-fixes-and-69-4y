"""Tests for v6.4.0 security analyzers."""

from pathlib import Path

from devai import (
    FilePermissionAnalyzer,
    HeaderInjectionAnalyzer,
    InformationDisclosureAnalyzer,
    MassAssignmentAnalyzer,
    SecurityScanner,
)


class TestFilePermissionAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("def save(path):\n    open(path, 'w').close()\n", encoding="utf-8")
        assert FilePermissionAnalyzer(str(tmp_path)).analyze() == []

    def test_detects_chmod_777(self, tmp_path: Path):
        (tmp_path / "setup.py").write_text(
            "import os\n\ndef setup():\n    os.chmod('/tmp/data', 0o777)\n",
            encoding="utf-8",
        )
        findings = FilePermissionAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "world_writable_chmod" for f in findings)


class TestInformationDisclosureAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("def ok():\n    return {'status': 'ok'}\n", encoding="utf-8")
        assert InformationDisclosureAnalyzer(str(tmp_path)).analyze() == []

    def test_detects_traceback_return(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "import traceback\n\ndef error():\n    return traceback.format_exc()\n",
            encoding="utf-8",
        )
        findings = InformationDisclosureAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "traceback_in_response" for f in findings)

    def test_detects_jsonify_vars(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "from flask import jsonify\n\ndef view(user):\n    return jsonify(vars(user))\n",
            encoding="utf-8",
        )
        findings = InformationDisclosureAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "jsonify_vars" for f in findings)


class TestHeaderInjectionAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("def ok():\n    return '/home'\n", encoding="utf-8")
        assert HeaderInjectionAnalyzer(str(tmp_path)).analyze() == []

    def test_detects_user_redirect(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "from flask import redirect, request\n\ndef view():\n    return redirect(request.args.get('next'))\n",
            encoding="utf-8",
        )
        findings = HeaderInjectionAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "user_controlled_redirect" for f in findings)


class TestMassAssignmentAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "def update_user(user, name):\n    user.name = name\n",
            encoding="utf-8",
        )
        assert MassAssignmentAnalyzer(str(tmp_path)).analyze() == []

    def test_detects_model_from_request(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "from flask import request\n\ndef create():\n    user = User(request.json)\n    return user\n",
            encoding="utf-8",
        )
        findings = MassAssignmentAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "model_from_request" for f in findings)

    def test_detects_update_from_request(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "from flask import request\n\ndef patch(user):\n    user.update(request.json)\n",
            encoding="utf-8",
        )
        findings = MassAssignmentAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "update_from_request" for f in findings)


class TestSecurityScannerV64:
    def test_includes_new_checks(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("def ok():\n    return 1\n", encoding="utf-8")
        report = SecurityScanner(str(tmp_path)).scan()
        names = {cat.name for cat in report.categories}
        assert "file_permissions" in names
        assert "information_disclosure" in names
        assert "header_injection" in names
        assert "mass_assignment" in names
