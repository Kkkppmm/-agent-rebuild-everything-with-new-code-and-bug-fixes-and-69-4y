"""Tests for v6.4.0 security analyzers."""

from pathlib import Path

from devai import (
    FilePermissionAnalyzer,
    InformationDisclosureAnalyzer,
    SecurityScanner,
)


class TestFilePermissionAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "import os\n"
            "def save(path):\n"
            "    os.chmod(path, 0o600)\n",
            encoding="utf-8",
        )
        assert FilePermissionAnalyzer(str(tmp_path)).analyze() == []

    def test_detects_world_writable_chmod(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "import os\n"
            "def save(path):\n"
            "    os.chmod(path, 0o777)\n",
            encoding="utf-8",
        )
        findings = FilePermissionAnalyzer(str(tmp_path)).analyze()
        assert len(findings) >= 1
        assert any(f.pattern == "world_writable_chmod" for f in findings)

    def test_detects_path_chmod(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "from pathlib import Path\n"
            "def save(p):\n"
            "    Path(p).chmod(0o666)\n",
            encoding="utf-8",
        )
        findings = FilePermissionAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "world_writable_chmod" for f in findings)


class TestInformationDisclosureAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "def view():\n"
            "    return {'status': 'ok'}\n",
            encoding="utf-8",
        )
        assert InformationDisclosureAnalyzer(str(tmp_path)).analyze() == []

    def test_detects_sensitive_field_in_response(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "def get_user(user):\n"
            "    return {'name': user.name, 'password': user.password}\n",
            encoding="utf-8",
        )
        findings = InformationDisclosureAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "sensitive_field_in_response" for f in findings)

    def test_detects_traceback_in_jsonify(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "import traceback\n"
            "from flask import jsonify\n"
            "def view():\n"
            "    return jsonify({'error': traceback.format_exc()})\n",
            encoding="utf-8",
        )
        findings = InformationDisclosureAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "traceback_in_response" for f in findings)

    def test_detects_exception_message_in_response(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "def view():\n"
            "    try:\n"
            "        risky()\n"
            "    except Exception as e:\n"
            "        return str(e)\n",
            encoding="utf-8",
        )
        findings = InformationDisclosureAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "exception_message_in_response" for f in findings)


class TestSecurityScannerV64:
    def test_includes_new_checks(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "import os, traceback\n"
            "from flask import jsonify\n"
            "def view():\n"
            "    os.chmod('/tmp/data', 0o777)\n"
            "    return jsonify({'error': traceback.format_exc(), 'password': 'x'})\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path)).scan()
        names = {cat.name for cat in report.categories}
        assert "file_permissions" in names
        assert "info_disclosure" in names
