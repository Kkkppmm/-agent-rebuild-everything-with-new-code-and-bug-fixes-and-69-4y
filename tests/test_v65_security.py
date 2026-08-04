"""Tests for v6.4.0 and v6.5.0 security analyzers."""

from pathlib import Path

from devai import (
    ClickjackingAnalyzer,
    FilePermissionAnalyzer,
    HeaderInjectionAnalyzer,
    HostHeaderAnalyzer,
    InformationDisclosureAnalyzer,
    MassAssignmentAnalyzer,
    SessionFixationAnalyzer,
)


class TestFilePermissionAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("def save(): return True\n", encoding="utf-8")
        assert FilePermissionAnalyzer(str(tmp_path)).analyze() == []

    def test_detects_chmod_777(self, tmp_path: Path):
        (tmp_path / "perms.py").write_text(
            "import os\n\ndef make_writable(path):\n    os.chmod(path, 0o777)\n",
            encoding="utf-8",
        )
        findings = FilePermissionAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "world_writable_chmod" for f in findings)


class TestInformationDisclosureAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("def log(msg): pass\n", encoding="utf-8")
        assert InformationDisclosureAnalyzer(str(tmp_path)).analyze() == []

    def test_detects_password_print(self, tmp_path: Path):
        (tmp_path / "auth.py").write_text(
            "def login(password):\n    print(password)\n",
            encoding="utf-8",
        )
        findings = InformationDisclosureAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "sensitive_in_output" for f in findings)


class TestHeaderInjectionAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "def set_header(resp):\n    resp.set_header('X-Custom', 'static')\n",
            encoding="utf-8",
        )
        assert HeaderInjectionAnalyzer(str(tmp_path)).analyze() == []

    def test_detects_user_header(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "def view(request, response):\n"
            "    response.set_header('X-Name', request.form.get('name'))\n",
            encoding="utf-8",
        )
        findings = HeaderInjectionAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "user_value_in_header" for f in findings)


class TestMassAssignmentAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "def update(user):\n    user.update({'name': 'alice'})\n",
            encoding="utf-8",
        )
        assert MassAssignmentAnalyzer(str(tmp_path)).analyze() == []

    def test_detects_request_update(self, tmp_path: Path):
        (tmp_path / "api.py").write_text(
            "def update_user(user, request):\n    user.update(request.data)\n",
            encoding="utf-8",
        )
        findings = MassAssignmentAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "bulk_update_from_request" for f in findings)


class TestClickjackingAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("def helper(): return 1\n", encoding="utf-8")
        assert ClickjackingAnalyzer(str(tmp_path)).analyze() == []

    def test_detects_missing_protection(self, tmp_path: Path):
        (tmp_path / "views.py").write_text(
            "from flask import Flask\napp = Flask(__name__)\n"
            "@app.route('/')\ndef index(): return 'hi'\n",
            encoding="utf-8",
        )
        findings = ClickjackingAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "missing_frame_protection" for f in findings)


class TestHostHeaderAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("def home(): return 'ok'\n", encoding="utf-8")
        assert HostHeaderAnalyzer(str(tmp_path)).analyze() == []

    def test_detects_host_redirect(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "def redirect_home(request):\n    return redirect(request.host)\n",
            encoding="utf-8",
        )
        findings = HostHeaderAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "host_redirect" for f in findings)


class TestSessionFixationAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "auth.py").write_text(
            "def login(user):\n    session.cycle_key()\n    return user\n",
            encoding="utf-8",
        )
        assert SessionFixationAnalyzer(str(tmp_path)).analyze() == []

    def test_detects_missing_regen(self, tmp_path: Path):
        (tmp_path / "auth.py").write_text(
            "def login(user, password):\n    return authenticate(user, password)\n",
            encoding="utf-8",
        )
        findings = SessionFixationAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "missing_session_regen" for f in findings)
