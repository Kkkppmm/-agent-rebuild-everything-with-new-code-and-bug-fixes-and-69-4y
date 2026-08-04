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
        (tmp_path / "app.py").write_text("def save(path): open(path, 'w')\n", encoding="utf-8")
        assert FilePermissionAnalyzer(str(tmp_path)).analyze() == []

    def test_detects_world_writable_chmod(self, tmp_path: Path):
        (tmp_path / "setup.py").write_text(
            "import os\n\ndef setup():\n    os.chmod('/tmp/data', 0o777)\n",
            encoding="utf-8",
        )
        findings = FilePermissionAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "world_writable_chmod" for f in findings)


class TestInformationDisclosureAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("def ok(): return 'success'\n", encoding="utf-8")
        assert InformationDisclosureAnalyzer(str(tmp_path)).analyze() == []

    def test_detects_traceback_exposure(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "import traceback\n\ndef err():\n    traceback.print_exc()\n",
            encoding="utf-8",
        )
        findings = InformationDisclosureAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "traceback_exposure" for f in findings)


class TestHeaderInjectionAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "def set_hdr(resp):\n    resp.set_header('X-Custom', 'static')\n",
            encoding="utf-8",
        )
        assert HeaderInjectionAnalyzer(str(tmp_path)).analyze() == []

    def test_detects_user_controlled_header(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "from flask import request\n"
            "def view(resp):\n"
            "    resp.set_header('X-User', request.args.get('name'))\n",
            encoding="utf-8",
        )
        findings = HeaderInjectionAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "user_controlled_header" for f in findings)


class TestMassAssignmentAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "def create_user(name):\n    return {'name': name}\n",
            encoding="utf-8",
        )
        assert MassAssignmentAnalyzer(str(tmp_path)).analyze() == []

    def test_detects_request_to_model(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "from flask import request\n"
            "class User:\n"
            "    def update(self, data): pass\n"
            "def view():\n"
            "    user = User()\n"
            "    user.update(request.form)\n",
            encoding="utf-8",
        )
        findings = MassAssignmentAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "request_to_model" for f in findings)


class TestClickjackingAnalyzer:
    def test_clean_non_web_code(self, tmp_path: Path):
        (tmp_path / "utils.py").write_text("def add(a, b): return a + b\n", encoding="utf-8")
        assert ClickjackingAnalyzer(str(tmp_path)).analyze() == []

    def test_detects_missing_frame_protection(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "from flask import Flask\napp = Flask(__name__)\n",
            encoding="utf-8",
        )
        findings = ClickjackingAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "missing_frame_protection" for f in findings)

    def test_no_finding_with_frame_options(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "from flask import Flask\n"
            "app = Flask(__name__)\n"
            "@app.after_request\n"
            "def add_header(resp):\n"
            "    resp.headers['X-Frame-Options'] = 'DENY'\n"
            "    return resp\n",
            encoding="utf-8",
        )
        assert ClickjackingAnalyzer(str(tmp_path)).analyze() == []


class TestHostHeaderAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("ALLOWED_HOSTS = ['example.com']\n", encoding="utf-8")
        findings = HostHeaderAnalyzer(str(tmp_path)).analyze()
        assert not any(f.pattern == "wildcard_allowed_hosts" for f in findings)

    def test_detects_wildcard_allowed_hosts(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text("ALLOWED_HOSTS = ['*']\n", encoding="utf-8")
        findings = HostHeaderAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "wildcard_allowed_hosts" for f in findings)

    def test_detects_host_in_redirect(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "from flask import request, redirect\n"
            "def go():\n"
            "    return redirect(f'https://{request.host}/home')\n",
            encoding="utf-8",
        )
        findings = HostHeaderAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "host_in_url" for f in findings)


class TestSessionFixationAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("def logout(): pass\n", encoding="utf-8")
        findings = SessionFixationAnalyzer(str(tmp_path)).analyze()
        assert findings == []

    def test_detects_no_session_regeneration(self, tmp_path: Path):
        (tmp_path / "auth.py").write_text(
            "def login(user, password):\n"
            "    if check(user, password):\n"
            "        session['user'] = user\n"
            "        return True\n",
            encoding="utf-8",
        )
        findings = SessionFixationAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "no_session_regeneration" for f in findings)

    def test_detects_session_from_request(self, tmp_path: Path):
        (tmp_path / "auth.py").write_text(
            "from flask import request, session\n"
            "def set_session():\n"
            "    session['id'] = request.cookies.get('sid')\n",
            encoding="utf-8",
        )
        findings = SessionFixationAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "session_from_request" for f in findings)
