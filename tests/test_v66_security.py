"""Tests for v6.4–v6.6 security analyzers."""

from pathlib import Path

from devai import (
    ClickjackingAnalyzer,
    FilePermissionAnalyzer,
    HeaderInjectionAnalyzer,
    HostHeaderAnalyzer,
    InformationDisclosureAnalyzer,
    InsecureFileUploadAnalyzer,
    MassAssignmentAnalyzer,
    SessionFixationAnalyzer,
    WeakPasswordAnalyzer,
)


class TestFilePermissionAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("def save(path): open(path, 'w')\n", encoding="utf-8")
        assert FilePermissionAnalyzer(str(tmp_path)).analyze() == []

    def test_detects_permissive_chmod(self, tmp_path: Path):
        (tmp_path / "setup.py").write_text(
            "import os\n\ndef init():\n    os.chmod('/tmp/data', 0o777)\n",
            encoding="utf-8",
        )
        findings = FilePermissionAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "permissive_chmod" for f in findings)


class TestInformationDisclosureAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("def view(): return {'name': 'alice'}\n", encoding="utf-8")
        assert InformationDisclosureAnalyzer(str(tmp_path)).analyze() == []

    def test_detects_sensitive_field(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "def view():\n    return {'password': user.password}\n",
            encoding="utf-8",
        )
        findings = InformationDisclosureAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "sensitive_in_response" for f in findings)


class TestHeaderInjectionAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "def view():\n    response.headers['X-Custom'] = 'static'\n",
            encoding="utf-8",
        )
        assert HeaderInjectionAnalyzer(str(tmp_path)).analyze() == []

    def test_detects_user_input_in_header(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "def view(request):\n    response.set('Location', request.args.get('url'))\n",
            encoding="utf-8",
        )
        findings = HeaderInjectionAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "user_input_in_header" for f in findings)


class TestMassAssignmentAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "def update(user, name):\n    user.name = name\n",
            encoding="utf-8",
        )
        assert MassAssignmentAnalyzer(str(tmp_path)).analyze() == []

    def test_detects_bulk_update(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "def update_user(request, user):\n    user.update(request.json)\n",
            encoding="utf-8",
        )
        findings = MassAssignmentAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "bulk_update_from_request" for f in findings)


class TestClickjackingAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("def helper(): return 1\n", encoding="utf-8")
        assert ClickjackingAnalyzer(str(tmp_path)).analyze() == []

    def test_detects_missing_protection(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "from flask import route\n\n@route('/')\ndef index(): return 'ok'\n",
            encoding="utf-8",
        )
        findings = ClickjackingAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "missing_frame_protection" for f in findings)


class TestHostHeaderAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("def home(): return 'ok'\n", encoding="utf-8")
        assert HostHeaderAnalyzer(str(tmp_path)).analyze() == []

    def test_detects_host_in_redirect(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "def redirect_home(request):\n    return redirect(request.host)\n",
            encoding="utf-8",
        )
        findings = HostHeaderAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "host_in_redirect" for f in findings)


class TestSessionFixationAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("def logout(): pass\n", encoding="utf-8")
        assert SessionFixationAnalyzer(str(tmp_path)).analyze() == []

    def test_detects_missing_regeneration(self, tmp_path: Path):
        (tmp_path / "auth.py").write_text(
            "def login(request, user):\n    session['user'] = user.id\n",
            encoding="utf-8",
        )
        findings = SessionFixationAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "missing_session_regeneration" for f in findings)


class TestInsecureFileUploadAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("def index(): return 'ok'\n", encoding="utf-8")
        assert InsecureFileUploadAnalyzer(str(tmp_path)).analyze() == []

    def test_detects_unvalidated_upload(self, tmp_path: Path):
        (tmp_path / "upload.py").write_text(
            "def upload(request):\n    f = request.files['doc']\n    f.save('/tmp/out')\n",
            encoding="utf-8",
        )
        findings = InsecureFileUploadAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "unvalidated_upload" for f in findings)


class TestWeakPasswordAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "auth.py").write_text(
            "import bcrypt\n\ndef hash_pw(p):\n    return bcrypt.hashpw(p, bcrypt.gensalt())\n",
            encoding="utf-8",
        )
        findings = WeakPasswordAnalyzer(str(tmp_path)).analyze()
        assert not any(f.pattern == "plaintext_password" for f in findings)

    def test_detects_plaintext_password(self, tmp_path: Path):
        (tmp_path / "user.py").write_text(
            "class User:\n    def set_password(self, p):\n        self.password = p\n",
            encoding="utf-8",
        )
        findings = WeakPasswordAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "plaintext_password" for f in findings)

    def test_detects_weak_length(self, tmp_path: Path):
        (tmp_path / "auth.py").write_text(
            "def validate(password):\n    return len(password) >= 4\n",
            encoding="utf-8",
        )
        findings = WeakPasswordAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "weak_length_check" for f in findings)
