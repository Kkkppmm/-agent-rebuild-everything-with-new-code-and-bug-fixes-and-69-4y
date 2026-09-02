"""Tests for v6.8.0 security analyzers."""

from pathlib import Path

from devai import (
    BrokenAuthAnalyzer,
    GraphQLInjectionAnalyzer,
    InsecureTempfileAnalyzer,
)


class TestInsecureTempfileAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "import tempfile\n\n"
            "def write_temp(data):\n"
            "    with tempfile.NamedTemporaryFile() as f:\n"
            "        f.write(data)\n",
            encoding="utf-8",
        )
        assert InsecureTempfileAnalyzer(str(tmp_path)).analyze() == []

    def test_detects_mktemp(self, tmp_path: Path):
        (tmp_path / "legacy.py").write_text(
            "import tempfile\n\n"
            "def get_path():\n"
            "    return tempfile.mktemp()\n",
            encoding="utf-8",
        )
        findings = InsecureTempfileAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "insecure_temp_api" for f in findings)

    def test_detects_delete_false(self, tmp_path: Path):
        (tmp_path / "upload.py").write_text(
            "import tempfile\n\n"
            "def save(data):\n"
            "  f = tempfile.NamedTemporaryFile(delete=False)\n"
            "  f.write(data)\n",
            encoding="utf-8",
        )
        findings = InsecureTempfileAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "persistent_tempfile" for f in findings)


class TestGraphQLInjectionAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "api.py").write_text(
            'QUERY = """\n'
            "query GetUser($id: ID!) {\n"
            "  user(id: $id) { name }\n"
            "}\n"
            '"""\n',
            encoding="utf-8",
        )
        assert GraphQLInjectionAnalyzer(str(tmp_path)).analyze() == []

    def test_detects_fstring_query(self, tmp_path: Path):
        (tmp_path / "client.py").write_text(
            "def fetch_user(client, user_id):\n"
            '    query = f"query {{ user(id: {user_id}) {{ name }} }}"\n'
            "    return client.execute(query)\n",
            encoding="utf-8",
        )
        findings = GraphQLInjectionAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "dynamic_graphql_query" for f in findings)

    def test_detects_dynamic_execute(self, tmp_path: Path):
        (tmp_path / "gql.py").write_text(
            "def run(client, name):\n"
            '    return client.execute(f"query {{ search(q: \\"{name}\\") {{ id }} }}")\n',
            encoding="utf-8",
        )
        findings = GraphQLInjectionAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "dynamic_graphql_query" for f in findings)


class TestBrokenAuthAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "auth.py").write_text(
            "from functools import wraps\n\n"
            "def login_required(fn):\n"
            "    @wraps(fn)\n"
            "    def wrapper(*args, **kwargs):\n"
            "        return fn(*args, **kwargs)\n"
            "    return wrapper\n",
            encoding="utf-8",
        )
        assert BrokenAuthAnalyzer(str(tmp_path)).analyze() == []

    def test_detects_hardcoded_bypass(self, tmp_path: Path):
        (tmp_path / "login.py").write_text(
            "def login(username, password):\n"
            '    if username == "admin" and password == "password":\n'
            "        return True\n"
            "    return False\n",
            encoding="utf-8",
        )
        findings = BrokenAuthAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "hardcoded_auth_bypass" for f in findings)

    def test_detects_auth_disabled(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text("authenticate = False\n", encoding="utf-8")
        findings = BrokenAuthAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "auth_disabled" for f in findings)

    def test_detects_session_shortcut(self, tmp_path: Path):
        (tmp_path / "views.py").write_text(
            "def login(request):\n"
            "    session['authenticated'] = True\n"
            "    return redirect('/')\n",
            encoding="utf-8",
        )
        findings = BrokenAuthAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "session_auth_shortcut" for f in findings)
