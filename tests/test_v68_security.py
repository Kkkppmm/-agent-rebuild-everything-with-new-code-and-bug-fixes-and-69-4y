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
            "def save(data):\n"
            "    with tempfile.NamedTemporaryFile(delete=False) as f:\n"
            "        f.write(data)\n"
            "        return f.name\n",
            encoding="utf-8",
        )
        assert InsecureTempfileAnalyzer(str(tmp_path)).analyze() == []

    def test_detects_mktemp(self, tmp_path: Path):
        (tmp_path / "bad.py").write_text(
            "import tempfile\n\n"
            "def get_path():\n"
            "    return tempfile.mktemp()\n",
            encoding="utf-8",
        )
        findings = InsecureTempfileAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "mktemp" for f in findings)

    def test_detects_os_mktemp(self, tmp_path: Path):
        (tmp_path / "legacy.py").write_text(
            "import os\n\npath = os.mktemp()\n",
            encoding="utf-8",
        )
        findings = InsecureTempfileAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "os_mktemp" for f in findings)


class TestGraphQLInjectionAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "client.py").write_text(
            'QUERY = """query GetUser($id: ID!) { user(id: $id) { name } }"""\n'
            "def fetch(client, user_id):\n"
            "    return client.execute(QUERY, variables={'id': user_id})\n",
            encoding="utf-8",
        )
        assert GraphQLInjectionAnalyzer(str(tmp_path)).analyze() == []

    def test_detects_fstring_graphql(self, tmp_path: Path):
        (tmp_path / "api.py").write_text(
            "def fetch_user(user_id):\n"
            '    query = f"query {{ user(id: {user_id}) {{ name }} }}"\n'
            "    return client.execute(query)\n",
            encoding="utf-8",
        )
        findings = GraphQLInjectionAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "fstring_graphql" for f in findings)

    def test_detects_concat_graphql(self, tmp_path: Path):
        (tmp_path / "api.py").write_text(
            "def delete_item(item_id):\n"
            '    query = "mutation { deleteItem(id: " + item_id + ") { ok } }"\n'
            "    return client.execute(query)\n",
            encoding="utf-8",
        )
        findings = GraphQLInjectionAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "concat_graphql" for f in findings)


class TestBrokenAuthAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "views.py").write_text(
            "from flask_login import login_required\n\n"
            "@app.route('/admin')\n"
            "@login_required\n"
            "def admin_panel():\n"
            "    return 'admin'\n",
            encoding="utf-8",
        )
        assert BrokenAuthAnalyzer(str(tmp_path)).analyze() == []

    def test_detects_missing_auth_on_sensitive_route(self, tmp_path: Path):
        (tmp_path / "routes.py").write_text(
            "@app.route('/admin/settings', methods=['POST'])\n"
            "def update_admin_settings():\n"
            "    return save_settings()\n",
            encoding="utf-8",
        )
        findings = BrokenAuthAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "missing_auth_decorator" for f in findings)

    def test_ignores_public_routes(self, tmp_path: Path):
        (tmp_path / "routes.py").write_text(
            "@app.route('/health')\n"
            "def health_check():\n"
            "    return 'ok'\n",
            encoding="utf-8",
        )
        assert BrokenAuthAnalyzer(str(tmp_path)).analyze() == []
