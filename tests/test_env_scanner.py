"""Tests for EnvVarScanner."""

from pathlib import Path

from devai.env_scanner import EnvVarScanner

CODE_WITH_ENV = '''
import os

API_KEY = os.environ.get("API_KEY")
DB_URL = os.getenv("DATABASE_URL")
'''

CODE_NO_ENV = '''
def hello():
    return "world"
'''


class TestEnvVarScanner:
    def test_detects_env_usage(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(CODE_WITH_ENV, encoding="utf-8")
        scanner = EnvVarScanner(str(tmp_path))
        usages = scanner.usages
        names = {u.name for u in usages}
        assert "API_KEY" in names
        assert "DATABASE_URL" in names

    def test_missing_from_env(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(CODE_WITH_ENV, encoding="utf-8")
        scanner = EnvVarScanner(str(tmp_path))
        issues = scanner.scan()
        missing = [i for i in issues if i.kind == "missing_from_env"]
        assert len(missing) == 2

    def test_aligned_env_file(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(CODE_WITH_ENV, encoding="utf-8")
        (tmp_path / ".env").write_text(
            "API_KEY=secret\nDATABASE_URL=postgres://localhost\n",
            encoding="utf-8",
        )
        scanner = EnvVarScanner(str(tmp_path))
        issues = scanner.scan()
        missing = [i for i in issues if i.kind == "missing_from_env"]
        assert missing == []

    def test_unused_in_env(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(CODE_NO_ENV, encoding="utf-8")
        (tmp_path / ".env").write_text("UNUSED_VAR=foo\n", encoding="utf-8")
        scanner = EnvVarScanner(str(tmp_path))
        issues = scanner.scan()
        unused = [i for i in issues if i.kind == "unused_in_code"]
        assert len(unused) == 1
        assert unused[0].name == "UNUSED_VAR"

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(CODE_WITH_ENV, encoding="utf-8")
        scanner = EnvVarScanner(str(tmp_path))
        assert "Env vars" in scanner.summary()
        assert "Environment variable analysis" in scanner.to_context()

    def test_health_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(CODE_WITH_ENV, encoding="utf-8")
        (tmp_path / ".env").write_text("API_KEY=x\nDATABASE_URL=y\n", encoding="utf-8")
        scanner = EnvVarScanner(str(tmp_path))
        assert scanner.health_score() == 100.0
