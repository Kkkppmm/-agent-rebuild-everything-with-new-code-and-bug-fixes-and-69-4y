"""Tests for SQLInjectionAnalyzer."""

from pathlib import Path

from devai.sql_injection import SQLInjectionAnalyzer


SAFE_CODE = '''
def get_user(conn, user_id):
    conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
'''

RISKY_CODE = '''
def bad_fstring(conn, name):
    conn.execute(f"SELECT * FROM users WHERE name = '{name}'")

def bad_concat(conn, table):
    conn.execute("SELECT * FROM " + table)

def bad_format(conn, col):
    conn.execute("SELECT {} FROM users".format(col))
'''


class TestSQLInjectionAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = SQLInjectionAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_risky_patterns(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = SQLInjectionAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        patterns = {f.pattern for f in findings}
        assert "f_string" in patterns
        assert "concatenation" in patterns
        assert "format" in patterns
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = SQLInjectionAnalyzer(str(tmp_path))
        assert "SQL injection" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()
