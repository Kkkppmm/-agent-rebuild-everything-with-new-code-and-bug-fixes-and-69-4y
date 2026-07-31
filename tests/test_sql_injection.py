"""Tests for SQLInjectionAnalyzer."""

from pathlib import Path

from devai.sql_injection import SQLInjectionAnalyzer, SQLInjectionRisk

SAFE_CODE = '''
def get_user(cursor, user_id):
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    cursor.execute(
        "INSERT INTO logs (msg) VALUES (?)",
        ("login",),
    )
'''

RISKY_CODE = '''
def bad_queries(cursor, table, user_id):
    cursor.execute(f"SELECT * FROM {table} WHERE id = {user_id}")
    cursor.execute("DELETE FROM users WHERE name = '" + user_id + "'")
    cursor.execute("UPDATE accounts SET balance = %s" % amount)
    cursor.execute("SELECT * FROM {}".format(table))
'''


class TestSQLInjectionAnalyzer:
    def test_safe_parameterized_queries(self, tmp_path: Path):
        (tmp_path / "db.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = SQLInjectionAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_interpolation_patterns(self, tmp_path: Path):
        (tmp_path / "db.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = SQLInjectionAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        patterns = {f.pattern for f in findings}
        assert "f_string" in patterns
        assert "concatenation" in patterns
        assert "percent_format" in patterns
        assert "str_format" in patterns
        assert analyzer.health_score() < 100.0
        assert analyzer.stats.total_findings >= 4

    def test_skips_test_files_by_default(self, tmp_path: Path):
        tests = tmp_path / "tests"
        tests.mkdir()
        (tests / "test_db.py").write_text(
            'def test_x(cursor):\n    cursor.execute(f"SELECT {1}")\n',
            encoding="utf-8",
        )
        analyzer = SQLInjectionAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []

    def test_include_tests(self, tmp_path: Path):
        tests = tmp_path / "tests"
        tests.mkdir()
        (tests / "test_db.py").write_text(
            'def test_x(cursor):\n    cursor.execute(f"SELECT * FROM {table}")\n',
            encoding="utf-8",
        )
        analyzer = SQLInjectionAnalyzer(str(tmp_path), include_tests=True)
        assert len(analyzer.analyze()) >= 1

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "db.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = SQLInjectionAnalyzer(str(tmp_path))
        assert "SQL injection risks:" in analyzer.summary()
        assert "SQL injection risk analysis:" in analyzer.to_context()

    def test_high_severity(self, tmp_path: Path):
        (tmp_path / "db.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = SQLInjectionAnalyzer(str(tmp_path))
        high = analyzer.high_severity()
        assert all(f.severity == "high" for f in high)
        assert len(high) >= 1

    def test_finding_format(self):
        finding = SQLInjectionRisk(
            path="db.py",
            function="query",
            lineno=10,
            call_name="execute",
            pattern="f_string",
            severity="high",
            message="use parameterized queries",
        )
        text = finding.format()
        assert "db.py:10" in text
        assert "f_string" in text
        assert "execute" in text
