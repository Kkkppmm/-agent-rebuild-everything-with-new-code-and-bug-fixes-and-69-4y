"""Tests for NoSQLInjectionAnalyzer."""

from pathlib import Path

from devai.nosql_injection import NoSQLInjectionAnalyzer


SAFE_CODE = '''
from pymongo import MongoClient

client = MongoClient()
db = client.mydb

def get_user(user_id: str):
    return db.users.find_one({"_id": user_id})

def list_active():
    return db.users.find({"status": "active"})
'''

RISKY_CODE = '''
from pymongo import MongoClient

client = MongoClient()
db = client.mydb

def bad_find(user_input):
    return db.users.find({"name": f"{user_input}"})

def bad_where(user_input):
    return db.users.find({"$where": user_input})

def bad_update(doc_id, value):
    query = "status=" + value
    return db.users.update_one({"_id": doc_id}, {"$set": {"status": query}})
'''


class TestNoSQLInjectionAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "db.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = NoSQLInjectionAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_risky_patterns(self, tmp_path: Path):
        (tmp_path / "db.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = NoSQLInjectionAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        patterns = {f.pattern for f in findings}
        assert "f_string" in patterns
        assert "where_operator" in patterns
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "db.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = NoSQLInjectionAnalyzer(str(tmp_path))
        assert "NoSQL injection" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()

    def test_high_severity(self, tmp_path: Path):
        (tmp_path / "db.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = NoSQLInjectionAnalyzer(str(tmp_path))
        assert len(analyzer.high_severity()) >= 1
