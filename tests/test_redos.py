"""Tests for ReDoSAnalyzer."""

from pathlib import Path

from devai.redos import ReDoSAnalyzer


SAFE_CODE = '''
import re

PATTERN = r"^\\w+@\\w+\\.\\w+$"

def validate_email(email):
    return re.match(PATTERN, email)
'''

RISKY_CODE = '''
import re
from flask import request

BAD_PATTERN = r"(.+)+"

def bad_nested():
    return re.search(r"(.*)+", request.args.get("text"))

def bad_user_pattern():
    return re.compile(request.form.get("pattern"))
'''


class TestReDoSAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "validators.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = ReDoSAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_nested_quantifiers(self, tmp_path: Path):
        (tmp_path / "risky.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = ReDoSAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        patterns = {f.pattern for f in findings}
        assert "nested_quantifier" in patterns
        assert "risky_pattern_literal" in patterns
        assert "user_controlled_regex" in patterns
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "risky.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = ReDoSAnalyzer(str(tmp_path))
        assert "ReDoS risks:" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()
