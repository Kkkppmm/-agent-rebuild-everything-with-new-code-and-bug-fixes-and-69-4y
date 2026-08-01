"""Tests for UnsafeDeserializationAnalyzer."""

from pathlib import Path

from devai.unsafe_deserialization import UnsafeDeserializationAnalyzer


SAFE_CODE = '''
import yaml

def load_config(data: str):
    return yaml.safe_load(data)
'''

RISKY_CODE = '''
import pickle
import yaml
import marshal

def load_session(session_data):
    return pickle.loads(session_data)

def load_yaml(user_input):
    return yaml.load(user_input)

def load_marshal(raw_bytes):
    return marshal.loads(raw_bytes)
'''


class TestUnsafeDeserializationAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = UnsafeDeserializationAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_risky_patterns(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = UnsafeDeserializationAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        patterns = {f.pattern for f in findings}
        assert "pickle_loads" in patterns
        assert "yaml_load" in patterns
        assert "marshal_loads" in patterns
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = UnsafeDeserializationAnalyzer(str(tmp_path))
        assert "Unsafe deserialization" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()

    def test_high_severity(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = UnsafeDeserializationAnalyzer(str(tmp_path))
        assert len(analyzer.high_severity()) >= 2
