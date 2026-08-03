"""Tests for UnsafeDeserializationAnalyzer."""

from pathlib import Path

from devai.unsafe_deserialization import UnsafeDeserializationAnalyzer


SAFE_CODE = '''
import json
import yaml

def load_config(data):
    return json.loads(data)

def load_yaml(text):
    return yaml.safe_load(text)
'''

RISKY_CODE = '''
import pickle
import marshal
import yaml

def load_session(session_data):
    return pickle.loads(session_data)

def load_blob(raw_bytes):
    return marshal.loads(raw_bytes)

def load_yaml_unsafe(user_payload):
    return yaml.load(user_payload)
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
        assert "unsafe_deserialization" in patterns
        assert "unsafe_yaml_load" in patterns
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = UnsafeDeserializationAnalyzer(str(tmp_path))
        assert "Unsafe deserialization" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()
