"""Tests for UnsafeDeserializationAnalyzer."""

from pathlib import Path

from devai.unsafe_deserialization import UnsafeDeserializationAnalyzer

SAFE_CODE = '''
import json
import yaml

def load_config(data):
    return json.loads(data)

def load_yaml(data):
    return yaml.safe_load(data)
'''

RISKY_CODE = '''
import pickle
import yaml
import marshal

def load_obj(data):
    return pickle.loads(data)

def load_yaml(data):
    return yaml.load(data)

def load_marshal(data):
    return marshal.loads(data)
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
        assert len(findings) >= 3
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = UnsafeDeserializationAnalyzer(str(tmp_path))
        assert "Unsafe deserialization" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()
