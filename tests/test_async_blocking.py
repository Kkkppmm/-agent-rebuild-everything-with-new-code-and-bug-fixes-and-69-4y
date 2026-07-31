"""Tests for AsyncBlockingDetector."""

from pathlib import Path

from devai.async_blocking import AsyncBlockingDetector, BlockingCall


SAFE_ASYNC = '''
import asyncio

async def fetch():
    await asyncio.sleep(1)
    return 42
'''

BLOCKING_ASYNC = '''
import time
import requests
import subprocess

async def slow():
    time.sleep(1)
    requests.get("https://example.com")
    subprocess.run(["echo", "hi"])
'''


class TestAsyncBlockingDetector:
    def test_clean_async_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAFE_ASYNC, encoding="utf-8")
        detector = AsyncBlockingDetector(str(tmp_path))
        assert detector.analyze() == []
        assert detector.health_score() == 100.0

    def test_detects_blocking_calls(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(BLOCKING_ASYNC, encoding="utf-8")
        detector = AsyncBlockingDetector(str(tmp_path))
        findings = detector.analyze()
        assert len(findings) >= 3
        calls = {f.call for f in findings}
        assert "time.sleep" in calls
        assert "requests.get" in calls
        assert "subprocess.run" in calls
        assert all(isinstance(f, BlockingCall) for f in findings)
        assert detector.health_score() < 100.0

    def test_sync_functions_ignored(self, tmp_path: Path):
        code = '''
import time

def sync_ok():
    time.sleep(1)
'''
        (tmp_path / "app.py").write_text(code, encoding="utf-8")
        detector = AsyncBlockingDetector(str(tmp_path))
        assert detector.analyze() == []

    def test_high_severity(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(BLOCKING_ASYNC, encoding="utf-8")
        detector = AsyncBlockingDetector(str(tmp_path))
        high = detector.high_severity()
        assert all(f.severity == "high" for f in high)
        assert len(high) >= 2

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(BLOCKING_ASYNC, encoding="utf-8")
        detector = AsyncBlockingDetector(str(tmp_path))
        assert "Async blocking calls" in detector.summary()
        assert "time.sleep" in detector.to_context()
