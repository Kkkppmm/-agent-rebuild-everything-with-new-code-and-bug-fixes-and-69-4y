"""Tests for AsyncBlockingDetector."""

from pathlib import Path

from devai.async_blocking import AsyncBlockingDetector


SAFE_CODE = '''
import asyncio

async def fetch():
    await asyncio.sleep(1)
'''

BLOCKING_CODE = '''
import time
import requests
import subprocess

async def bad_sleep():
    time.sleep(1)

async def bad_http():
    requests.get("https://example.com")

async def bad_subprocess():
    subprocess.run(["echo", "hi"])
'''


class TestAsyncBlockingDetector:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAFE_CODE, encoding="utf-8")
        detector = AsyncBlockingDetector(str(tmp_path))
        assert detector.analyze() == []
        assert detector.health_score() == 100.0

    def test_detects_blocking_calls(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(BLOCKING_CODE, encoding="utf-8")
        detector = AsyncBlockingDetector(str(tmp_path))
        findings = detector.analyze()
        calls = {f.call for f in findings}
        assert "time.sleep" in calls
        assert "requests.get" in calls
        assert "subprocess.run" in calls
        assert detector.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(BLOCKING_CODE, encoding="utf-8")
        detector = AsyncBlockingDetector(str(tmp_path))
        assert "Async blocking" in detector.summary()
        assert "Findings:" in detector.to_context()
