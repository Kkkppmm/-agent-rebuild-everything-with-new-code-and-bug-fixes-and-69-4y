"""Tests for AsyncBlockingDetector."""

from pathlib import Path

from devai.async_blocking import AsyncBlockingDetector, AsyncBlockingFinding


SAFE_ASYNC = '''
import asyncio

async def fetch():
    await asyncio.sleep(1)
    return "ok"
'''

BLOCKING_ASYNC = '''
import time
import subprocess
import requests

async def slow():
    time.sleep(1)

async def fetch_url():
    return requests.get("https://example.com")

async def run_cmd(cmd):
    subprocess.run(["echo", cmd], check=True)

async def read_file(path):
    f = open(path)
    return f.read()
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
        kinds = {f.kind for f in findings}
        assert "time" in kinds
        assert "http" in kinds
        assert "subprocess" in kinds
        assert "io" in kinds
        assert detector.health_score() < 100.0

    def test_by_kind(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(BLOCKING_ASYNC, encoding="utf-8")
        detector = AsyncBlockingDetector(str(tmp_path))
        http = detector.by_kind("http")
        assert len(http) >= 1

    def test_high_severity(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(BLOCKING_ASYNC, encoding="utf-8")
        detector = AsyncBlockingDetector(str(tmp_path))
        high = detector.high_severity()
        assert all(f.severity == "high" for f in high)
        assert len(high) >= 2

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(BLOCKING_ASYNC, encoding="utf-8")
        detector = AsyncBlockingDetector(str(tmp_path))
        assert "Async blocking" in detector.summary()
        assert "Async blocking analysis" in detector.to_context()

    def test_finding_format(self):
        finding = AsyncBlockingFinding(
            path="app.py",
            function="slow",
            call="time.sleep",
            lineno=5,
            kind="time",
            severity="high",
            message="blocks event loop",
        )
        assert "app.py:5" in finding.format()
        assert "slow()" in finding.format()
