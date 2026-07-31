"""Tests for AsyncBlockingDetector."""

from pathlib import Path

from devai.async_blocking import AsyncBlockingCall, AsyncBlockingDetector

SAFE_ASYNC = '''
import asyncio
import aiohttp

async def fetch(url):
    await asyncio.sleep(1)
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as resp:
            return await resp.text()

async def read_file(path):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, open, path)
'''

BLOCKING_ASYNC = '''
import time
import requests
import subprocess

async def slow():
    time.sleep(1)

async def fetch(url):
    return requests.get(url)

async def run_cmd(cmd):
    subprocess.run(cmd, shell=True)

async def read_config(path):
    with open(path) as f:
        return f.read()

async def prompt():
    return input("name: ")
'''


class TestAsyncBlockingDetector:
    def test_clean_async_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAFE_ASYNC, encoding="utf-8")
        analyzer = AsyncBlockingDetector(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_blocking_patterns(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(BLOCKING_ASYNC, encoding="utf-8")
        analyzer = AsyncBlockingDetector(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "time_blocking" in kinds
        assert "network_blocking" in kinds
        assert "subprocess_blocking" in kinds
        assert "io_blocking" in kinds
        assert analyzer.health_score() < 100.0

    def test_ignores_sync_functions(self, tmp_path: Path):
        code = '''
import time

def slow():
    time.sleep(1)
'''
        (tmp_path / "app.py").write_text(code, encoding="utf-8")
        analyzer = AsyncBlockingDetector(str(tmp_path))
        assert analyzer.analyze() == []

    def test_by_kind(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(BLOCKING_ASYNC, encoding="utf-8")
        analyzer = AsyncBlockingDetector(str(tmp_path))
        time_findings = analyzer.by_kind("time_blocking")
        assert any(f.name == "time.sleep" for f in time_findings)

    def test_high_severity(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(BLOCKING_ASYNC, encoding="utf-8")
        analyzer = AsyncBlockingDetector(str(tmp_path))
        high = analyzer.high_severity()
        assert all(f.severity == "high" for f in high)
        assert len(high) >= 2

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(BLOCKING_ASYNC, encoding="utf-8")
        analyzer = AsyncBlockingDetector(str(tmp_path))
        assert "Async blocking:" in analyzer.summary()
        assert "time.sleep" in analyzer.to_context()

    def test_format(self):
        finding = AsyncBlockingCall(
            path="app.py",
            function="slow",
            name="time.sleep",
            lineno=5,
            kind="time_blocking",
            severity="high",
            message="use asyncio.sleep()",
        )
        assert "app.py:5" in finding.format()
        assert "slow()" in finding.format()
