"""Tests for DevWatcher file watcher."""

import time
from pathlib import Path

from devai.runtime import DevRuntime
from devai.watch import DevWatcher, WatchEvent


class TestDevWatcher:
    def test_detects_created_file(self, tmp_path):
        events: list[WatchEvent] = []
        watcher = DevWatcher(
            tmp_path,
            on_change=lambda e: events.append(e),
        )
        watcher.run_once()

        sample = tmp_path / "sample.py"
        sample.write_text("x = 1\n", encoding="utf-8")

        results = watcher.run_once()
        assert len(results) == 1
        assert results[0].event.change_type == "created"
        assert results[0].success

    def test_detects_modified_file(self, tmp_path):
        sample = tmp_path / "mod.py"
        sample.write_text("a = 1\n", encoding="utf-8")

        watcher = DevWatcher(tmp_path)
        watcher.run_once()

        sample.write_text("a = 2\n", encoding="utf-8")
        results = watcher.run_once()

        assert len(results) == 1
        assert results[0].event.change_type == "modified"

    def test_runs_preset_on_change(self, tmp_path):
        sample = tmp_path / "code.py"
        sample.write_text("def foo(): pass\n", encoding="utf-8")

        runtime = DevRuntime.create(use_mock=True)
        watcher = DevWatcher(
            tmp_path,
            runtime=runtime,
            preset="pre-commit",
        )
        watcher.run_once()
        results = watcher.run_once()

        assert len(results) == 0

        sample.write_text("def foo(): return 1\n", encoding="utf-8")
        results = watcher.run_once()

        assert len(results) == 1
        assert results[0].success
        assert results[0].output is not None

    def test_custom_callback(self, tmp_path):
        sample = tmp_path / "cb.py"
        sample.write_text("1\n", encoding="utf-8")

        watcher = DevWatcher(
            tmp_path,
            on_change=lambda e: f"handled:{e.path}",
        )
        watcher.run_once()
        sample.write_text("2\n", encoding="utf-8")
        results = watcher.run_once()

        assert results[0].output.startswith("handled:")

    def test_watch_event_to_dict(self):
        event = WatchEvent(path="/tmp/a.py", change_type="modified", timestamp=1.0)
        data = event.to_dict()
        assert data["path"] == "/tmp/a.py"
        assert data["change_type"] == "modified"

    def test_watch_with_max_events(self, tmp_path):
        watcher = DevWatcher(tmp_path)
        watcher.run_once()

        (tmp_path / "a.py").write_text("a\n", encoding="utf-8")
        (tmp_path / "b.py").write_text("b\n", encoding="utf-8")

        results = watcher.watch(interval=0.01, max_events=1, timeout=1.0)
        assert len(results) == 1
