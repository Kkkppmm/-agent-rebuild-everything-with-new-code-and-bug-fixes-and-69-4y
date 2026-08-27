"""File watcher for triggering DevAI programs on code changes."""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from devai.runtime import DevRuntime


@dataclass
class WatchEvent:
    """A detected file change event."""

    path: str
    change_type: str  # "created", "modified", "deleted"
    timestamp: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "change_type": self.change_type,
            "timestamp": self.timestamp,
        }


@dataclass
class WatchResult:
    """Result from processing a watch event."""

    event: WatchEvent
    success: bool
    output: Any = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "event": self.event.to_dict(),
            "success": self.success,
            "output": self.output,
            "error": self.error,
        }


class DevWatcher:
    """Poll a directory and run DevAI programs when files change.

    Example::

        watcher = DevWatcher(
            "src/",
            patterns=["*.py"],
            runtime=DevRuntime.create(use_mock=True),
            preset="pre-commit",
        )
        watcher.run_once()  # process any pending changes
        watcher.watch(interval=2.0, max_events=1)  # poll until one event handled
    """

    def __init__(
        self,
        directory: str | Path,
        *,
        patterns: list[str] = ["*.py"],
        ignore_dirs: set[str] | None = None,
        runtime: DevRuntime | None = None,
        preset: str | None = None,
        program: str | None = None,
        on_change: Callable[[WatchEvent], Any] | None = None,
    ) -> None:
        self.directory = Path(directory)
        self.patterns = patterns
        self.ignore_dirs = ignore_dirs or {
            ".git",
            "__pycache__",
            ".pytest_cache",
            ".ruff_cache",
            ".mypy_cache",
            "node_modules",
            ".devai-cache",
        }
        self.runtime = runtime
        self.preset = preset
        self.program = program
        self.on_change = on_change
        self._snapshots: dict[str, tuple[float, int, str]] = {}
        self._history: list[WatchResult] = []

    def _iter_files(self) -> list[Path]:
        if not self.directory.exists():
            return []
        files: list[Path] = []
        for pattern in self.patterns:
            for path in self.directory.rglob(pattern):
                if any(part in self.ignore_dirs for part in path.parts):
                    continue
                if path.is_file():
                    files.append(path)
        return files

    def _detect_changes(self) -> list[WatchEvent]:
        events: list[WatchEvent] = []
        current: dict[str, tuple[float, int, str]] = {}
        now = time.time()

        for path in self._iter_files():
            key = str(path)
            stat = path.stat()
            digest = hashlib.md5(path.read_bytes()).hexdigest()
            sig = (stat.st_mtime, stat.st_size, digest)
            current[key] = sig
            if key not in self._snapshots:
                events.append(WatchEvent(path=key, change_type="created", timestamp=now))
            elif sig != self._snapshots[key]:
                events.append(WatchEvent(path=key, change_type="modified", timestamp=now))

        for key in self._snapshots:
            if key not in current:
                events.append(
                    WatchEvent(path=key, change_type="deleted", timestamp=now)
                )

        self._snapshots = current
        return events

    def _handle_event(self, event: WatchEvent) -> WatchResult:
        try:
            if self.on_change is not None:
                output = self.on_change(event)
            elif self.runtime is not None:
                code = ""
                if event.change_type != "deleted":
                    code = Path(event.path).read_text(encoding="utf-8", errors="replace")
                if self.preset:
                    output = self.runtime.run(self.preset, {"code": code})
                elif self.program:
                    output = self.runtime.run(self.program, {"code": code})
                else:
                    output = self.runtime.review(code)
            else:
                output = None
            result = WatchResult(event=event, success=True, output=output)
        except Exception as exc:
            result = WatchResult(event=event, success=False, error=str(exc))
        self._history.append(result)
        return result

    def run_once(self) -> list[WatchResult]:
        """Detect and process all pending file changes once."""
        return [self._handle_event(event) for event in self._detect_changes()]

    def watch(
        self,
        interval: float = 1.0,
        *,
        max_events: int | None = None,
        timeout: float | None = None,
    ) -> list[WatchResult]:
        """Poll for file changes until max_events or timeout is reached."""
        results: list[WatchResult] = []
        deadline = time.time() + timeout if timeout is not None else None

        while True:
            for event in self._detect_changes():
                results.append(self._handle_event(event))
                if max_events is not None and len(results) >= max_events:
                    return results

            if deadline is not None and time.time() >= deadline:
                return results

            if max_events is None and timeout is None:
                time.sleep(interval)
                continue

            if max_events is not None and len(results) >= max_events:
                return results

            time.sleep(interval)

    @property
    def history(self) -> list[WatchResult]:
        return list(self._history)

    def clear_history(self) -> None:
        self._history.clear()
