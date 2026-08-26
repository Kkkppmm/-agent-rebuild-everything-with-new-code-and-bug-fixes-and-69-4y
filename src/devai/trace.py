"""Lightweight tracing for DevAI programs and LLM calls."""

from __future__ import annotations

import json
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Iterator


@dataclass
class TraceEvent:
    """A single trace event."""

    name: str
    kind: str
    start_ms: float
    end_ms: float | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    children: list[TraceEvent] = field(default_factory=list)

    @property
    def duration_ms(self) -> float | None:
        if self.end_ms is None:
            return None
        return self.end_ms - self.start_ms

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "name": self.name,
            "kind": self.kind,
            "start_ms": self.start_ms,
            "metadata": self.metadata,
        }
        if self.end_ms is not None:
            payload["end_ms"] = self.end_ms
            payload["duration_ms"] = self.duration_ms
        if self.children:
            payload["children"] = [child.to_dict() for child in self.children]
        return payload


@dataclass
class DevTrace:
    """Collect spans and events for observability during program runs."""

    trace_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    events: list[TraceEvent] = field(default_factory=list)
    _stack: list[TraceEvent] = field(default_factory=list, init=False, repr=False)
    _origin_ms: float = field(default_factory=time.perf_counter, init=False, repr=False)

    def _now_ms(self) -> float:
        return (time.perf_counter() - self._origin_ms) * 1000.0

    @contextmanager
    def span(self, name: str, *, kind: str = "span", **metadata: Any) -> Iterator[TraceEvent]:
        """Record a timed span. Nested spans attach to the current parent."""
        event = TraceEvent(name=name, kind=kind, start_ms=self._now_ms(), metadata=metadata)
        parent = self._stack[-1] if self._stack else None
        if parent is None:
            self.events.append(event)
        else:
            parent.children.append(event)
        self._stack.append(event)
        try:
            yield event
        finally:
            event.end_ms = self._now_ms()
            self._stack.pop()

    def record(self, name: str, *, kind: str = "event", **metadata: Any) -> TraceEvent:
        """Record an instantaneous event."""
        event = TraceEvent(
            name=name,
            kind=kind,
            start_ms=self._now_ms(),
            end_ms=self._now_ms(),
            metadata=metadata,
        )
        parent = self._stack[-1] if self._stack else None
        if parent is None:
            self.events.append(event)
        else:
            parent.children.append(event)
        return event

    def summary(self) -> dict[str, Any]:
        """Return a summary of the trace."""
        total_spans = 0
        total_duration = 0.0

        def walk(event: TraceEvent) -> None:
            nonlocal total_spans, total_duration
            if event.duration_ms is not None and event.kind != "event":
                total_spans += 1
                total_duration += event.duration_ms
            for child in event.children:
                walk(child)

        for event in self.events:
            walk(event)

        return {
            "trace_id": self.trace_id,
            "event_count": len(self.events),
            "span_count": total_spans,
            "total_duration_ms": round(total_duration, 3),
            "events": [event.to_dict() for event in self.events],
        }

    def to_json(self, *, indent: int = 2) -> str:
        """Serialize the trace to JSON."""
        return json.dumps(self.summary(), indent=indent)

    def clear(self) -> None:
        """Reset the trace."""
        self.events.clear()
        self._stack.clear()
        self._origin_ms = time.perf_counter()
