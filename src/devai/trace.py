"""Lightweight tracing for DevAI program and workflow steps."""

from __future__ import annotations

import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Iterator


@dataclass
class TraceSpan:
    """A single traced operation."""

    name: str
    span_id: str
    start_time: float
    end_time: float | None = None
    attributes: dict[str, Any] = field(default_factory=dict)
    children: list[TraceSpan] = field(default_factory=list)

    @property
    def duration_ms(self) -> float | None:
        if self.end_time is None:
            return None
        return (self.end_time - self.start_time) * 1000

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "span_id": self.span_id,
            "duration_ms": self.duration_ms,
            "attributes": self.attributes,
            "children": [child.to_dict() for child in self.children],
        }


class DevTrace:
    """Collect lightweight timing spans for DevAI operations."""

    def __init__(self, name: str = "trace") -> None:
        self.name = name
        self.spans: list[TraceSpan] = []
        self._stack: list[TraceSpan] = []

    @contextmanager
    def span(self, name: str, **attributes: Any) -> Iterator[TraceSpan]:
        span = TraceSpan(
            name=name,
            span_id=uuid.uuid4().hex[:12],
            start_time=time.perf_counter(),
            attributes=attributes,
        )
        if self._stack:
            self._stack[-1].children.append(span)
        else:
            self.spans.append(span)
        self._stack.append(span)
        try:
            yield span
        finally:
            span.end_time = time.perf_counter()
            self._stack.pop()

    def start_span(self, name: str, **attributes: Any) -> TraceSpan:
        span = TraceSpan(
            name=name,
            span_id=uuid.uuid4().hex[:12],
            start_time=time.perf_counter(),
            attributes=attributes,
        )
        if self._stack:
            self._stack[-1].children.append(span)
        else:
            self.spans.append(span)
        self._stack.append(span)
        return span

    def end_span(self, span: TraceSpan) -> None:
        span.end_time = time.perf_counter()
        if self._stack and self._stack[-1] is span:
            self._stack.pop()

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "spans": [span.to_dict() for span in self.spans],
        }

    def to_markdown(self) -> str:
        lines = [f"# Trace: {self.name}\n"]
        for span in self.spans:
            lines.extend(self._format_span(span, indent=0))
        return "\n".join(lines)

    def _format_span(self, span: TraceSpan, *, indent: int) -> list[str]:
        prefix = "  " * indent
        duration = f"{span.duration_ms:.1f}ms" if span.duration_ms is not None else "running"
        lines = [f"{prefix}- **{span.name}** ({duration})"]
        if span.attributes:
            attrs = ", ".join(f"{k}={v!r}" for k, v in span.attributes.items())
            lines.append(f"{prefix}  attrs: {attrs}")
        for child in span.children:
            lines.extend(self._format_span(child, indent=indent + 1))
        return lines
