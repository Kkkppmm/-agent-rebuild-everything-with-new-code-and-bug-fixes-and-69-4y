"""Tests for DevTrace."""

import json

from devai import DevTrace
from devai.program import DevProgram
from devai.assistant import CodeAssistant
from devai.core import MockLLMClient


class TestDevTrace:
    def test_span_records_duration(self):
        trace = DevTrace()
        with trace.span("step-one", action="review"):
            pass
        summary = trace.summary()
        assert summary["span_count"] == 1
        assert summary["total_duration_ms"] >= 0

    def test_nested_spans(self):
        trace = DevTrace()
        with trace.span("parent"):
            with trace.span("child"):
                trace.record("event", kind="event", detail="ok")
        data = trace.summary()
        assert len(data["events"]) == 1
        parent = data["events"][0]
        assert len(parent["children"]) == 1
        assert parent["children"][0]["name"] == "child"
        assert len(parent["children"][0]["children"]) == 1

    def test_to_json(self):
        trace = DevTrace()
        with trace.span("task"):
            pass
        payload = json.loads(trace.to_json())
        assert "trace_id" in payload
        assert payload["span_count"] == 1

    def test_program_run_with_trace(self):
        client = MockLLMClient(responses=["reviewed", "secured"])
        assistant = CodeAssistant(client=client)
        program = (
            DevProgram("audit", assistant)
            .add("review_step", "review")
            .add("security_step", "security")
        )
        trace = DevTrace()
        results = program.run({"code": "def foo(): pass"}, trace=trace)
        assert len(results) == 2
        assert trace.summary()["span_count"] == 2

    def test_clear(self):
        trace = DevTrace()
        with trace.span("one"):
            pass
        trace.clear()
        assert trace.summary()["event_count"] == 0
