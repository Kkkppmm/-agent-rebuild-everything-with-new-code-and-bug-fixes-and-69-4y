"""Tests for tracing."""

from devai.trace import DevTrace


class TestDevTrace:
    def test_span_context_manager(self):
        trace = DevTrace("test")
        with trace.span("step1", key="value") as span:
            assert span.name == "step1"
            with trace.span("step2"):
                pass
        assert len(trace.spans) == 1
        assert trace.spans[0].children
        assert trace.spans[0].duration_ms is not None

    def test_to_markdown(self):
        trace = DevTrace("demo")
        with trace.span("run"):
            pass
        md = trace.to_markdown()
        assert "# Trace: demo" in md
        assert "run" in md

    def test_to_dict(self):
        trace = DevTrace("demo")
        with trace.span("a"):
            pass
        data = trace.to_dict()
        assert data["name"] == "demo"
        assert len(data["spans"]) == 1
