"""Tests for memory, output, RAG, pipeline, and utils."""

import pytest
from pydantic import BaseModel

from devai.core.messages import Message
from devai.memory import ConversationMemory
from devai.output import parse_json, parse_model, StructuredParser
from devai.core.exceptions import ParseError
from devai.rag import VectorStore, chunk_text
from devai.pipeline import DevPipeline, PipelineStep
from devai.core.client import MockLLMClient
from devai.utils import estimate_tokens, extract_code_blocks, truncate_to_tokens


class TestConversationMemory:
    def test_add_and_get(self):
        mem = ConversationMemory()
        mem.add(Message.user("hello"))
        assert len(mem) == 1
        assert mem.last.content == "hello"

    def test_max_messages(self):
        mem = ConversationMemory(max_messages=2)
        mem.add(Message.user("1"))
        mem.add(Message.user("2"))
        mem.add(Message.user("3"))
        assert len(mem) == 2
        assert mem.get_messages()[0].content == "2"

    def test_clear(self):
        mem = ConversationMemory()
        mem.add(Message.user("hi"))
        mem.clear()
        assert len(mem) == 0


class TestOutputParser:
    def test_parse_json_raw(self):
        result = parse_json('{"key": "value"}')
        assert result["key"] == "value"

    def test_parse_json_codeblock(self):
        result = parse_json('Here is the data:\n```json\n{"a": 1}\n```')
        assert result["a"] == 1

    def test_parse_model(self):
        class Item(BaseModel):
            name: str

        item = parse_model('{"name": "test"}', Item)
        assert item.name == "test"

    def test_structured_parser(self):
        class Score(BaseModel):
            value: int

        parser = StructuredParser(Score)
        result = parser.parse('{"value": 42}')
        assert result.value == 42

    def test_invalid_json_raises(self):
        with pytest.raises(ParseError):
            parse_json("not json at all {{{")


class TestRAG:
    def test_chunk_text(self):
        text = "A" * 1000
        chunks = chunk_text(text, chunk_size=200, overlap=20)
        assert len(chunks) > 1
        assert all(len(c.content) <= 200 for c in chunks)

    def test_chunk_text_paragraphs(self):
        text = "Para one.\n\nPara two.\n\nPara three."
        chunks = chunk_text(text, chunk_size=20)
        assert len(chunks) >= 1

    def test_vector_store_search(self):
        store = VectorStore()
        store.add("hello world", [1.0, 0.0])
        store.add("goodbye world", [0.0, 1.0])
        results = store.search([1.0, 0.0], top_k=1)
        assert results[0].document.content == "hello world"
        assert results[0].score > 0.9

    def test_chunk_invalid_size(self):
        with pytest.raises(ValueError):
            chunk_text("text", chunk_size=0)


class TestPipeline:
    def test_review(self):
        pipeline = DevPipeline(client=MockLLMClient(responses=["Good code"]))
        result = pipeline.review("x = 1")
        assert result == "Good code"
        assert len(pipeline.results) == 1

    def test_run_all(self):
        client = MockLLMClient(responses=["review", "security"])
        pipeline = DevPipeline(client=client)
        outputs = pipeline.run_all("code", steps=[PipelineStep.REVIEW, PipelineStep.SECURITY])
        assert "review" in outputs
        assert "security" in outputs

    def test_summary(self):
        pipeline = DevPipeline(client=MockLLMClient(responses=["ok"]))
        pipeline.review("x=1")
        summary = pipeline.summary()
        assert "REVIEW" in summary


class TestUtils:
    def test_estimate_tokens(self):
        assert estimate_tokens("hello world") >= 1

    def test_truncate(self):
        text = "a" * 1000
        truncated = truncate_to_tokens(text, 10)
        assert len(truncated) < len(text)

    def test_extract_code_blocks(self):
        text = "Here:\n```python\nx = 1\n```\nDone."
        blocks = extract_code_blocks(text, language="python")
        assert len(blocks) == 1
        assert "x = 1" in blocks[0]
