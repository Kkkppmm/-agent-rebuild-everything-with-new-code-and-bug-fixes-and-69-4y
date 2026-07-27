import pytest
from pydantic import BaseModel

from devai import CodeAssistant, DevAIConfig
from devai.agents import CoderAgent
from devai.chains import SimpleChain
from devai.core.client import EmbeddingClient, MockLLMClient
from devai.core.exceptions import ToolExecutionError
from devai.core.models import Message, ToolDefinition
from devai.memory import ConversationMemory
from devai.output import parse_json, parse_model
from devai.pipeline import DevPipeline
from devai.prompts import CODE_REVIEW, PromptTemplate
from devai.rag import RAGChain, VectorStore, chunk_text
from devai.tools import ToolRegistry, default_tools
from devai.tools.code_utils import count_complexity, explain_code, lint_python, search_code
from devai.utils import estimate_tokens, extract_code_blocks, truncate_to_tokens


class TestConfig:
    def test_from_env(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")
        config = DevAIConfig.from_env()
        assert config.api_key == "test-key"

    def test_mock(self):
        config = DevAIConfig.mock()
        assert config.api_key == "mock-key"


class TestModels:
    def test_message_to_dict(self):
        msg = Message.user("hello")
        assert msg.to_dict() == {"role": "user", "content": "hello"}

    def test_tool_definition_schema(self):
        tool = ToolDefinition(name="test", description="A test tool")
        schema = tool.to_openai_schema()
        assert schema["function"]["name"] == "test"


class TestMockClient:
    def test_complete(self):
        client = MockLLMClient()
        response = client.complete([Message.user("review this code")])
        assert response.content
        assert "review" in response.content.lower()

    def test_json_mode(self):
        client = MockLLMClient()
        response = client.complete([Message.user("test")], json_mode=True)
        import json
        data = json.loads(response.content)
        assert "summary" in data

    def test_stream(self):
        client = MockLLMClient()
        chunks = list(client.stream([Message.user("hello")]))
        assert len(chunks) > 0

    @pytest.mark.asyncio
    async def test_acomplete(self):
        client = MockLLMClient()
        response = await client.acomplete([Message.user("explain")])
        assert response.content

    def test_tool_calling(self):
        client = MockLLMClient()
        tools = [ToolDefinition(name="search_code", description="search")]
        response = client.complete([Message.user("search for TODO")], tools=tools)
        assert response.tool_calls
        assert response.tool_calls[0].name == "search_code"


class TestEmbedding:
    def test_mock_embed(self):
        client = EmbeddingClient(DevAIConfig.mock())
        embeddings = client.embed(["hello", "world"])
        assert len(embeddings) == 2
        assert len(embeddings[0]) == 64


class TestAssistant:
    def test_review(self):
        assistant = CodeAssistant(config=DevAIConfig.mock())
        result = assistant.review("def add(a, b): return a + b")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_explain(self):
        assistant = CodeAssistant(config=DevAIConfig.mock())
        result = assistant.explain("x = 1")
        assert isinstance(result, str)

    def test_debug(self):
        assistant = CodeAssistant(config=DevAIConfig.mock())
        result = assistant.debug("x = 1/0", "ZeroDivisionError")
        assert "debug" in result.lower() or "error" in result.lower() or len(result) > 0

    def test_full_review(self):
        assistant = CodeAssistant(config=DevAIConfig.mock())
        result = assistant.full_review("def foo(): pass")
        assert "review" in result
        assert "security" in result
        assert "tests" in result


class TestPrompts:
    def test_template_format(self):
        result = CODE_REVIEW(code="print(1)", language="python")
        assert "print(1)" in result

    def test_custom_template(self):
        t = PromptTemplate("Hello $name")
        assert t.format(name="World") == "Hello World"


class TestTools:
    def test_explain_code(self):
        result = explain_code("def foo():\n    pass")
        assert "foo" in result

    def test_lint_python(self):
        result = lint_python("def foo():\n    pass\n")
        assert "docstring" in result.lower()

    def test_count_complexity(self):
        code = "def simple():\n    return 1\n\ndef complex(x):\n    if x > 0:\n        if x > 10:\n            return x\n    return 0\n"
        result = count_complexity(code)
        assert "simple" in result
        assert "complex" in result

    def test_tool_registry(self):
        registry = ToolRegistry()
        for tool in default_tools():
            registry.register(tool)
        assert len(registry.list_tools()) == 7
        result = registry.execute("explain_code", {"code": "x = 1"})
        assert result

    def test_tool_error(self):
        registry = ToolRegistry()
        with pytest.raises(ToolExecutionError):
            registry.execute("nonexistent", {})


class TestAgent:
    def test_coder_agent(self):
        registry = ToolRegistry()
        for tool in default_tools():
            registry.register(tool)
        agent = CoderAgent(config=DevAIConfig.mock(), tools=registry)
        result = agent.run("search for files")
        assert isinstance(result, str)


class TestChains:
    def test_simple_chain(self):
        chain = SimpleChain(CODE_REVIEW, config=DevAIConfig.mock())
        result = chain.run(code="x=1", language="python")
        assert isinstance(result, str)


class TestMemory:
    def test_conversation(self):
        mem = ConversationMemory(max_messages=3)
        mem.add_user("hi")
        mem.add_assistant("hello")
        assert len(mem) == 2
        mem.clear()
        assert len(mem) == 0


class TestOutput:
    def test_parse_json_raw(self):
        result = parse_json('{"key": "value"}')
        assert result["key"] == "value"

    def test_parse_json_codeblock(self):
        result = parse_json('Here is the result:\n```json\n{"a": 1}\n```')
        assert result["a"] == 1

    def test_parse_model(self):
        class Review(BaseModel):
            summary: str

        result = parse_model('{"summary": "looks good"}', Review)
        assert result.summary == "looks good"


class TestRAG:
    def test_chunk_text(self):
        docs = chunk_text("Paragraph one.\n\nParagraph two.\n\nParagraph three.")
        assert len(docs) >= 1

    def test_vector_store(self):
        store = VectorStore(DevAIConfig.mock())
        store.add_text("DevAI is a Python AI library for developers.")
        assert len(store) == 1
        results = store.search("Python library")
        assert len(results) > 0

    def test_rag_chain(self):
        store = VectorStore(DevAIConfig.mock())
        store.add_text("Install with: pip install devai")
        rag = RAGChain(store=store, config=DevAIConfig.mock())
        answer = rag.query("How to install?")
        assert isinstance(answer, str)


class TestPipeline:
    def test_review_pipeline(self):
        pipeline = DevPipeline.review_pipeline(DevAIConfig.mock())
        results = pipeline.run("def foo(): pass")
        assert len(results) == 3
        assert results[0].step == "review"


class TestUtils:
    def test_estimate_tokens(self):
        assert estimate_tokens("hello world") > 0

    def test_extract_code_blocks(self):
        text = "Here:\n```python\nx = 1\n```"
        blocks = extract_code_blocks(text)
        assert blocks == ["x = 1\n"]

    def test_truncate(self):
        text = "a" * 1000
        result = truncate_to_tokens(text, 10)
        assert len(result) < 1000


class TestSearchCode:
    def test_search_in_workspace(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text("# TODO: fix this\nx = 1\n")
        result = search_code(str(tmp_path), "TODO")
        assert "TODO" in result
