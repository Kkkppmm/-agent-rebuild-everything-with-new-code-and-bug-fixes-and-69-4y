"""Tests for DevAI client."""

import json

import pytest

from devai import DevAI, PromptTemplate, RAGPipeline, ToolRegistry
from devai.chat import ChatSession, Message, Role
from devai.embeddings import cosine_similarity, find_most_similar
from devai.providers.mock import MockProvider
from devai.rag import chunk_text, Document, VectorStore


@pytest.fixture
def ai():
    return DevAI.mock()


def test_chat_basic(ai):
    response = ai.chat("Hello")
    assert response.content
    assert response.usage.total_tokens > 0


def test_echo_command(ai):
    response = ai.chat("echo: test message")
    assert response.content == "test message"


def test_chat_stream(ai):
    tokens = list(ai.chat_stream("Hello"))
    assert len(tokens) > 0
    assert "".join(tokens)


def test_embeddings(ai):
    vectors = ai.embed(["hello", "world"])
    assert len(vectors) == 2
    assert len(vectors[0]) == 32


def test_cosine_similarity():
    a = [1.0, 0.0, 0.0]
    b = [1.0, 0.0, 0.0]
    assert cosine_similarity(a, b) == 1.0
    assert cosine_similarity(a, [0.0, 1.0, 0.0]) == 0.0


def test_find_most_similar():
    query = [1.0, 0.0]
    candidates = [[1.0, 0.0], [0.0, 1.0], [0.9, 0.1]]
    results = find_most_similar(query, candidates, top_k=2)
    assert len(results) == 2
    assert results[0][0] == 0


def test_chat_session(ai):
    session = ChatSession(system="You are helpful.")
    session.add_user("Hi")
    response = session.complete(ai, "What is 2+2?")
    assert response.content
    assert len(session.messages) >= 2


def test_prompt_template():
    tpl = PromptTemplate("Write {lang} code for {task}.")
    result = tpl.format(lang="Python", task="fibonacci")
    assert "Python" in result
    assert "fibonacci" in result


def test_tool_registry():
    registry = ToolRegistry()

    @registry.register(description="Add two numbers")
    def add(a: int, b: int) -> int:
        return a + b

    assert registry.execute("add", {"a": 2, "b": 3}) == 5
    schema = registry.to_openai_schema()
    assert schema[0]["function"]["name"] == "add"


def test_run_with_tools(ai):
    registry = ToolRegistry()

    @registry.register(description="Get weather for a city")
    def get_weather(city: str) -> str:
        return f"Sunny in {city}"

    ai.tools = registry
    response = ai.run_with_tools("What's the weather today?")
    assert response.content or response.tool_calls


def test_mock_tool_calls():
    provider = MockProvider()
    tools = [{"type": "function", "function": {"name": "get_weather", "parameters": {}}}]
    response = provider.chat(
        [{"role": "user", "content": "What's the weather today?"}],
        "mock",
        tools=tools,
    )
    assert len(response.tool_calls) == 1
    assert response.tool_calls[0]["function"]["name"] == "get_weather"


def test_rag_pipeline(ai):
    rag = RAGPipeline(chunk_size=100, chunk_overlap=10)
    count = rag.index(ai, "Python is a programming language. It is widely used.")
    assert count >= 1
    results = rag.retrieve(ai, "programming", top_k=1)
    assert len(results) == 1
    assert results[0][1] > 0


def test_rag_ask(ai):
    rag = RAGPipeline(chunk_size=200)
    rag.index(ai, "The capital of France is Paris.")
    response = rag.ask(ai, "What is the capital of France?")
    assert response.content


def test_chunk_text():
    text = "a" * 100
    chunks = chunk_text(text, chunk_size=30, chunk_overlap=5)
    assert len(chunks) >= 3


def test_vector_store():
    store = VectorStore()
    doc = Document(content="test", id="1")
    store.add(doc, [1.0, 0.0])
    results = store.search([1.0, 0.0], top_k=1)
    assert results[0][0].content == "test"


@pytest.mark.asyncio
async def test_chat_async(ai):
    response = await ai.chat_async("Hello async")
    assert response.content


@pytest.mark.asyncio
async def test_embed_async(ai):
    vectors = await ai.embed_async("hello")
    assert len(vectors) == 1


@pytest.mark.asyncio
async def test_stream_async(ai):
    parts = []
    async for token in ai.chat_stream_async("stream test"):
        parts.append(token)
    assert parts


def test_message_to_dict():
    msg = Message(role=Role.USER, content="hi")
    d = msg.to_dict()
    assert d["role"] == "user"
    assert d["content"] == "hi"


def test_json_echo(ai):
    response = ai.chat("json: hello")
    data = json.loads(response.content)
    assert data["parsed"] == "hello"
