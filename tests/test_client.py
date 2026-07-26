"""Tests for LLM clients."""

import json

import pytest

from devai.core.client import MockLLMClient
from devai.core.models import Message, Role


def test_mock_complete():
    client = MockLLMClient(responses=["Hello!", "World!"])
    msg = client.complete([Message(role=Role.USER, content="Hi")])
    assert msg.content == "Hello!"
    assert msg.role == Role.ASSISTANT
    assert len(client.calls) == 1


def test_mock_cycles_responses():
    client = MockLLMClient(responses=["A", "B"])
    assert client.complete([Message(role=Role.USER, content="1")]).content == "A"
    assert client.complete([Message(role=Role.USER, content="2")]).content == "B"
    assert client.complete([Message(role=Role.USER, content="3")]).content == "A"


def test_mock_json_mode():
    client = MockLLMClient(responses=["plain text"])
    result = client.complete_json([Message(role=Role.USER, content="test")])
    assert result == {"result": "plain text"}


def test_mock_json_mode_valid():
    client = MockLLMClient(responses=['{"key": "value"}'])
    result = client.complete_json([Message(role=Role.USER, content="test")])
    assert result == {"key": "value"}


def test_mock_stream():
    client = MockLLMClient(responses=["hello world"])
    chunks = list(client.stream([Message(role=Role.USER, content="test")]))
    assert "".join(chunks).strip() == "hello world"
