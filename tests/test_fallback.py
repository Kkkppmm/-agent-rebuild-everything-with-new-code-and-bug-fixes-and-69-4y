"""Tests for FallbackLLMClient."""

import pytest

from devai.core import FallbackLLMClient, LLMError, Message, MockLLMClient
from devai.core.exceptions import LLMError as CoreLLMError


class TestFallbackLLMClient:
    def test_uses_first_successful_client(self):
        primary = MockLLMClient()
        primary.complete = lambda *a, **kw: (_ for _ in ()).throw(CoreLLMError("down"))  # type: ignore[method-assign]
        fallback = MockLLMClient(default_response="backup")
        client = FallbackLLMClient([primary, fallback], labels=["primary", "fallback"])
        assert client.complete([Message.user("hi")]) == "backup"
        assert client.last_success_index == 1
        assert len(client.attempts) == 2

    def test_raises_when_all_fail(self):
        primary = MockLLMClient()
        primary.complete = lambda *a, **kw: (_ for _ in ()).throw(CoreLLMError("fail-1"))  # type: ignore[method-assign]
        secondary = MockLLMClient()
        secondary.complete = lambda *a, **kw: (_ for _ in ()).throw(CoreLLMError("fail-2"))  # type: ignore[method-assign]
        client = FallbackLLMClient([primary, secondary])
        with pytest.raises(LLMError, match="All 2 LLM clients failed"):
            client.complete([Message.user("hi")])

    def test_requires_clients(self):
        with pytest.raises(ValueError, match="at least one client"):
            FallbackLLMClient([])

    async def test_acomplete_fallback(self):
        primary = MockLLMClient()
        primary.acomplete = lambda *a, **kw: (_ for _ in ()).throw(CoreLLMError("down"))  # type: ignore[method-assign]
        fallback = MockLLMClient(default_response="async-backup")
        client = FallbackLLMClient([primary, fallback])
        result = await client.acomplete([Message.user("hi")])
        assert result == "async-backup"
