"""Tests for async DevAI facade methods."""

import pytest

from devai import DevAI


class TestAsyncFacade:
    @pytest.mark.asyncio
    async def test_areview(self):
        ai = DevAI.mock()
        result = await ai.areview("def add(a, b): return a + b")
        assert isinstance(result, str)
        assert result

    @pytest.mark.asyncio
    async def test_aexplain(self):
        ai = DevAI.mock()
        result = await ai.aexplain("x = 1 + 2")
        assert isinstance(result, str)
        assert result
