"""Tests for disk-backed LLM cache."""

import pytest

from devai.core import MockLLMClient
from devai.core.disk_cache import DiskCachedLLMClient
from devai.core.models import Message


class TestDiskCachedLLMClient:
    def test_caches_to_disk(self, tmp_path):
        client = MockLLMClient(default_response="cached-response")
        disk = DiskCachedLLMClient(client, cache_dir=tmp_path)
        messages = [Message.user("hello")]

        first = disk.complete(messages)
        second = disk.complete(messages)

        assert first == second
        assert disk.cache_size == 1

    def test_different_prompts_different_cache(self, tmp_path):
        client = MockLLMClient()
        disk = DiskCachedLLMClient(client, cache_dir=tmp_path)

        disk.complete([Message.user("a")])
        disk.complete([Message.user("b")])

        assert disk.cache_size == 2

    def test_clear_cache(self, tmp_path):
        client = MockLLMClient()
        disk = DiskCachedLLMClient(client, cache_dir=tmp_path)
        disk.complete([Message.user("x")])
        assert disk.cache_size == 1
        disk.clear_cache()
        assert disk.cache_size == 0

    def test_max_entries_evicts_oldest(self, tmp_path):
        client = MockLLMClient()
        disk = DiskCachedLLMClient(client, cache_dir=tmp_path, max_entries=2)

        disk.complete([Message.user("1")])
        disk.complete([Message.user("2")])
        disk.complete([Message.user("3")])

        assert disk.cache_size == 2

    @pytest.mark.asyncio
    async def test_async_complete_cached(self, tmp_path):
        client = MockLLMClient(default_response="async-cached")
        disk = DiskCachedLLMClient(client, cache_dir=tmp_path)
        messages = [Message.user("async")]

        first = await disk.acomplete(messages)
        second = await disk.acomplete(messages)

        assert first == second
        assert disk.cache_size == 1
