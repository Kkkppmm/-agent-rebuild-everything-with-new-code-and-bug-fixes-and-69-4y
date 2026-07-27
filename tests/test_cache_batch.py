"""Tests for cache and batch modules."""

from devai.core.client import MockLLMClient
from devai.core.cache import CachedLLMClient
from devai.core.batch import BatchRunner, BatchRequest


class TestCachedLLMClient:
    def test_caches_repeated_prompts(self):
        client = MockLLMClient(responses=["first", "second"])
        cached = CachedLLMClient(client)

        assert cached.complete("hello").content == "first"
        assert cached.complete("hello").content == "first"
        assert cached.stats["hits"] == 1
        assert cached.stats["misses"] == 1

    def test_different_prompts_not_cached_together(self):
        client = MockLLMClient(responses=["a", "b"])
        cached = CachedLLMClient(client)

        assert cached.complete("prompt-a").content == "a"
        assert cached.complete("prompt-b").content == "b"
        assert cached.stats["misses"] == 2

    def test_clear_resets_cache(self):
        client = MockLLMClient(responses=["one", "two"])
        cached = CachedLLMClient(client)
        cached.complete("x")
        cached.clear()
        assert cached.stats["size"] == 0


class TestBatchRunner:
    def test_run_prompts(self):
        client = MockLLMClient(responses=["r1", "r2", "r3"])
        runner = BatchRunner(client)
        results = runner.run_prompts(["p1", "p2", "p3"])
        assert results == ["r1", "r2", "r3"]

    def test_arun_with_metadata(self):
        client = MockLLMClient(responses=["done"])
        runner = BatchRunner(client)
        results = runner.run([
            BatchRequest(prompt="test", metadata={"id": 1}),
        ])
        assert len(results) == 1
        assert results[0].content == "done"
        assert results[0].metadata == {"id": 1}

    def test_max_concurrency(self):
        client = MockLLMClient(responses=["a", "b"])
        runner = BatchRunner(client, max_concurrency=1)
        results = runner.run_prompts(["one", "two"])
        assert len(results) == 2
