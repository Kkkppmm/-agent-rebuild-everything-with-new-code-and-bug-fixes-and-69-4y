"""Tests for circuit breaker."""

import pytest

from devai.core import (
    CircuitBreaker,
    CircuitBreakerError,
    CircuitBreakerLLMClient,
    CircuitState,
    Message,
    MockLLMClient,
)
from devai.core.exceptions import LLMError


class TestCircuitBreaker:
    def test_starts_closed(self):
        breaker = CircuitBreaker()
        assert breaker.state == CircuitState.CLOSED

    def test_opens_after_failures(self):
        breaker = CircuitBreaker(failure_threshold=2, recovery_timeout=60)
        breaker.before_call()
        breaker.record_failure()
        breaker.before_call()
        breaker.record_failure()
        assert breaker.state == CircuitState.OPEN
        with pytest.raises(CircuitBreakerError):
            breaker.before_call()

    def test_resets_on_success(self):
        breaker = CircuitBreaker(failure_threshold=2)
        breaker.record_failure()
        breaker.record_success()
        assert breaker.state == CircuitState.CLOSED
        breaker.before_call()

    def test_manual_reset(self):
        breaker = CircuitBreaker(failure_threshold=1)
        breaker.record_failure()
        assert breaker.state == CircuitState.OPEN
        breaker.reset()
        assert breaker.state == CircuitState.CLOSED


class TestCircuitBreakerLLMClient:
    def test_success_path(self):
        inner = MockLLMClient(default_response="ok")
        client = CircuitBreakerLLMClient(inner, CircuitBreaker())
        assert client.complete([Message.user("hi")]) == "ok"

    def test_failure_opens_circuit(self):
        inner = MockLLMClient()
        inner.complete = lambda *a, **kw: (_ for _ in ()).throw(LLMError("fail"))  # type: ignore[method-assign]
        breaker = CircuitBreaker(failure_threshold=1)
        client = CircuitBreakerLLMClient(inner, breaker)
        with pytest.raises(LLMError):
            client.complete([Message.user("hi")])
        with pytest.raises(CircuitBreakerError):
            client.complete([Message.user("hi")])
