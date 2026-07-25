"""Custom exceptions for DevAI."""

from __future__ import annotations


class DevAIError(Exception):
    """Base exception for all DevAI errors."""


class APIError(DevAIError):
    """Raised when an LLM API request fails."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class AgentError(DevAIError):
    """Raised when an agent loop fails or exceeds limits."""


class ToolError(DevAIError):
    """Raised when a tool execution fails."""
