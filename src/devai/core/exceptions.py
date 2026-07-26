"""Core exceptions for DevAI."""

from __future__ import annotations


class DevAIError(Exception):
    """Base exception for all DevAI errors."""


class ConfigError(DevAIError):
    """Raised when configuration is invalid or missing."""


class LLMError(DevAIError):
    """Raised when an LLM API call fails."""


class RateLimitError(LLMError):
    """Raised when the API rate limit is exceeded."""


class AuthenticationError(LLMError):
    """Raised when API authentication fails."""


class ToolError(DevAIError):
    """Raised when a tool execution fails."""


class ParseError(DevAIError):
    """Raised when structured output parsing fails."""


class AgentError(DevAIError):
    """Raised when an agent encounters an unrecoverable error."""
