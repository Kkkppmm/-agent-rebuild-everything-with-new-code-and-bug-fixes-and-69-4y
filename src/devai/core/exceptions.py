"""Core exceptions for DevAI."""

from __future__ import annotations


class DevAIError(Exception):
    """Base exception for all DevAI errors."""


class LLMError(DevAIError):
    """Raised when an LLM API call fails."""


class ConfigError(DevAIError):
    """Raised when configuration is invalid or missing."""


class ParseError(DevAIError):
    """Raised when structured output parsing fails."""


class ToolError(DevAIError):
    """Raised when a tool execution fails."""


class AgentError(DevAIError):
    """Raised when an agent encounters an unrecoverable error."""
