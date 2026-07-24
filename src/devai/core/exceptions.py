"""Core exceptions for DevAI."""

from typing import Any


class DevAIError(Exception):
    """Base exception for all DevAI errors."""


class ProviderError(DevAIError):
    """Raised when an LLM provider returns an error."""

    def __init__(self, message: str, status_code: int | None = None, details: Any = None):
        super().__init__(message)
        self.status_code = status_code
        self.details = details


class ConfigurationError(DevAIError):
    """Raised when configuration is invalid or missing."""


class ToolExecutionError(DevAIError):
    """Raised when a tool fails during execution."""


class ParseError(DevAIError):
    """Raised when structured output parsing fails."""
