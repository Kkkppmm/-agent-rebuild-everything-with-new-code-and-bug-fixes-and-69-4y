"""Custom exceptions for DevAI."""


class DevAIError(Exception):
    """Base exception for all DevAI errors."""


class LLMError(DevAIError):
    """Raised when an LLM API call fails."""


class RateLimitError(LLMError):
    """Raised when rate limits are exceeded."""


class ParseError(DevAIError):
    """Raised when output parsing fails."""


class ToolError(DevAIError):
    """Raised when a tool execution fails."""
