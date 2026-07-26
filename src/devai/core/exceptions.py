"""DevAI exception hierarchy."""


class DevAIError(Exception):
    """Base exception for all DevAI errors."""


class LLMError(DevAIError):
    """Raised when an LLM request fails."""


class RateLimitError(LLMError):
    """Raised when the API rate limit is exceeded."""


class ParseError(DevAIError):
    """Raised when structured output parsing fails."""


class ToolExecutionError(DevAIError):
    """Raised when a tool call fails during execution."""
