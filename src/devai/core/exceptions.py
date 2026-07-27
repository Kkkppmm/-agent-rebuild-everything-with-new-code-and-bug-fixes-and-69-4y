"""DevAI exception hierarchy."""


class DevAIError(Exception):
    """Base exception for all DevAI errors."""


class LLMError(DevAIError):
    """Raised when an LLM API call fails."""


class RateLimitError(LLMError):
    """Raised when the API rate limit is exceeded."""


class ToolError(DevAIError):
    """Raised when a tool execution fails."""


class ParseError(DevAIError):
    """Raised when structured output parsing fails."""
