"""Exception hierarchy for DevAI."""


class DevAIError(Exception):
    """Base exception for all DevAI errors."""


class LLMError(DevAIError):
    """Raised when an LLM API call fails."""


class RateLimitError(LLMError):
    """Raised when the LLM provider rate-limits requests."""


class ParseError(DevAIError):
    """Raised when structured output parsing fails."""


class ToolExecutionError(DevAIError):
    """Raised when a tool fails during execution."""
