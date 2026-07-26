"""Exception types for DevAI."""


class DevAIError(Exception):
    """Base exception for all DevAI errors."""


class LLMError(DevAIError):
    """Raised when an LLM API call fails."""


class ParseError(DevAIError):
    """Raised when structured output parsing fails."""


class ToolError(DevAIError):
    """Raised when a tool execution fails."""
