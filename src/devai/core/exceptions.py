"""DevAI exceptions."""


class DevAIError(Exception):
    """Base exception for all DevAI errors."""


class ConfigError(DevAIError):
    """Raised when configuration is invalid or incomplete."""


class APIError(DevAIError):
    """Raised when an LLM API request fails."""

    def __init__(self, message: str, status_code: int | None = None, body: str | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.body = body


class RetryExhaustedError(DevAIError):
    """Raised when all retry attempts are exhausted."""


class ParseError(DevAIError):
    """Raised when structured output parsing fails."""


class ToolError(DevAIError):
    """Raised when a tool execution fails."""
