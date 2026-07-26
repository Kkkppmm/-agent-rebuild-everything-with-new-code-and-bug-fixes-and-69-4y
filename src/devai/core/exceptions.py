"""DevAI exception hierarchy."""


class DevAIError(Exception):
    """Base exception for all DevAI errors."""


class ConfigurationError(DevAIError):
    """Raised when configuration is invalid or incomplete."""


class APIError(DevAIError):
    """Raised when an API request fails."""

    def __init__(self, message: str, status_code: int | None = None, body: str | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.body = body


class RateLimitError(APIError):
    """Raised when the API rate limit is exceeded."""


class AuthenticationError(APIError):
    """Raised when authentication fails."""


class ParseError(DevAIError):
    """Raised when output parsing fails."""


class ToolExecutionError(DevAIError):
    """Raised when a tool fails to execute."""
