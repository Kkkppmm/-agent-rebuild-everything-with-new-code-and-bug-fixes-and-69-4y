"""Exception hierarchy for DevAI."""


class DevAIError(Exception):
    """Base exception for all DevAI errors."""


class ConfigurationError(DevAIError):
    """Raised when configuration is invalid or missing."""


class APIError(DevAIError):
    """Raised when the LLM API returns an error."""

    def __init__(self, message: str, status_code: int | None = None, body: str | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.body = body


class RateLimitError(APIError):
    """Raised when the API rate limit is exceeded."""


class AuthenticationError(APIError):
    """Raised when API authentication fails."""


class ToolExecutionError(DevAIError):
    """Raised when a tool fails during execution."""


class AgentError(DevAIError):
    """Raised when an agent encounters an unrecoverable error."""
