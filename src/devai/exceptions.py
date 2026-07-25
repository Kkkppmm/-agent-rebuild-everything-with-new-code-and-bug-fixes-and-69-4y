"""Custom exceptions for the devai library."""


class DevAIError(Exception):
    """Base exception for all devai errors."""


class APIError(DevAIError):
    """Raised when an upstream API returns an error."""

    def __init__(self, message: str, status_code: int | None = None, body: str | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.body = body


class ConfigurationError(DevAIError):
    """Raised when required configuration is missing or invalid."""


class ToolExecutionError(DevAIError):
    """Raised when a registered tool fails during execution."""
