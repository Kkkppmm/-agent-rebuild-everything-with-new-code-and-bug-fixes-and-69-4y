"""Exception hierarchy for DevAI."""

from __future__ import annotations


class DevAIError(Exception):
    """Base exception for all DevAI errors."""


class ProviderError(DevAIError):
    """Raised when an upstream provider returns an error."""

    def __init__(self, message: str, status_code: int | None = None, body: str | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.body = body


class ConfigurationError(DevAIError):
    """Raised when client configuration is invalid."""


class ToolExecutionError(DevAIError):
    """Raised when a registered tool fails during execution."""
