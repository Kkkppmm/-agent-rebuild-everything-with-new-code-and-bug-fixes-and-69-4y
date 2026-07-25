"""DevAI exception hierarchy."""


class DevAIError(Exception):
    """Base exception for all DevAI errors."""


class ProviderError(DevAIError):
    """Raised when an upstream AI provider returns an error."""

    def __init__(self, message: str, *, provider: str, status_code: int | None = None):
        super().__init__(message)
        self.provider = provider
        self.status_code = status_code


class RateLimitError(ProviderError):
    """Raised when a provider rate-limits the request."""


class ConfigurationError(DevAIError):
    """Raised when required configuration is missing or invalid."""
