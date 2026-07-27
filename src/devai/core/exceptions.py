"""DevAI exception hierarchy."""


class DevAIError(Exception):
    """Base exception for all DevAI errors."""


class ConfigurationError(DevAIError):
    """Raised when configuration is invalid or incomplete."""


class ProviderError(DevAIError):
    """Raised when an LLM provider returns an error."""


class AuthenticationError(ProviderError):
    """Raised when API authentication fails."""


class RateLimitError(ProviderError):
    """Raised when rate limits are exceeded."""
