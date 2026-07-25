"""Exception hierarchy for DevAI."""


class DevAIError(Exception):
    """Base exception for all DevAI errors."""


class LLMError(DevAIError):
    """Raised when an LLM API call fails."""


class RateLimitError(LLMError):
    """Raised when the LLM provider rate-limits requests."""


class ToolExecutionError(DevAIError):
    """Raised when a tool fails during execution."""


class ConfigurationError(DevAIError):
    """Raised when configuration is invalid or incomplete."""
