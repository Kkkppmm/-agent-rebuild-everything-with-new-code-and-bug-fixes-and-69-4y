"""Exceptions for DevAI."""


class DevAIError(Exception):
  """Base exception for DevAI."""


class LLMError(DevAIError):
  """Raised when an LLM API call fails."""


class RateLimitError(LLMError):
  """Raised when rate limited by the LLM provider."""


class ParseError(DevAIError):
  """Raised when structured output parsing fails."""


class ToolExecutionError(DevAIError):
  """Raised when a tool fails to execute."""
