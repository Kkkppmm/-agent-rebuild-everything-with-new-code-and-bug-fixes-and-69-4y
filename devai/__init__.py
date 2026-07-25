"""DevAI — a lightweight Python AI library for developers."""

from devai.agents.agent import Agent, CoderAgent
from devai.chains.chain import Chain
from devai.core.client import LLMClient
from devai.core.config import DevAIConfig
from devai.core.exceptions import APIError, AgentError, DevAIError, ToolError
from devai.core.models import Message, Role, ToolCall, ToolDefinition
from devai.memory.conversation import ConversationMemory
from devai.prompts.template import PromptTemplate
from devai.tools.registry import ToolRegistry
from devai.utils.text import estimate_tokens, extract_code_blocks, truncate_to_tokens

__version__ = "0.1.0"

__all__ = [
    "Agent",
    "APIError",
    "AgentError",
    "Chain",
    "CoderAgent",
    "ConversationMemory",
    "DevAIConfig",
    "DevAIError",
    "LLMClient",
    "Message",
    "PromptTemplate",
    "Role",
    "ToolCall",
    "ToolDefinition",
    "ToolError",
    "ToolRegistry",
    "estimate_tokens",
    "extract_code_blocks",
    "truncate_to_tokens",
    "__version__",
]
