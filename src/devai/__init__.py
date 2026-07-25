"""DevAI — A Python AI library for developers and programmers."""

from devai.agents.agent import Agent
from devai.agents.coder_agent import CoderAgent
from devai.chains.chain import Chain
from devai.core.client import LLMClient
from devai.core.config import DevAIConfig
from devai.core.models import Message, Role, ToolCall, ToolDefinition
from devai.memory.conversation import ConversationMemory
from devai.prompts.template import PromptTemplate
from devai.tools.registry import ToolRegistry

__version__ = "0.1.0"

__all__ = [
    "Agent",
    "CoderAgent",
    "Chain",
    "ConversationMemory",
    "DevAIConfig",
    "LLMClient",
    "Message",
    "PromptTemplate",
    "Role",
    "ToolCall",
    "ToolDefinition",
    "ToolRegistry",
    "__version__",
]
