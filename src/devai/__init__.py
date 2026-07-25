"""DevAI — A Python AI library for developers and programmers."""

from devai.core.client import LLMClient
from devai.core.config import DevAIConfig
from devai.core.models import Message, Role, Tool, ToolCall
from devai.agents.agent import Agent
from devai.agents.coder import CoderAgent
from devai.chains.chain import Chain, SequentialChain
from devai.memory.conversation import ConversationMemory
from devai.prompts.template import PromptTemplate
from devai.tools.registry import ToolRegistry

__version__ = "0.1.0"
__all__ = [
    "LLMClient",
    "DevAIConfig",
    "Message",
    "Role",
    "Tool",
    "ToolCall",
    "Agent",
    "CoderAgent",
    "Chain",
    "SequentialChain",
    "ConversationMemory",
    "PromptTemplate",
    "ToolRegistry",
    "__version__",
]
