"""DevAI — a Python AI library for developers and programmers."""

from devai.core.client import LLMClient, MockLLMClient
from devai.core.config import DevAIConfig
from devai.core.models import Message, Role, Tool, ToolCall
from devai.agents.agent import Agent
from devai.agents.coder import CoderAgent
from devai.chains.chain import Chain, SequentialChain, StructuredChain
from devai.memory.conversation import ConversationMemory
from devai.prompts.template import PromptTemplate
from devai.tools.registry import ToolRegistry

__version__ = "0.3.0"

__all__ = [
    "Agent",
    "Chain",
    "CoderAgent",
    "ConversationMemory",
    "DevAIConfig",
    "LLMClient",
    "Message",
    "MockLLMClient",
    "PromptTemplate",
    "Role",
    "SequentialChain",
    "StructuredChain",
    "Tool",
    "ToolCall",
    "ToolRegistry",
    "__version__",
]
