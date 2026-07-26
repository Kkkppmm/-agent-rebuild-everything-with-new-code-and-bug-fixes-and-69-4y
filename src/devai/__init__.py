"""DevAI — a Python AI library for developers and programmers."""

from devai.core.client import LLMClient, MockLLMClient
from devai.core.config import DevAIConfig
from devai.core.models import Message, Role, Tool, ToolCall
from devai.agents.agent import Agent
from devai.agents.coder import CoderAgent
from devai.chains.chain import Chain
from devai.chains.sequential import SequentialChain
from devai.chains.structured import StructuredChain
from devai.memory.conversation import ConversationMemory
from devai.rag.rag_chain import RAGChain
from devai.prompts.template import PromptTemplate

__version__ = "0.3.0"

__all__ = [
    "LLMClient",
    "MockLLMClient",
    "DevAIConfig",
    "Message",
    "Role",
    "Tool",
    "ToolCall",
    "Agent",
    "CoderAgent",
    "Chain",
    "SequentialChain",
    "StructuredChain",
    "ConversationMemory",
    "RAGChain",
    "PromptTemplate",
    "__version__",
]
