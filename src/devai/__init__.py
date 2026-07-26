"""DevAI — A Python AI library for developers and programmers."""

from devai.core.client import EmbeddingClient, LLMClient, MockLLMClient
from devai.core.config import DevAIConfig
from devai.core.messages import Message, Role, ToolCall, ToolDefinition
from devai.agents.agent import Agent
from devai.agents.coder import CoderAgent
from devai.chains.simple import SimpleChain
from devai.chains.sequential import SequentialChain
from devai.chains.structured import StructuredChain
from devai.memory.conversation import ConversationMemory
from devai.pipeline import DevPipeline
from devai.prompts.template import PromptTemplate

__version__ = "0.4.0"

__all__ = [
    "__version__",
    "Agent",
    "CoderAgent",
    "ConversationMemory",
    "DevAIConfig",
    "DevPipeline",
    "EmbeddingClient",
    "LLMClient",
    "Message",
    "MockLLMClient",
    "PromptTemplate",
    "Role",
    "SequentialChain",
    "SimpleChain",
    "StructuredChain",
    "ToolCall",
    "ToolDefinition",
]
