"""DevAI — a lightweight Python AI library for developers."""

from devai.client import DevAI
from devai.chat import ChatSession, Message, Role
from devai.embeddings import EmbeddingResult
from devai.prompts import PromptTemplate
from devai.rag import Document, RAGPipeline, VectorStore
from devai.tools import Tool, ToolRegistry
from devai.types import ChatResponse, Usage

__version__ = "0.1.0"

__all__ = [
    "DevAI",
    "ChatSession",
    "Message",
    "Role",
    "EmbeddingResult",
    "PromptTemplate",
    "Document",
    "RAGPipeline",
    "VectorStore",
    "Tool",
    "ToolRegistry",
    "ChatResponse",
    "Usage",
]
