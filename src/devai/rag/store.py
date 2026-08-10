"""RAG (Retrieval-Augmented Generation) for DevAI."""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from dataclasses import dataclass, field

from devai.core.client import LLMClientProtocol
from devai.core.models import Message


def chunk_text(
    text: str,
    chunk_size: int = 500,
    overlap: int = 50,
    separator: str = "\n",
) -> list[str]:
    """Split text into overlapping chunks."""
    if not text.strip():
        return []

    paragraphs = text.split(separator)
    chunks: list[str] = []
    current: list[str] = []
    current_len = 0

    for para in paragraphs:
        para_len = len(para)
        if current_len + para_len > chunk_size and current:
            chunks.append(separator.join(current))
            # Keep overlap
            overlap_text = separator.join(current)
            if len(overlap_text) > overlap:
                overlap_text = overlap_text[-overlap:]
                current = [overlap_text, para]
                current_len = len(overlap_text) + para_len
            else:
                current = [para]
                current_len = para_len
        else:
            current.append(para)
            current_len += para_len

    if current:
        chunks.append(separator.join(current))

    return chunks


def _tokenize(text: str) -> list[str]:
    return re.findall(r"\b\w+\b", text.lower())


def _tfidf_vector(text: str, idf: dict[str, float]) -> dict[str, float]:
    tokens = _tokenize(text)
    tf = Counter(tokens)
    total = len(tokens) or 1
    return {word: (count / total) * idf.get(word, 1.0) for word, count in tf.items()}


def _cosine_similarity(a: dict[str, float], b: dict[str, float]) -> float:
    common = set(a) & set(b)
    if not common:
        return 0.0
    dot = sum(a[k] * b[k] for k in common)
    mag_a = math.sqrt(sum(v * v for v in a.values()))
    mag_b = math.sqrt(sum(v * v for v in b.values()))
    if mag_a == 0 or mag_b == 0:
        return 0.0
    return dot / (mag_a * mag_b)


@dataclass
class Document:
    """A document chunk with metadata."""

    content: str
    metadata: dict = field(default_factory=dict)
    doc_id: str = ""

    def __post_init__(self) -> None:
        if not self.doc_id:
            self.doc_id = hashlib.md5(self.content.encode()).hexdigest()[:12]


class VectorStore:
    """Simple in-memory vector store using TF-IDF."""

    def __init__(self) -> None:
        self.documents: list[Document] = []
        self._idf: dict[str, float] = {}
        self._vectors: list[dict[str, float]] = []

    def add_documents(self, texts: list[str], metadata: list[dict] | None = None) -> None:
        meta = metadata or [{}] * len(texts)
        for text, m in zip(texts, meta):
            self.documents.append(Document(content=text, metadata=m))
        self._rebuild_index()

    def _rebuild_index(self) -> None:
        all_tokens: list[set[str]] = []
        for doc in self.documents:
            all_tokens.append(set(_tokenize(doc.content)))

        n = len(self.documents) or 1
        df: Counter[str] = Counter()
        for tokens in all_tokens:
            df.update(tokens)

        self._idf = {word: math.log(n / (count + 1)) + 1 for word, count in df.items()}
        self._vectors = [_tfidf_vector(doc.content, self._idf) for doc in self.documents]

    def search(self, query: str, top_k: int = 3) -> list[Document]:
        if not self.documents:
            return []

        query_vec = _tfidf_vector(query, self._idf)
        scores = [
            (i, _cosine_similarity(query_vec, vec))
            for i, vec in enumerate(self._vectors)
        ]
        scores.sort(key=lambda x: x[1], reverse=True)

        return [self.documents[i] for i, score in scores[:top_k] if score > 0]

    def __len__(self) -> int:
        return len(self.documents)


class RAGChain:
    """Retrieval-augmented generation chain."""

    def __init__(
        self,
        client: LLMClientProtocol,
        store: VectorStore,
        top_k: int = 3,
    ) -> None:
        self.client = client
        self.store = store
        self.top_k = top_k

    def query(self, question: str) -> str:
        docs = self.store.search(question, top_k=self.top_k)
        if not docs:
            context = "No relevant documents found."
        else:
            context = "\n\n---\n\n".join(d.content for d in docs)

        messages = [
            Message.system(
                "Answer the question based on the provided context. "
                "If the context doesn't contain the answer, say so."
            ),
            Message.user(f"Context:\n{context}\n\nQuestion: {question}"),
        ]
        return self.client.complete(messages)

    async def aquery(self, question: str) -> str:
        docs = self.store.search(question, top_k=self.top_k)
        if not docs:
            context = "No relevant documents found."
        else:
            context = "\n\n---\n\n".join(d.content for d in docs)

        messages = [
            Message.system(
                "Answer the question based on the provided context. "
                "If the context doesn't contain the answer, say so."
            ),
            Message.user(f"Context:\n{context}\n\nQuestion: {question}"),
        ]
        return await self.client.acomplete(messages)
