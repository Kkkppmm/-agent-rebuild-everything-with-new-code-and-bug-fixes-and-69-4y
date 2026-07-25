"""RAG utilities: chunking, vector store, and retrieval pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from devai.embeddings import cosine_similarity, find_most_similar


@dataclass
class Document:
    """A text document with optional metadata."""

    content: str
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str | None = None


@dataclass
class VectorStore:
    """In-memory vector store for semantic search."""

    documents: list[Document] = field(default_factory=list)
    vectors: list[list[float]] = field(default_factory=list)

    def add(self, doc: Document, vector: list[float]) -> None:
        self.documents.append(doc)
        self.vectors.append(vector)

    def add_batch(self, docs: list[Document], vectors: list[list[float]]) -> None:
        for doc, vec in zip(docs, vectors):
            self.add(doc, vec)

    def search(self, query_vector: list[float], top_k: int = 5) -> list[tuple[Document, float]]:
        matches = find_most_similar(query_vector, self.vectors, top_k=top_k)
        return [(self.documents[i], score) for i, score in matches]

    def __len__(self) -> int:
        return len(self.documents)


def chunk_text(
    text: str,
    chunk_size: int = 500,
    chunk_overlap: int = 50,
    separator: str = "\n",
) -> list[str]:
    """Split text into overlapping chunks for embedding."""
    if not text:
        return []

    if len(text) <= chunk_size:
        return [text]

    chunks: list[str] = []
    parts = text.split(separator)
    current = ""

    for part in parts:
        candidate = f"{current}{separator}{part}" if current else part
        if len(candidate) <= chunk_size:
            current = candidate
        else:
            if current:
                chunks.append(current)
            if len(part) > chunk_size:
                for i in range(0, len(part), chunk_size - chunk_overlap):
                    chunks.append(part[i : i + chunk_size])
                current = ""
            else:
                current = part

    if current:
        chunks.append(current)

    return _merge_overlap(chunks, chunk_overlap)


def _merge_overlap(chunks: list[str], overlap: int) -> list[str]:
    if overlap <= 0 or len(chunks) < 2:
        return chunks
    merged = [chunks[0]]
    for chunk in chunks[1:]:
        prev = merged[-1]
        if len(prev) > overlap and chunk.startswith(prev[-overlap:]):
            merged.append(chunk[overlap:])
        else:
            merged.append(chunk)
    return merged


@dataclass
class RAGPipeline:
    """
    Retrieval-augmented generation pipeline.

    Indexes documents, retrieves relevant chunks, and builds context for chat.
    """

    store: VectorStore = field(default_factory=VectorStore)
    chunk_size: int = 500
    chunk_overlap: int = 50

    def index(self, client: Any, texts: list[str] | str, metadata: list[dict] | None = None) -> int:
        """Chunk and embed texts into the vector store."""
        if isinstance(texts, str):
            texts = [texts]
        metadata = metadata or [{} for _ in texts]
        all_docs: list[Document] = []
        all_chunks: list[str] = []

        for i, text in enumerate(texts):
            meta = metadata[i] if i < len(metadata) else {}
            for j, chunk in enumerate(chunk_text(text, self.chunk_size, self.chunk_overlap)):
                doc = Document(content=chunk, metadata={**meta, "chunk": j})
                all_docs.append(doc)
                all_chunks.append(chunk)

        vectors = client.embed(all_chunks)
        self.store.add_batch(all_docs, vectors)
        return len(all_docs)

    def retrieve(self, client: Any, query: str, top_k: int = 3) -> list[tuple[Document, float]]:
        """Find documents most similar to the query."""
        query_vec = client.embed(query)[0]
        return self.store.search(query_vec, top_k=top_k)

    def build_context(self, client: Any, query: str, top_k: int = 3) -> str:
        """Retrieve relevant chunks and format as context string."""
        results = self.retrieve(client, query, top_k=top_k)
        if not results:
            return ""
        lines = ["Relevant context:"]
        for doc, score in results:
            lines.append(f"[score={score:.3f}] {doc.content}")
        return "\n".join(lines)

    def ask(
        self,
        client: Any,
        question: str,
        top_k: int = 3,
        system: str | None = None,
        **kwargs: Any,
    ) -> Any:
        """RAG query: retrieve context and chat with the model."""
        context = self.build_context(client, question, top_k=top_k)
        system_prompt = system or "Answer using the provided context. If unsure, say so."
        prompt = f"{context}\n\nQuestion: {question}"
        return client.chat(prompt, system=system_prompt, **kwargs)
