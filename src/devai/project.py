"""CodeProject — scan and index a codebase for AI workflows."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from devai.rag import VectorStore, chunk_text
from devai.utils import estimate_tokens, truncate_to_tokens

LANGUAGE_EXTENSIONS: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".jsx": "javascript",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".rb": "ruby",
    ".cpp": "cpp",
    ".c": "c",
    ".h": "c",
    ".cs": "csharp",
    ".php": "php",
    ".swift": "swift",
    ".kt": "kotlin",
    ".sql": "sql",
    ".sh": "shell",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".toml": "toml",
    ".md": "markdown",
    ".json": "json",
}

DEFAULT_IGNORE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    ".tox",
    "dist",
    "build",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
}


@dataclass
class ProjectFile:
    """A source file discovered in a project."""

    path: str
    language: str
    size: int
    line_count: int


@dataclass
class CodeProject:
    """Scan and index a codebase for AI-assisted development."""

    root: str
    extensions: set[str] | None = None
    ignore_dirs: set[str] = field(default_factory=lambda: set(DEFAULT_IGNORE_DIRS))

    def _should_skip(self, path: Path) -> bool:
        return any(part in self.ignore_dirs for part in path.parts)

    def _language_for(self, path: Path) -> str | None:
        ext = path.suffix.lower()
        if self.extensions and ext not in self.extensions:
            return None
        return LANGUAGE_EXTENSIONS.get(ext)

    def scan(self) -> list[ProjectFile]:
        """Discover source files in the project root."""
        root = Path(self.root)
        if not root.exists():
            return []

        files: list[ProjectFile] = []
        for path in sorted(root.rglob("*")):
            if not path.is_file() or self._should_skip(path):
                continue
            language = self._language_for(path)
            if language is None:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            files.append(
                ProjectFile(
                    path=str(path.relative_to(root)),
                    language=language,
                    size=path.stat().st_size,
                    line_count=text.count("\n") + 1,
                )
            )
        return files

    def summary(self) -> str:
        """Return a human-readable project summary."""
        files = self.scan()
        if not files:
            return f"No source files found in {self.root}"

        by_lang: dict[str, int] = {}
        total_lines = 0
        for f in files:
            by_lang[f.language] = by_lang.get(f.language, 0) + 1
            total_lines += f.line_count

        lines = [
            f"Project: {self.root}",
            f"Files: {len(files)}",
            f"Total lines: {total_lines}",
            "Languages:",
        ]
        for lang, count in sorted(by_lang.items(), key=lambda x: -x[1]):
            lines.append(f"  {lang}: {count} files")
        return "\n".join(lines)

    def read_file(self, relative_path: str, max_lines: int = 500) -> str:
        """Read a project file by relative path."""
        path = Path(self.root) / relative_path
        if not path.exists():
            return f"File not found: {relative_path}"
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            return f"Error reading {relative_path}: {e}"
        lines = content.split("\n")
        if len(lines) > max_lines:
            return "\n".join(lines[:max_lines]) + f"\n... [{len(lines) - max_lines} more lines]"
        return content

    def to_vector_store(self, max_files: int = 200, chunk_size: int = 800) -> VectorStore:
        """Index project files into a vector store for RAG."""
        store = VectorStore()
        root = Path(self.root)
        texts: list[str] = []
        metadata: list[dict] = []

        for pf in self.scan()[:max_files]:
            path = root / pf.path
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for chunk in chunk_text(content, chunk_size=chunk_size):
                texts.append(f"File: {pf.path}\n\n{chunk}")
                metadata.append({"path": pf.path, "language": pf.language})

        if texts:
            store.add_documents(texts, metadata)
        return store

    def build_context(
        self,
        query: str | None = None,
        max_tokens: int = 8000,
        top_k: int = 5,
    ) -> str:
        """Build LLM context from the project, optionally ranked by query."""
        summary = self.summary()
        parts = [summary, ""]

        if query:
            store = self.to_vector_store()
            docs = store.search(query, top_k=top_k)
            if docs:
                parts.append("Relevant code:")
                for doc in docs:
                    parts.append(doc.content)
                    parts.append("")
        else:
            files = self.scan()[:10]
            if files:
                parts.append("Sample files:")
                for pf in files:
                    content = self.read_file(pf.path, max_lines=50)
                    parts.append(f"--- {pf.path} ({pf.language}) ---")
                    parts.append(content)
                    parts.append("")

        return truncate_to_tokens("\n".join(parts), max_tokens)

    def token_estimate(self) -> int:
        """Estimate total tokens across all project files."""
        total = 0
        root = Path(self.root)
        for pf in self.scan():
            try:
                content = (root / pf.path).read_text(encoding="utf-8", errors="replace")
                total += estimate_tokens(content)
            except OSError:
                continue
        return total
