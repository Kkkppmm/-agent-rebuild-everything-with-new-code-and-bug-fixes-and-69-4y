"""Batch code review for multiple files and directories."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

from devai.assistant import CodeAssistant


@dataclass(frozen=True)
class FileReviewResult:
    """Result of reviewing a single file."""

    path: str
    review: str
    language: str | None = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


@dataclass
class BatchReviewReport:
    """Aggregated results from a batch review."""

    results: list[FileReviewResult]

    @property
    def reviewed(self) -> list[FileReviewResult]:
        return [r for r in self.results if r.ok]

    @property
    def failed(self) -> list[FileReviewResult]:
        return [r for r in self.results if not r.ok]

    def summary(self) -> str:
        lines = [
            f"Reviewed {len(self.reviewed)} file(s), {len(self.failed)} failed",
        ]
        for result in self.results:
            status = "ok" if result.ok else f"error: {result.error}"
            lines.append(f"  {result.path} [{status}]")
        return "\n".join(lines)

    def to_markdown(self) -> str:
        parts = ["# Batch Code Review\n"]
        for result in self.results:
            parts.append(f"## {result.path}\n")
            if result.error:
                parts.append(f"**Error:** {result.error}\n")
            else:
                parts.append(result.review.strip())
                parts.append("")
        return "\n".join(parts)


def _guess_language(path: Path) -> str | None:
    suffix_map = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".jsx": "javascript",
        ".go": "go",
        ".rs": "rust",
        ".java": "java",
        ".rb": "ruby",
        ".sql": "sql",
        ".sh": "bash",
        ".yaml": "yaml",
        ".yml": "yaml",
        ".json": "json",
        ".md": "markdown",
    }
    return suffix_map.get(path.suffix.lower())


class BatchReviewer:
    """Review multiple source files in parallel using CodeAssistant."""

    def __init__(self, assistant: CodeAssistant, max_workers: int = 4) -> None:
        self.assistant = assistant
        self.max_workers = max_workers

    def review_file(self, path: str | Path) -> FileReviewResult:
        """Review a single file."""
        file_path = Path(path)
        if not file_path.exists():
            return FileReviewResult(
                path=str(file_path),
                review="",
                error=f"File not found: {file_path}",
            )
        try:
            code = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return FileReviewResult(
                path=str(file_path),
                review="",
                error=str(exc),
            )
        review = self.assistant.review(code)
        return FileReviewResult(
            path=str(file_path),
            review=review,
            language=_guess_language(file_path),
        )

    def review_files(self, paths: list[str | Path]) -> BatchReviewReport:
        """Review multiple files in parallel."""
        results: list[FileReviewResult | None] = [None] * len(paths)

        def _review(idx: int, path: str | Path) -> tuple[int, FileReviewResult]:
            return idx, self.review_file(path)

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(_review, i, path): i for i, path in enumerate(paths)
            }
            for future in as_completed(futures):
                idx, result = future.result()
                results[idx] = result

        return BatchReviewReport(results=[r for r in results if r is not None])

    def review_directory(
        self,
        directory: str | Path,
        *,
        pattern: str = "*.py",
        recursive: bool = True,
    ) -> BatchReviewReport:
        """Review all files matching a glob pattern in a directory."""
        root = Path(directory)
        if not root.exists():
            return BatchReviewReport(
                results=[
                    FileReviewResult(
                        path=str(root),
                        review="",
                        error=f"Directory not found: {root}",
                    )
                ]
            )
        globber = root.rglob if recursive else root.glob
        paths = sorted(
            p
            for p in globber(pattern)
            if p.is_file() and not any(part.startswith(".") for part in p.parts)
        )
        if not paths:
            return BatchReviewReport(
                results=[
                    FileReviewResult(
                        path=str(root),
                        review="",
                        error=f"No files matching '{pattern}' in {root}",
                    )
                ]
            )
        return self.review_files(paths)
