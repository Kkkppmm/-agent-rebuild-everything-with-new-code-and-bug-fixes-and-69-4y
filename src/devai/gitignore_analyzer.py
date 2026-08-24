"""GitignoreAnalyzer — audit .gitignore coverage and detect exposed sensitive files."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path

from devai.project_detect import ProjectDetector

# Universal patterns every repo should consider ignoring.
UNIVERSAL_PATTERNS: tuple[tuple[str, str, str], ...] = (
    (".env", "high", "Environment files with secrets"),
    (".env.local", "high", "Local environment overrides"),
    (".env.*.local", "medium", "Per-environment local overrides"),
    ("*.pem", "high", "Private key files"),
    ("*.key", "high", "Private key files"),
    ("credentials.json", "high", "Credential files"),
    (".DS_Store", "low", "macOS metadata"),
    ("Thumbs.db", "low", "Windows thumbnail cache"),
)

# Language-specific recommended patterns.
LANGUAGE_PATTERNS: dict[str, tuple[tuple[str, str, str], ...]] = {
    "python": (
        ("__pycache__/", "medium", "Python bytecode cache"),
        ("*.py[cod]", "medium", "Compiled Python files"),
        (".venv/", "medium", "Virtual environment"),
        ("venv/", "medium", "Virtual environment"),
        (".pytest_cache/", "low", "Pytest cache"),
        (".mypy_cache/", "low", "Mypy cache"),
        (".ruff_cache/", "low", "Ruff cache"),
        ("*.egg-info/", "low", "Package metadata"),
        ("dist/", "low", "Build artifacts"),
        ("build/", "low", "Build artifacts"),
    ),
    "javascript": (
        ("node_modules/", "medium", "Node.js dependencies"),
        ("npm-debug.log*", "low", "npm debug logs"),
        (".next/", "low", "Next.js build output"),
        ("dist/", "low", "Build artifacts"),
    ),
    "go": (
        ("bin/", "low", "Go binary output"),
        ("vendor/", "low", "Go vendor directory"),
    ),
    "rust": (
        ("target/", "low", "Rust build output"),
    ),
    "java": (
        ("target/", "low", "Maven/Gradle build output"),
        (".gradle/", "low", "Gradle cache"),
    ),
}

# Files that should never be committed if they exist in the repo root.
SENSITIVE_FILES: tuple[tuple[str, str], ...] = (
    (".env", "Environment file with secrets"),
    (".env.local", "Local environment file"),
    ("id_rsa", "SSH private key"),
    ("credentials.json", "Credential file"),
)


@dataclass
class GitignorePattern:
    """A parsed pattern from a .gitignore file."""

    pattern: str
    source: str
    lineno: int
    negated: bool = False

    def format(self) -> str:
        """Return a single-line description."""
        prefix = "!" if self.negated else ""
        return f"{self.source}:{self.lineno} {prefix}{self.pattern}"


@dataclass
class GitignoreGap:
    """A missing or risky .gitignore configuration."""

    kind: str
    severity: str
    pattern: str
    message: str
    path: str | None = None

    def format(self) -> str:
        """Return a single-line description."""
        loc = f" ({self.path})" if self.path else ""
        return f"[{self.severity}] {self.pattern} — {self.message}{loc}"


@dataclass
class GitignoreStats:
    """Aggregate .gitignore analysis statistics."""

    patterns: int
    recommended: int
    covered: int
    gaps: int
    exposed_files: int = 0
    has_gitignore: bool = False


def _normalize_pattern(pattern: str) -> str:
    return pattern.strip().rstrip("/")


def _pattern_matches_gitignore_line(pattern: str, line: str) -> bool:
    """Return True if a .gitignore line covers the recommended pattern."""
    pat = _normalize_pattern(pattern)
    line_norm = _normalize_pattern(line)

    if pat == line_norm:
        return True
    if line_norm.endswith("/") and pat == line_norm[:-1]:
        return True
    if pat.endswith("/") and line_norm == pat[:-1]:
        return True

    # Wildcard patterns: *.pem matches if line is *.pem or **/*.pem
    if "*" in pat:
        return fnmatch.fnmatch(pat, line_norm) or fnmatch.fnmatch(line_norm, pat)

    # Directory-only patterns
    if line_norm.endswith("/"):
        return pat.startswith(line_norm) or pat == line_norm[:-1]

    return False


def _is_ignored(path: str, patterns: list[GitignorePattern]) -> bool:
    """Approximate gitignore matching for a relative file path."""
    ignored = False
    for p in patterns:
        if p.negated:
            if _path_matches_pattern(path, p.pattern):
                ignored = False
            continue
        if _path_matches_pattern(path, p.pattern):
            ignored = True
    return ignored


def _path_matches_pattern(path: str, pattern: str) -> bool:
    """Check if a path matches a gitignore pattern (simplified)."""
    pat = pattern.strip()
    if not pat:
        return False

    # Anchor patterns without slash to any directory level (git behavior).
    if "/" not in pat and not pat.startswith("**"):
        return fnmatch.fnmatch(Path(path).name, pat) or fnmatch.fnmatch(path, pat)

    if pat.endswith("/"):
        return path.startswith(pat) or path.startswith(pat[:-1] + "/")

    return fnmatch.fnmatch(path, pat) or fnmatch.fnmatch(Path(path).name, pat)


class GitignoreAnalyzer:
    """Audit .gitignore coverage and detect sensitive files not ignored.

    Recommends patterns based on detected project languages and flags
    sensitive files present in the repository without ignore rules.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._patterns: list[GitignorePattern] | None = None
        self._gaps: list[GitignoreGap] | None = None
        self._stats: GitignoreStats | None = None

    def patterns(self) -> list[GitignorePattern]:
        """Parse and return patterns from .gitignore (and nested .gitignore files)."""
        if self._patterns is not None:
            return self._patterns

        found: list[GitignorePattern] = []
        for gitignore in sorted(self.root.rglob(".gitignore")):
            rel = gitignore.relative_to(self.root)
            source = str(rel)
            try:
                lines = gitignore.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for lineno, raw in enumerate(lines, start=1):
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                negated = line.startswith("!")
                pattern = line[1:] if negated else line
                found.append(
                    GitignorePattern(
                        pattern=pattern,
                        source=source,
                        lineno=lineno,
                        negated=negated,
                    )
                )
        self._patterns = found
        return found

    def _recommended_patterns(self) -> list[tuple[str, str, str]]:
        """Build the list of recommended patterns for this project."""
        recs: list[tuple[str, str, str]] = list(UNIVERSAL_PATTERNS)
        profile = ProjectDetector().detect(self.root)
        for lang in profile.languages:
            recs.extend(LANGUAGE_PATTERNS.get(lang, ()))
        # Deduplicate while preserving order.
        seen: set[str] = set()
        unique: list[tuple[str, str, str]] = []
        for pattern, severity, message in recs:
            if pattern not in seen:
                seen.add(pattern)
                unique.append((pattern, severity, message))
        return unique

    def _pattern_covered(self, pattern: str, lines: list[str]) -> bool:
        return any(_pattern_matches_gitignore_line(pattern, line) for line in lines)

    def analyze(self) -> list[GitignoreGap]:
        """Find missing patterns and exposed sensitive files."""
        if self._gaps is not None:
            return self._gaps

        gaps: list[GitignoreGap] = []
        parsed = self.patterns()
        raw_lines = [p.pattern for p in parsed if not p.negated]
        has_gitignore = (self.root / ".gitignore").exists()

        if not has_gitignore:
            gaps.append(
                GitignoreGap(
                    kind="missing_file",
                    severity="high",
                    pattern=".gitignore",
                    message="no .gitignore file found in project root",
                )
            )

        recommended = self._recommended_patterns()
        covered = 0
        for pattern, severity, message in recommended:
            if self._pattern_covered(pattern, raw_lines):
                covered += 1
            else:
                gaps.append(
                    GitignoreGap(
                        kind="missing_pattern",
                        severity=severity,
                        pattern=pattern,
                        message=f"recommended pattern missing — {message}",
                    )
                )

        exposed = 0
        for filename, description in SENSITIVE_FILES:
            path = self.root / filename
            if path.is_file() and not _is_ignored(filename, parsed):
                exposed += 1
                gaps.append(
                    GitignoreGap(
                        kind="exposed_file",
                        severity="high",
                        pattern=filename,
                        message=f"sensitive file present but not ignored — {description}",
                        path=filename,
                    )
                )

        self._gaps = gaps
        self._stats = GitignoreStats(
            patterns=len(parsed),
            recommended=len(recommended),
            covered=covered,
            gaps=len(gaps),
            exposed_files=exposed,
            has_gitignore=has_gitignore,
        )
        return gaps

    @property
    def stats(self) -> GitignoreStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = fully covered, no exposure)."""
        self.analyze()
        stats = self.stats
        if not stats.has_gitignore:
            return 0.0
        if stats.recommended == 0:
            return 100.0
        coverage = stats.covered / stats.recommended
        score = coverage * 100.0
        high = sum(1 for g in self._gaps if g.severity == "high")
        medium = sum(1 for g in self._gaps if g.severity == "medium")
        low = sum(1 for g in self._gaps if g.severity == "low")
        penalty = high * 15.0 + medium * 5.0 + low * 1.0
        return round(max(0.0, min(100.0, score - penalty * 0.1)), 1)

    def generate_template(self) -> str:
        """Scaffold a .gitignore from recommended patterns."""
        self.analyze()
        lines = ["# Generated by DevAI GitignoreAnalyzer", ""]
        recommended = self._recommended_patterns()
        raw_lines = [p.pattern for p in self.patterns() if not p.negated]

        for pattern, _severity, message in recommended:
            if not self._pattern_covered(pattern, raw_lines):
                lines.append(f"# {message}")
                lines.append(pattern)
                lines.append("")
        return "\n".join(lines).rstrip() + "\n"

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        lines = [
            (
                f"Gitignore: {stats.patterns} pattern(s), "
                f"{stats.covered}/{stats.recommended} recommended covered, "
                f"{stats.gaps} gap(s)"
            ),
        ]
        if stats.exposed_files:
            lines.append(f"  exposed sensitive files: {stats.exposed_files}")
        high = [g for g in self._gaps if g.severity == "high"]
        if high:
            lines.append(f"  high severity: {len(high)}")
        return "\n".join(lines)

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Gitignore analysis:",
            f"  patterns: {stats.patterns}",
            f"  recommended covered: {stats.covered}/{stats.recommended}",
            f"  gaps: {stats.gaps}",
            f"  health score: {self.health_score()}/100",
        ]
        for gap in self._gaps[:20]:
            lines.append(f"  - {gap.format()}")
        if len(self._gaps) > 20:
            lines.append(f"  ... and {len(self._gaps) - 20} more")
        return "\n".join(lines)
