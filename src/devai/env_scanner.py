"""EnvVarScanner — find environment variable usage and .env alignment issues."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

ENV_CALL_PATTERNS = [
    re.compile(r"os\.environ\.get\s*\(\s*['\"]([^'\"]+)['\"]"),
    re.compile(r"os\.environ\s*\[\s*['\"]([^'\"]+)['\"]"),
    re.compile(r"os\.getenv\s*\(\s*['\"]([^'\"]+)['\"]"),
    re.compile(r"getenv\s*\(\s*['\"]([^'\"]+)['\"]"),
    re.compile(r"environ\.get\s*\(\s*['\"]([^'\"]+)['\"]"),
]

ENV_FILE_LINE = re.compile(
    r"^\s*(?:export\s+)?([A-Z][A-Z0-9_]*)\s*="
)


@dataclass
class EnvVarUsage:
    """A single environment variable reference in source code."""

    name: str
    path: str
    lineno: int
    source: str

    def format(self) -> str:
        """Return a single-line description."""
        return f"{self.path}:{self.lineno} {self.name} ({self.source})"


@dataclass
class EnvVarIssue:
    """An environment variable alignment issue."""

    name: str
    kind: str
    detail: str

    def format(self) -> str:
        """Return a single-line description."""
        return f"[{self.kind}] {self.name}: {self.detail}"


@dataclass
class EnvVarStats:
    """Aggregate environment variable statistics."""

    used_in_code: int
    declared_in_env: int
    missing_from_env: int
    unused_in_env: int
    issues: int


class EnvVarScanner:
    """Scan Python projects for environment variable usage and .env alignment.

    Detects ``os.environ``, ``os.getenv``, and Pydantic ``Field(env=...)`` usage,
    then compares against ``.env``, ``.env.example``, and ``.env.local`` files.
    """

    ENV_FILES = (".env", ".env.example", ".env.local", ".env.development")

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
        env_files: tuple[str, ...] | None = None,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self.env_files = env_files or self.ENV_FILES
        self._usages: list[EnvVarUsage] = []
        self._declared: set[str] = set()
        self._issues: list[EnvVarIssue] = []
        self._stats: EnvVarStats | None = None

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix.lower() != ".py"

    def _collect_python_files(self) -> list[Path]:
        return [
            p
            for p in sorted(self.root.rglob("*.py"))
            if p.is_file() and not self._should_skip(p)
        ]

    def _scan_regex(self, rel: str, source: str) -> list[EnvVarUsage]:
        usages: list[EnvVarUsage] = []
        for lineno, line in enumerate(source.splitlines(), start=1):
            for pattern in ENV_CALL_PATTERNS:
                for match in pattern.finditer(line):
                    usages.append(
                        EnvVarUsage(
                            name=match.group(1),
                            path=rel,
                            lineno=lineno,
                            source="os.environ/getenv",
                        )
                    )
        return usages

    def _scan_ast(self, rel: str, source: str) -> list[EnvVarUsage]:
        usages: list[EnvVarUsage] = []
        try:
            tree = ast.parse(source, filename=rel)
        except SyntaxError:
            return usages

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr == "Field":
                for kw in node.keywords:
                    if kw.arg == "env" and isinstance(kw.value, ast.Constant):
                        if isinstance(kw.value.value, str):
                            usages.append(
                                EnvVarUsage(
                                    name=kw.value.value,
                                    path=rel,
                                    lineno=node.lineno,
                                    source="pydantic.Field(env=)",
                                )
                            )
            elif isinstance(func, ast.Name) and func.id == "Field":
                for kw in node.keywords:
                    if kw.arg == "env" and isinstance(kw.value, ast.Constant):
                        if isinstance(kw.value.value, str):
                            usages.append(
                                EnvVarUsage(
                                    name=kw.value.value,
                                    path=rel,
                                    lineno=node.lineno,
                                    source="pydantic.Field(env=)",
                                )
                            )
        return usages

    def _scan_code(self) -> list[EnvVarUsage]:
        usages: list[EnvVarUsage] = []
        for path in self._collect_python_files():
            rel = str(path.relative_to(self.root))
            try:
                source = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            usages.extend(self._scan_regex(rel, source))
            usages.extend(self._scan_ast(rel, source))
        return usages

    def _load_env_files(self) -> set[str]:
        declared: set[str] = set()
        for name in self.env_files:
            env_path = self.root / name
            if not env_path.is_file():
                continue
            try:
                text = env_path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            for lineno, line in enumerate(text.splitlines(), start=1):
                if line.strip().startswith("#"):
                    continue
                match = ENV_FILE_LINE.match(line)
                if match:
                    declared.add(match.group(1))
        return declared

    def _build_issues(
        self, used_names: set[str], declared: set[str]
    ) -> list[EnvVarIssue]:
        issues: list[EnvVarIssue] = []
        for name in sorted(used_names - declared):
            issues.append(
                EnvVarIssue(
                    name=name,
                    kind="missing_from_env",
                    detail="Used in code but not declared in .env files",
                )
            )
        for name in sorted(declared - used_names):
            issues.append(
                EnvVarIssue(
                    name=name,
                    kind="unused_in_code",
                    detail="Declared in .env but not referenced in Python code",
                )
            )
        return issues

    def scan(self) -> list[EnvVarIssue]:
        """Scan the project and return environment variable alignment issues."""
        if self._issues:
            return self._issues

        self._usages = self._scan_code()
        self._declared = self._load_env_files()
        used_names = {u.name for u in self._usages}
        self._issues = self._build_issues(used_names, self._declared)

        missing = sum(1 for i in self._issues if i.kind == "missing_from_env")
        unused = sum(1 for i in self._issues if i.kind == "unused_in_code")
        self._stats = EnvVarStats(
            used_in_code=len(used_names),
            declared_in_env=len(self._declared),
            missing_from_env=missing,
            unused_in_env=unused,
            issues=len(self._issues),
        )
        return self._issues

    @property
    def usages(self) -> list[EnvVarUsage]:
        """Return all environment variable usages found in code."""
        if not self._usages:
            self.scan()
        return self._usages

    @property
    def declared(self) -> set[str]:
        """Return environment variables declared in .env files."""
        if not self._declared and not self._issues:
            self.scan()
        return self._declared

    @property
    def stats(self) -> EnvVarStats:
        """Return aggregate environment variable statistics."""
        if self._stats is None:
            self.scan()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = perfect env alignment)."""
        self.scan()
        if not self._usages and not self._declared:
            return 100.0
        missing = sum(1 for i in self._issues if i.kind == "missing_from_env")
        if missing == 0:
            return 100.0
        used = len({u.name for u in self._usages}) or 1
        penalty = min(100.0, (missing / used) * 100.0)
        return round(max(0.0, 100.0 - penalty), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.scan()
        stats = self.stats
        lines = [
            f"Env vars: {stats.used_in_code} used in code, "
            f"{stats.declared_in_env} declared in .env",
            f"Issues: {stats.missing_from_env} missing, {stats.unused_in_env} unused",
            f"Health score: {self.health_score()}/100",
        ]
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing env var alignment."""
        self.scan()
        lines = [
            "Environment variable analysis:",
            self.summary(),
            "",
            "Issues:",
        ]
        if not self._issues:
            lines.append("No env var alignment issues found.")
        else:
            for issue in self._issues[:limit]:
                lines.append(f"  - {issue.format()}")
            if len(self._issues) > limit:
                lines.append(f"... and {len(self._issues) - limit} more")
        return "\n".join(lines)
