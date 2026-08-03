"""WeakCryptoAnalyzer — detect weak hashing and cipher usage."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_WEAK_HASH_ATTRS = frozenset({"md5", "sha1", "md4", "sha"})
_WEAK_CIPHER_ATTRS = frozenset({"DES", "RC4", "Blowfish"})
_WEAK_HASHLIB_FUNCS = frozenset({"md5", "sha1", "md4", "sha"})

_SECURITY_CONTEXT_RE = re.compile(
    r"(password|passwd|token|secret|auth|credential|session|sign|hash|digest|checksum|"
    r"encrypt|decrypt|cipher|key|salt|hmac|signature|verify)",
    re.IGNORECASE,
)


@dataclass
class WeakCryptoFinding:
    """A detected weak cryptographic primitive usage."""

    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    function: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        loc = f"{self.path}:{self.lineno}"
        fn = f" in {self.function}" if self.function else ""
        return f"{loc}{fn} [{self.severity}] {self.pattern}: {self.message}"


@dataclass
class WeakCryptoStats:
    """Aggregate weak-crypto analysis statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _call_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parts: list[str] = []
        current: ast.AST = func
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))
    return ""


def _in_security_context(function_stack: list[str]) -> bool:
    return any(_SECURITY_CONTEXT_RE.search(name) for name in function_stack)


class _WeakCryptoVisitor(ast.NodeVisitor):
    """Walk a module AST and collect weak crypto usage."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[WeakCryptoFinding] = []
        self._function_stack: list[str] = []

    def _current_function(self) -> str:
        return self._function_stack[-1] if self._function_stack else ""

    def _add(self, node: ast.AST, pattern: str, severity: str, message: str) -> None:
        self.findings.append(
            WeakCryptoFinding(
                path=self.path,
                lineno=getattr(node, "lineno", 0),
                pattern=pattern,
                severity=severity,
                message=message,
                function=self._current_function(),
            )
        )

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._function_stack.append(node.name)
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._function_stack.append(node.name)
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_Call(self, node: ast.Call) -> None:
        name = _call_name(node)
        short = name.split(".")[-1] if name else ""
        in_ctx = _in_security_context(self._function_stack)

        if short in _WEAK_HASHLIB_FUNCS and name.startswith("hashlib."):
            self._add(
                node,
                "weak_hashlib",
                "high" if in_ctx else "medium",
                f"hashlib.{short}() is cryptographically weak — use hashlib.sha256 or better",
            )
        elif short in _WEAK_HASH_ATTRS:
            if isinstance(node.func, ast.Attribute):
                parent = ""
                if isinstance(node.func.value, ast.Name):
                    parent = node.func.value.id
                if parent in {"hashlib", "Crypto", "cryptography"} or in_ctx:
                    self._add(
                        node,
                        "weak_hash",
                        "high" if in_ctx else "medium",
                        f"Weak hash algorithm {short} — prefer SHA-256, SHA-3, or bcrypt/argon2 for passwords",
                    )

        if short in _WEAK_CIPHER_ATTRS:
            self._add(
                node,
                "weak_cipher",
                "high",
                f"Weak cipher {short} — use AES-GCM or ChaCha20-Poly1305",
            )

        if short == "new" and isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "DES":
                self._add(
                    node,
                    "weak_cipher",
                    "high",
                    "DES cipher is broken — use AES-GCM",
                )

        self.generic_visit(node)


class WeakCryptoAnalyzer:
    """Detect use of weak cryptographic primitives.

    Flags MD5, SHA-1, DES, RC4, and similar algorithms especially in
  security-sensitive contexts like password hashing and token generation.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[WeakCryptoFinding] = []
        self._stats: WeakCryptoStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def analyze(self) -> list[WeakCryptoFinding]:
        """Analyze the project and return weak-crypto findings."""
        if self._findings:
            return self._findings

        findings: list[WeakCryptoFinding] = []
        files_scanned = 0
        files_with_findings: set[str] = set()

        for path in sorted(self.root.rglob("*.py")):
            if not path.is_file() or self._should_skip(path):
                continue
            try:
                source = path.read_text(encoding="utf-8")
                tree = ast.parse(source, filename=str(path))
            except (OSError, UnicodeDecodeError, SyntaxError):
                continue

            files_scanned += 1
            rel = str(path.relative_to(self.root))
            visitor = _WeakCryptoVisitor(rel)
            visitor.visit(tree)
            if visitor.findings:
                files_with_findings.add(rel)
            findings.extend(visitor.findings)

        self._findings = findings
        self._files_scanned = files_scanned

        by_pattern: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for finding in findings:
            by_pattern[finding.pattern] = by_pattern.get(finding.pattern, 0) + 1
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

        density = 0.0
        if files_scanned:
            density = round(100.0 * len(findings) / files_scanned, 1)

        self._stats = WeakCryptoStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> WeakCryptoStats:
        """Return aggregate weak-crypto statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def by_pattern(self, pattern: str) -> list[WeakCryptoFinding]:
        """Return findings for a specific pattern."""
        return [f for f in self.analyze() if f.pattern == pattern]

    def high_severity(self) -> list[WeakCryptoFinding]:
        """Return only high-severity findings."""
        return [f for f in self.analyze() if f.severity == "high"]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no weak crypto usage)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = high * 20.0 + medium * 8.0
        ratio = penalty / self._files_scanned
        return round(max(0.0, 100.0 - ratio), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        high = stats.by_severity.get("high", 0)
        lines = [
            f"Weak crypto: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"High severity: {high}",
            f"Health score: {self.health_score()}/100",
        ]
        if stats.by_pattern:
            patterns = ", ".join(f"{k}={v}" for k, v in sorted(stats.by_pattern.items()))
            lines.append(f"By pattern: {patterns}")
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing weak-crypto findings."""
        self.analyze()
        lines = [
            "Weak crypto analysis:",
            self.summary(),
            "",
            "Findings:",
        ]
        if not self._findings:
            lines.append("No weak cryptographic usage found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
