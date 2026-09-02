"""WeakCryptoAnalyzer — detect use of weak cryptographic algorithms."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_SENSITIVE_RE = re.compile(
    r"(password|passwd|secret|token|credential|auth|sign|hash|digest|checksum|signature)",
    re.IGNORECASE,
)

_WEAK_HASH_ATTRS = frozenset({"md5", "sha1", "md4", "md2"})
_WEAK_CIPHER_ATTRS = frozenset({"DES", "RC4", "Blowfish"})


@dataclass
class WeakCryptoFinding:
    """A detected use of a weak cryptographic algorithm."""

    path: str
    lineno: int
    name: str
    severity: str
    message: str
    context: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        ctx = f" ({self.context})" if self.context else ""
        return (
            f"{self.path}:{self.lineno} [{self.severity}] {self.name}{ctx}: "
            f"{self.message}"
        )


@dataclass
class WeakCryptoStats:
    """Aggregate weak-crypto analysis statistics."""

    total_findings: int
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _is_sensitive_name(name: str) -> bool:
    return bool(_SENSITIVE_RE.search(name))


def _assignment_target_names(node: ast.AST) -> list[str]:
    names: list[str] = []
    if isinstance(node, ast.Name):
        names.append(node.id)
    elif isinstance(node, ast.Tuple):
        for elt in node.elts:
            names.extend(_assignment_target_names(elt))
    return names


def _hashlib_call(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        if func.value.id == "hashlib" and func.attr in _WEAK_HASH_ATTRS:
            return f"hashlib.{func.attr}"
    return None


class _WeakCryptoVisitor(ast.NodeVisitor):
    """Walk a module AST and collect weak crypto usage."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[WeakCryptoFinding] = []

    def _add(
        self,
        node: ast.AST,
        name: str,
        *,
        severity: str,
        message: str,
        context: str = "",
    ) -> None:
        self.findings.append(
            WeakCryptoFinding(
                path=self.path,
                lineno=getattr(node, "lineno", 0),
                name=name,
                severity=severity,
                message=message,
                context=context,
            )
        )

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.Call):
            call_name = _hashlib_call(node.value)
            if call_name:
                for target in node.targets:
                    for var_name in _assignment_target_names(target):
                        if _is_sensitive_name(var_name):
                            self._add(
                                node,
                                call_name,
                                severity="high",
                                message="Weak hash for security-sensitive data — use bcrypt, scrypt, or argon2",
                                context=f"assigned to {var_name}",
                            )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        call_name = _hashlib_call(node)
        if call_name:
            severity = "high" if call_name.endswith(("md5", "sha1")) else "medium"
            self._add(
                node,
                call_name,
                severity=severity,
                message="Weak hash algorithm — prefer SHA-256+ or a password hashing function",
            )

        func = node.func
        if isinstance(func, ast.Attribute):
            if func.attr in _WEAK_CIPHER_ATTRS:
                self._add(
                    node,
                    func.attr,
                    severity="high",
                    message="Weak cipher — use AES-GCM or ChaCha20-Poly1305",
                )
            if func.attr == "new" and isinstance(func.value, ast.Attribute):
                mod = func.value
                if isinstance(mod.value, ast.Name) and mod.value.id == "Crypto":
                    algo = mod.attr
                    if algo in _WEAK_HASH_ATTRS or algo in _WEAK_CIPHER_ATTRS:
                        self._add(
                            node,
                            f"Crypto.{algo}",
                            severity="high",
                            message="Weak PyCrypto algorithm for security use",
                        )

        for kw in node.keywords:
            if kw.arg and _is_sensitive_name(kw.arg) and isinstance(kw.value, ast.Call):
                inner = _hashlib_call(kw.value)
                if inner:
                    self._add(
                        node,
                        inner,
                        severity="high",
                        message="Weak hash passed to security-sensitive parameter",
                        context=f"kwarg={kw.arg}",
                    )
        self.generic_visit(node)


class WeakCryptoAnalyzer:
    """Detect use of weak cryptographic algorithms in Python code.

    Flags ``hashlib.md5``, ``hashlib.sha1``, and weak ciphers when used for
    passwords, tokens, or other security-sensitive operations.
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

        by_severity: dict[str, int] = {}
        for finding in findings:
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

        density = 0.0
        if files_scanned:
            density = round(100.0 * len(findings) / files_scanned, 1)

        self._stats = WeakCryptoStats(
            total_findings=len(findings),
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
        penalty = high * 25.0 + medium * 10.0
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
            lines.append("No weak crypto usage found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
