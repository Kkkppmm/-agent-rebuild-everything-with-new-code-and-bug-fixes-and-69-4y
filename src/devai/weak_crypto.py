"""WeakCryptoAnalyzer — detect use of weak cryptographic algorithms."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_WEAK_HASH_ATTRS = frozenset({"md5", "sha1", "sha", "new"})
_WEAK_CIPHER_ATTRS = frozenset({"DES", "DES3", "RC4", "Blowfish"})
_WEAK_HASH_NAMES = frozenset({"md5", "sha1"})
_HASHLIB_MODULE = "hashlib"
_CRYPTO_MODULE = "Crypto"

_SENSITIVE_RE = re.compile(
    r"(password|passwd|token|secret|credential|auth|sign|verify|hash|digest|checksum|"
    r"encrypt|decrypt|cipher|key|signature|hmac)",
    re.IGNORECASE,
)


@dataclass
class WeakCryptoFinding:
    """A potentially weak cryptographic algorithm usage."""

    path: str
    lineno: int
    algorithm: str
    severity: str
    message: str
    context: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        ctx = f" ({self.context})" if self.context else ""
        return (
            f"{self.path}:{self.lineno} [{self.severity}] {self.algorithm}{ctx}: "
            f"{self.message}"
        )


@dataclass
class WeakCryptoStats:
    """Aggregate weak-crypto analysis statistics."""

    total_findings: int
    by_algorithm: dict[str, int] = field(default_factory=dict)
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


def _weak_hash_call(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Attribute):
        if func.attr == "hexdigest" and isinstance(func.value, ast.Call):
            inner = _weak_hash_call(func.value)
            if inner:
                return inner
        if isinstance(func.value, ast.Name):
            if func.value.id == _HASHLIB_MODULE and func.attr in _WEAK_HASH_ATTRS:
                return f"hashlib.{func.attr}"
            if func.value.id == _HASHLIB_MODULE and func.attr == "new":
                for arg in node.args:
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        algo = arg.value.lower()
                        if algo in _WEAK_HASH_NAMES or algo.startswith("md5") or algo.startswith("sha1"):
                            return f"hashlib.new({algo})"
    if isinstance(func, ast.Name) and func.id in _WEAK_HASH_NAMES:
        return func.id
    return None


def _weak_cipher_call(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Attribute):
        if isinstance(func.value, ast.Name) and func.value.id in {"DES", "DES3", "RC4"}:
            return func.value.id
        if isinstance(func.value, ast.Attribute):
            mod = func.value
            if isinstance(mod.value, ast.Name) and mod.value.id == _CRYPTO_MODULE:
                if mod.attr == "Cipher" and func.attr == "new":
                    for arg in node.args:
                        if isinstance(arg, ast.Attribute) and isinstance(arg.value, ast.Name):
                            if arg.value.id in _WEAK_CIPHER_ATTRS:
                                return f"Cipher.new({arg.value.id})"
    return None


class _WeakCryptoVisitor(ast.NodeVisitor):
    """Walk a module AST and collect weak cryptographic algorithm usage."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[WeakCryptoFinding] = []

    def _add(
        self,
        node: ast.AST,
        algorithm: str,
        *,
        severity: str,
        message: str,
        context: str = "",
    ) -> None:
        self.findings.append(
            WeakCryptoFinding(
                path=self.path,
                lineno=getattr(node, "lineno", 0),
                algorithm=algorithm,
                severity=severity,
                message=message,
                context=context,
            )
        )

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.Call):
            algo = _weak_hash_call(node.value) or _weak_cipher_call(node.value)
            if algo:
                for target in node.targets:
                    for var_name in _assignment_target_names(target):
                        sev = "high" if _is_sensitive_name(var_name) else "medium"
                        self._add(
                            node,
                            algo,
                            severity=sev,
                            message="Weak algorithm for security-sensitive data — use SHA-256+ or bcrypt/argon2",
                            context=f"assigned to {var_name}",
                        )
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> None:
        if isinstance(node.value, ast.Call):
            algo = _weak_hash_call(node.value) or _weak_cipher_call(node.value)
            if algo:
                self._add(
                    node,
                    algo,
                    severity="medium",
                    message="Weak cryptographic algorithm — prefer SHA-256, bcrypt, or argon2",
                    context="return value",
                )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        algo = _weak_hash_call(node) or _weak_cipher_call(node)
        if algo:
            for kw in node.keywords:
                if kw.arg and _is_sensitive_name(kw.arg):
                    self._add(
                        node,
                        algo,
                        severity="high",
                        message="Weak algorithm for security-sensitive parameter",
                        context=f"kwarg={kw.arg}",
                    )
            if not any(kw.arg and _is_sensitive_name(kw.arg) for kw in node.keywords):
                self._add(
                    node,
                    algo,
                    severity="medium",
                    message="Weak cryptographic algorithm — prefer SHA-256, bcrypt, or argon2",
                )
        self.generic_visit(node)


class WeakCryptoAnalyzer:
    """Detect use of weak cryptographic algorithms (MD5, SHA1, DES, RC4).

    Flags ``hashlib.md5``, ``hashlib.sha1``, and weak cipher usage especially
    when assigned to security-sensitive variable names.
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

        by_algorithm: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for finding in findings:
            by_algorithm[finding.algorithm] = by_algorithm.get(finding.algorithm, 0) + 1
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

        density = 0.0
        if files_scanned:
            density = round(100.0 * len(findings) / files_scanned, 1)

        self._stats = WeakCryptoStats(
            total_findings=len(findings),
            by_algorithm=by_algorithm,
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
            lines.append("No weak cryptographic algorithms found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
