"""JWTSecurityAnalyzer — detect insecure JWT handling patterns."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_JWT_MODULES = frozenset({"jwt", "jose", "jose_jwt", "authlib"})

_JWT_DECODE_FUNCS = frozenset({"decode", "decode_complete"})


@dataclass
class JWTSecurityFinding:
    """An insecure JWT handling pattern."""

    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    call: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        call = f" ({self.call})" if self.call else ""
        return (
            f"{self.path}:{self.lineno}{call} [{self.severity}] {self.pattern}: "
            f"{self.message}"
        )


@dataclass
class JWTSecurityStats:
    """Aggregate JWT security statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _call_name(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _module_name(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return func.value.id
    return None


def _kw_bool(node: ast.keyword) -> bool | None:
    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, bool):
        return node.value.value
    return None


def _kw_string(node: ast.keyword) -> str | None:
    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
        return node.value.value
    return None


def _kw_list_strings(node: ast.keyword) -> list[str]:
    if not isinstance(node.value, ast.List):
        return []
    result: list[str] = []
    for elt in node.value.elts:
        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
            result.append(elt.value)
    return result


class _JWTSecurityVisitor(ast.NodeVisitor):
    """Walk a module AST and collect JWT security risks."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[JWTSecurityFinding] = []

    def _add(
        self,
        node: ast.AST,
        pattern: str,
        *,
        severity: str,
        message: str,
        call: str = "",
    ) -> None:
        self.findings.append(
            JWTSecurityFinding(
                path=self.path,
                lineno=getattr(node, "lineno", 0),
                pattern=pattern,
                severity=severity,
                message=message,
                call=call,
            )
        )

    def visit_Call(self, node: ast.Call) -> None:
        name = _call_name(node)
        module = _module_name(node)

        if name in _JWT_DECODE_FUNCS and module in _JWT_MODULES:
            call_label = f"{module}.{name}"
            verify_disabled = False
            algorithms_none = False
            missing_algorithms = True

            for kw in node.keywords:
                if kw.arg == "verify" and _kw_bool(kw) is False:
                    verify_disabled = True
                if kw.arg == "options" and isinstance(kw.value, ast.Dict):
                    for key, val in zip(kw.value.keys, kw.value.values):
                        if (
                            isinstance(key, ast.Constant)
                            and key.value == "verify_signature"
                            and isinstance(val, ast.Constant)
                            and val.value is False
                        ):
                            verify_disabled = True
                if kw.arg == "algorithms":
                    missing_algorithms = False
                    algs = _kw_list_strings(kw)
                    if "none" in algs or "None" in algs:
                        algorithms_none = True
                if kw.arg == "algorithm":
                    alg = _kw_string(kw)
                    if alg and alg.lower() == "none":
                        algorithms_none = True

            if verify_disabled:
                self._add(
                    node,
                    "jwt_verify_disabled",
                    severity="high",
                    message="JWT signature verification is disabled — tokens can be forged",
                    call=call_label,
                )
            if algorithms_none:
                self._add(
                    node,
                    "jwt_algorithm_none",
                    severity="high",
                    message='JWT algorithm "none" allows unsigned tokens',
                    call=call_label,
                )
            if missing_algorithms and not verify_disabled:
                self._add(
                    node,
                    "jwt_missing_algorithms",
                    severity="medium",
                    message="Specify algorithms= explicitly to prevent algorithm confusion attacks",
                    call=call_label,
                )

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Name) and re.search(
                r"(jwt|token).*secret", target.id, re.IGNORECASE
            ):
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    self._add(
                        node,
                        "hardcoded_jwt_secret",
                        severity="high",
                        message="Hardcoded JWT secret — use environment variables",
                        call=target.id,
                    )
        self.generic_visit(node)


class JWTSecurityAnalyzer:
    """Detect insecure JWT decode and configuration patterns.

    Flags disabled signature verification, algorithm-none attacks,
    missing algorithm allowlists, and hardcoded JWT secrets.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[JWTSecurityFinding] = []
        self._stats: JWTSecurityStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def analyze(self) -> list[JWTSecurityFinding]:
        """Analyze the project and return JWT security findings."""
        if self._findings:
            return self._findings

        findings: list[JWTSecurityFinding] = []
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
            visitor = _JWTSecurityVisitor(rel)
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

        density = round(100.0 * len(findings) / files_scanned, 1) if files_scanned else 0.0
        self._stats = JWTSecurityStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> JWTSecurityStats:
        """Return aggregate JWT security statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def high_severity(self) -> list[JWTSecurityFinding]:
        """Return only high-severity findings."""
        return [f for f in self.analyze() if f.severity == "high"]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no JWT security issues)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = high * 25.0 + medium * 10.0
        return round(max(0.0, 100.0 - penalty / self._files_scanned), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        high = stats.by_severity.get("high", 0)
        lines = [
            f"JWT security risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"High severity: {high}",
            f"Health score: {self.health_score()}/100",
        ]
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing JWT security findings."""
        self.analyze()
        lines = ["JWT security analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No JWT security issues found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
