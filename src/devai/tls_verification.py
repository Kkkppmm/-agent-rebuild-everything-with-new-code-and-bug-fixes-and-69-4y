"""TLSVerificationAnalyzer — detect disabled SSL/TLS certificate verification."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_HTTP_CLIENT_ATTRS = frozenset({"get", "post", "put", "patch", "delete", "head", "request"})
_HTTP_MODULES = frozenset({"requests", "httpx", "aiohttp", "urllib3"})
_LINE_PATTERNS = (
    re.compile(r"verify\s*=\s*False"),
    re.compile(r"ssl\._create_unverified_context\s*\("),
    re.compile(r"ssl\.CERT_NONE"),
    re.compile(r"check_hostname\s*=\s*False"),
)


@dataclass
class TLSVerificationFinding:
    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    function: str = ""

    def format(self) -> str:
        loc = f"{self.path}:{self.lineno}"
        fn = f" in {self.function}" if self.function else ""
        return f"{loc}{fn} [{self.severity}] {self.pattern}: {self.message}"


@dataclass
class TLSVerificationStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


class _TLSVerificationVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[TLSVerificationFinding] = []
        self._function_stack: list[str] = []

    def _current_function(self) -> str:
        return self._function_stack[-1] if self._function_stack else ""

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._function_stack.append(node.name)
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._function_stack.append(node.name)
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Attribute) and target.attr == "verify":
                if isinstance(node.value, ast.Constant) and node.value.value is False:
                    self.findings.append(
                        TLSVerificationFinding(
                            path=self.path,
                            lineno=node.lineno,
                            pattern="session_verify_disabled",
                            severity="high",
                            message="Session.verify = False disables TLS certificate validation",
                            function=self._current_function(),
                        )
                    )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        for kw in node.keywords:
            if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                self.findings.append(
                    TLSVerificationFinding(
                        path=self.path,
                        lineno=node.lineno,
                        pattern="verify_false",
                        severity="high",
                        message="verify=False disables TLS certificate validation — use a proper CA bundle",
                        function=self._current_function(),
                    )
                )
            if kw.arg == "check_hostname" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                self.findings.append(
                    TLSVerificationFinding(
                        path=self.path,
                        lineno=node.lineno,
                        pattern="check_hostname_false",
                        severity="high",
                        message="check_hostname=False allows MITM attacks on TLS connections",
                        function=self._current_function(),
                    )
                )

        func = node.func
        if isinstance(func, ast.Attribute):
            if func.attr == "_create_unverified_context":
                self.findings.append(
                    TLSVerificationFinding(
                        path=self.path,
                        lineno=node.lineno,
                        pattern="unverified_ssl_context",
                        severity="high",
                        message="ssl._create_unverified_context() bypasses certificate validation",
                        function=self._current_function(),
                    )
                )
            if func.attr in _HTTP_CLIENT_ATTRS:
                base = func.value
                if isinstance(base, ast.Name) and base.id in _HTTP_MODULES:
                    for kw in node.keywords:
                        if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                            self.findings.append(
                                TLSVerificationFinding(
                                    path=self.path,
                                    lineno=node.lineno,
                                    pattern="http_client_verify_false",
                                    severity="high",
                                    message=f"{base.id}.{func.attr}(verify=False) disables TLS verification",
                                    function=self._current_function(),
                                )
                            )
        self.generic_visit(node)


class TLSVerificationAnalyzer:
    """Detect disabled SSL/TLS certificate verification in HTTP clients."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[TLSVerificationFinding] = []
        self._stats: TLSVerificationStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _scan_line_patterns(self, rel: str, source: str) -> list[TLSVerificationFinding]:
        findings: list[TLSVerificationFinding] = []
        for lineno, line in enumerate(source.splitlines(), start=1):
            for pattern in _LINE_PATTERNS:
                if pattern.search(line):
                    name = pattern.pattern
                    if "verify" in name:
                        ptype, msg = (
                            "verify_false",
                            "verify=False disables TLS certificate validation",
                        )
                    elif "unverified_context" in name:
                        ptype, msg = (
                            "unverified_ssl_context",
                            "ssl._create_unverified_context() bypasses certificate validation",
                        )
                    elif "CERT_NONE" in name:
                        ptype, msg = (
                            "ssl_cert_none",
                            "ssl.CERT_NONE disables certificate verification",
                        )
                    else:
                        ptype, msg = (
                            "check_hostname_false",
                            "check_hostname=False allows MITM attacks on TLS connections",
                        )
                    findings.append(
                        TLSVerificationFinding(
                            path=rel,
                            lineno=lineno,
                            pattern=ptype,
                            severity="high",
                            message=msg,
                        )
                    )
                    break
        return findings

    def analyze(self) -> list[TLSVerificationFinding]:
        if self._findings:
            return self._findings

        findings: list[TLSVerificationFinding] = []
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
            visitor = _TLSVerificationVisitor(rel)
            visitor.visit(tree)
            line_findings = self._scan_line_patterns(rel, source)
            all_findings = visitor.findings + line_findings
            if all_findings:
                files_with_findings.add(rel)
            findings.extend(all_findings)

        self._findings = findings
        self._files_scanned = files_scanned
        by_pattern: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for finding in findings:
            by_pattern[finding.pattern] = by_pattern.get(finding.pattern, 0) + 1
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

        density = round(100.0 * len(findings) / files_scanned, 1) if files_scanned else 0.0
        self._stats = TLSVerificationStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> TLSVerificationStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        penalty = high * 15.0
        return round(max(0.0, 100.0 - penalty / self._files_scanned), 1)

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        return (
            f"TLS verification risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["TLS verification analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No disabled TLS verification patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
