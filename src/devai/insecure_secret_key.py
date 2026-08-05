"""InsecureSecretKeyAnalyzer — detect weak or default application secret keys."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_SECRET_SETTING_NAMES = frozenset(
    {
        "SECRET_KEY",
        "SECRET",
        "APP_SECRET",
        "APP_SECRET_KEY",
        "JWT_SECRET",
        "JWT_SECRET_KEY",
        "ENCRYPTION_KEY",
        "SIGNING_KEY",
        "FLASK_SECRET_KEY",
        "SESSION_SECRET",
        "AUTH_SECRET",
        "API_SECRET",
        "CRYPTO_KEY",
        "HMAC_SECRET",
    }
)

_WEAK_VALUE_RE = re.compile(
    r"(?i)^(changeme|secret|password|test|dev|debug|admin|12345|"
    r"your[_-]?secret|replace[_-]?me|insert[_-]?key|todo|"
    r"django-insecure-|flask-secret|supersecret|mysecret|"
    r"not[_-]?a[_-]?real[_-]?secret|example|sample|dummy|fake)$"
)

_MIN_SECRET_LENGTH = 20


@dataclass
class InsecureSecretKeyFinding:
    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    setting: str = ""
    function: str = ""

    def format(self) -> str:
        loc = f"{self.path}:{self.lineno}"
        fn = f" in {self.function}" if self.function else ""
        setting = f" ({self.setting})" if self.setting else ""
        return f"{loc}{fn} [{self.severity}] {self.pattern}{setting}: {self.message}"


@dataclass
class InsecureSecretKeyStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _setting_name(target: ast.AST) -> str | None:
    if isinstance(target, ast.Name) and target.id in _SECRET_SETTING_NAMES:
        return target.id
    if isinstance(target, ast.Attribute) and target.attr in _SECRET_SETTING_NAMES:
        return target.attr
    return None


def _string_value(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _is_weak_secret(value: str) -> tuple[str, str] | None:
    if _WEAK_VALUE_RE.match(value):
        return ("weak_secret_value", "high", "Hardcoded secret key uses a known weak or placeholder value")
    if value.lower().startswith("django-insecure-"):
        return ("weak_secret_value", "high", "Django development SECRET_KEY prefix detected — rotate before production")
    if len(value) < _MIN_SECRET_LENGTH:
        return ("short_secret_key", "high", f"Secret key is too short ({len(value)} chars) — use at least {_MIN_SECRET_LENGTH}")
    return None


def _is_environ_setdefault(node: ast.Call) -> tuple[str, ast.AST] | None:
    func = node.func
    if not isinstance(func, ast.Attribute) or func.attr != "setdefault":
        return None
    base = func.value
    if isinstance(base, ast.Attribute) and base.attr == "environ":
        if not (isinstance(base.value, ast.Name) and base.value.id == "os"):
            return None
    elif isinstance(base, ast.Name) and base.id == "environ":
        pass
    else:
        return None
    if (
        len(node.args) >= 2
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
        and node.args[0].value in _SECRET_SETTING_NAMES
    ):
        return node.args[0].value, node.args[1]
    return None


class _InsecureSecretKeyVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[InsecureSecretKeyFinding] = []
        self._function_stack: list[str] = []

    def _current_function(self) -> str:
        return self._function_stack[-1] if self._function_stack else ""

    def _add_finding(
        self,
        node: ast.AST,
        *,
        pattern: str,
        severity: str,
        message: str,
        setting: str = "",
    ) -> None:
        self.findings.append(
            InsecureSecretKeyFinding(
                path=self.path,
                lineno=getattr(node, "lineno", 1),
                pattern=pattern,
                severity=severity,
                message=message,
                setting=setting,
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

    def visit_Assign(self, node: ast.Assign) -> None:
        value = _string_value(node.value)
        if value is not None:
            for target in node.targets:
                name = _setting_name(target)
                if name is None:
                    continue
                weak = _is_weak_secret(value)
                if weak:
                    pattern, severity, message = weak
                    self._add_finding(
                        node,
                        pattern=pattern,
                        severity=severity,
                        message=message,
                        setting=name,
                    )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        env_default = _is_environ_setdefault(node)
        if env_default:
            setting, value_node = env_default
            value = _string_value(value_node)
            if value is not None:
                weak = _is_weak_secret(value)
                if weak:
                    pattern, severity, message = weak
                    self._add_finding(
                        node,
                        pattern=pattern,
                        severity=severity,
                        message=f"{message} (os.environ.setdefault default)",
                        setting=setting,
                    )
        self.generic_visit(node)


class InsecureSecretKeyAnalyzer:
    """Detect weak or default SECRET_KEY and related signing key values."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[InsecureSecretKeyFinding] = []
        self._stats: InsecureSecretKeyStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _scan_source(self, rel: str, source: str) -> list[InsecureSecretKeyFinding]:
        findings: list[InsecureSecretKeyFinding] = []
        try:
            tree = ast.parse(source, filename=rel)
        except SyntaxError:
            return findings

        visitor = _InsecureSecretKeyVisitor(rel)
        visitor.visit(tree)
        findings.extend(visitor.findings)
        return findings

    def analyze(self) -> list[InsecureSecretKeyFinding]:
        if self._findings:
            return self._findings

        findings: list[InsecureSecretKeyFinding] = []
        files_scanned = 0
        files_with_findings: set[str] = set()

        for path in sorted(self.root.rglob("*.py")):
            if not path.is_file() or self._should_skip(path):
                continue
            try:
                source = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue

            files_scanned += 1
            rel = str(path.relative_to(self.root))
            file_findings = self._scan_source(rel, source)
            if file_findings:
                files_with_findings.add(rel)
            findings.extend(file_findings)

        self._findings = findings
        self._files_scanned = files_scanned
        by_pattern: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for finding in findings:
            by_pattern[finding.pattern] = by_pattern.get(finding.pattern, 0) + 1
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

        density = round(100.0 * len(findings) / files_scanned, 1) if files_scanned else 0.0
        self._stats = InsecureSecretKeyStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> InsecureSecretKeyStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        penalty = high * 30.0
        return round(max(0.0, 100.0 - penalty / self._files_scanned), 1)

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        return (
            f"Insecure secret keys: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Insecure secret key analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No weak or default secret keys found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
