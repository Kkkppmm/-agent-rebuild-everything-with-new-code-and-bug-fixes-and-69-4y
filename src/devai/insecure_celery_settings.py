"""InsecureCelerySettingsAnalyzer — detect insecure Celery task queue configuration."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_PROD_FILENAMES = frozenset(
    {
        "settings.py",
        "production.py",
        "prod.py",
        "config.py",
        "celery.py",
        "celeryconfig.py",
    }
)
_CELERY_SETTING_NAMES = frozenset(
    {
        "CELERY_BROKER_URL",
        "CELERY_RESULT_BACKEND",
        "CELERY_TASK_ALWAYS_EAGER",
        "CELERY_TASK_SERIALIZER",
        "CELERY_RESULT_SERIALIZER",
        "CELERY_ACCEPT_CONTENT",
        "broker_url",
        "result_backend",
        "task_always_eager",
        "task_serializer",
        "result_serializer",
        "accept_content",
    }
)
_PICKLE_RE = re.compile(r"['\"]pickle['\"]", re.IGNORECASE)
_REDIS_NO_AUTH_RE = re.compile(
    r"redis://(?!.*:.*@)[^\s\"']+",
    re.IGNORECASE,
)
_GUEST_AMQP_RE = re.compile(
    r"amqp://guest:guest@|amqps://guest:guest@",
    re.IGNORECASE,
)
_TASK_ALWAYS_EAGER_RE = re.compile(
    r"(CELERY_TASK_ALWAYS_EAGER|task_always_eager)\s*=\s*True",
    re.IGNORECASE,
)


@dataclass
class InsecureCelerySettingsFinding:
    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    setting: str = ""

    def format(self) -> str:
        setting = f" ({self.setting})" if self.setting else ""
        return f"{self.path}:{self.lineno}{setting} [{self.severity}] {self.pattern}: {self.message}"


@dataclass
class InsecureCelerySettingsStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _dict_string_value(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _bool_value(node: ast.AST) -> bool | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, bool):
        return node.value
    return None


def _list_string_values(node: ast.AST) -> list[str]:
    if not isinstance(node, ast.List):
        return []
    values: list[str] = []
    for elt in node.elts:
        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
            values.append(elt.value)
    return values


def _redis_has_no_auth(value: str) -> bool:
    if "redis://" not in value.lower():
        return False
    return bool(_REDIS_NO_AUTH_RE.search(value))


def _contains_pickle(values: list[str]) -> bool:
    return any(value.lower() == "pickle" for value in values)


class _InsecureCelerySettingsVisitor(ast.NodeVisitor):
    def __init__(self, path: str, filename: str) -> None:
        self.path = path
        self.filename = filename
        self.findings: list[InsecureCelerySettingsFinding] = []

    def _add(
        self,
        lineno: int,
        pattern: str,
        severity: str,
        message: str,
        setting: str = "",
    ) -> None:
        self.findings.append(
            InsecureCelerySettingsFinding(
                path=self.path,
                lineno=lineno,
                pattern=pattern,
                severity=severity,
                message=message,
                setting=setting,
            )
        )

    def visit_Assign(self, node: ast.Assign) -> None:
        if self.filename not in _PROD_FILENAMES:
            self.generic_visit(node)
            return

        for target in node.targets:
            if isinstance(target, ast.Name) and target.id in _CELERY_SETTING_NAMES:
                self._check_setting(target.id, node.value, node.lineno)
        self.generic_visit(node)

    def _check_setting(self, name: str, value_node: ast.AST, lineno: int) -> None:
        if name in {"CELERY_TASK_ALWAYS_EAGER", "task_always_eager"}:
            eager = _bool_value(value_node)
            if eager is True:
                self._add(
                    lineno,
                    "task_always_eager_in_production",
                    "high",
                    "task_always_eager runs tasks synchronously — disable in production",
                    setting=name,
                )
            return

        if name in {"CELERY_TASK_SERIALIZER", "task_serializer"}:
            serializer = _dict_string_value(value_node)
            if serializer and serializer.lower() == "pickle":
                self._add(
                    lineno,
                    "pickle_task_serializer",
                    "critical",
                    "Pickle task serializer enables remote code execution — use json",
                    setting=name,
                )
            return

        if name in {"CELERY_RESULT_SERIALIZER", "result_serializer"}:
            serializer = _dict_string_value(value_node)
            if serializer and serializer.lower() == "pickle":
                self._add(
                    lineno,
                    "pickle_result_serializer",
                    "critical",
                    "Pickle result serializer enables remote code execution — use json",
                    setting=name,
                )
            return

        if name in {"CELERY_ACCEPT_CONTENT", "accept_content"}:
            accepted = _list_string_values(value_node)
            if _contains_pickle(accepted):
                self._add(
                    lineno,
                    "pickle_accept_content",
                    "critical",
                    "accept_content includes pickle — remove pickle to prevent deserialization attacks",
                    setting=name,
                )
            return

        if name in {"CELERY_BROKER_URL", "broker_url", "CELERY_RESULT_BACKEND", "result_backend"}:
            url = _dict_string_value(value_node)
            if not url:
                return
            if _redis_has_no_auth(url):
                self._add(
                    lineno,
                    "redis_broker_no_password",
                    "high",
                    "Redis broker/backend URL has no password — require authentication",
                    setting=name,
                )
            if _GUEST_AMQP_RE.search(url):
                self._add(
                    lineno,
                    "default_amqp_credentials",
                    "high",
                    "Broker uses default guest:guest credentials — use dedicated credentials",
                    setting=name,
                )


class InsecureCelerySettingsAnalyzer:
    """Detect insecure Celery configuration in Django and standalone apps."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[InsecureCelerySettingsFinding] = []
        self._stats: InsecureCelerySettingsStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _scan_source(
        self, rel: str, source: str, filename: str
    ) -> list[InsecureCelerySettingsFinding]:
        findings: list[InsecureCelerySettingsFinding] = []
        try:
            tree = ast.parse(source, filename=rel)
            visitor = _InsecureCelerySettingsVisitor(rel, filename)
            visitor.visit(tree)
            findings.extend(visitor.findings)
        except SyntaxError:
            pass

        if filename not in _PROD_FILENAMES:
            return findings

        for lineno, line in enumerate(source.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if _TASK_ALWAYS_EAGER_RE.search(line):
                findings.append(
                    InsecureCelerySettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="task_always_eager_in_production",
                        severity="high",
                        message="task_always_eager runs tasks synchronously — disable in production",
                        setting="task_always_eager",
                    )
                )
            if _PICKLE_RE.search(line) and any(
                token in line
                for token in (
                    "task_serializer",
                    "result_serializer",
                    "accept_content",
                    "CELERY_TASK_SERIALIZER",
                    "CELERY_RESULT_SERIALIZER",
                    "CELERY_ACCEPT_CONTENT",
                )
            ):
                pattern = "pickle_accept_content"
                if "task_serializer" in line or "CELERY_TASK_SERIALIZER" in line:
                    pattern = "pickle_task_serializer"
                elif "result_serializer" in line or "CELERY_RESULT_SERIALIZER" in line:
                    pattern = "pickle_result_serializer"
                findings.append(
                    InsecureCelerySettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern=pattern,
                        severity="critical",
                        message="Pickle serialization enables remote code execution — use json",
                        setting="serializer",
                    )
                )
            if _REDIS_NO_AUTH_RE.search(line) and any(
                token in line
                for token in (
                    "broker_url",
                    "result_backend",
                    "CELERY_BROKER_URL",
                    "CELERY_RESULT_BACKEND",
                )
            ):
                findings.append(
                    InsecureCelerySettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="redis_broker_no_password",
                        severity="high",
                        message="Redis broker/backend URL has no password — require authentication",
                        setting="broker_url",
                    )
                )
            if _GUEST_AMQP_RE.search(line):
                findings.append(
                    InsecureCelerySettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="default_amqp_credentials",
                        severity="high",
                        message="Broker uses default guest:guest credentials — use dedicated credentials",
                        setting="broker_url",
                    )
                )
        return findings

    def analyze(self) -> list[InsecureCelerySettingsFinding]:
        if self._findings:
            return self._findings

        findings: list[InsecureCelerySettingsFinding] = []
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
            file_findings = self._scan_source(rel, source, path.name)
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
        self._stats = InsecureCelerySettingsStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> InsecureCelerySettingsStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        critical = sum(1 for f in self._findings if f.severity == "critical")
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        low = sum(1 for f in self._findings if f.severity == "low")
        penalty = critical * 35.0 + high * 25.0 + medium * 12.0 + low * 5.0
        return round(max(0.0, 100.0 - penalty / self._files_scanned), 1)

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        return (
            f"Insecure Celery settings: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Insecure Celery settings analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No insecure Celery configuration patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
