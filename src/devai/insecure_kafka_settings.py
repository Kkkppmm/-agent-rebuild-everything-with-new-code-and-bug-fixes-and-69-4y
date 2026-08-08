"""InsecureKafkaSettingsAnalyzer — detect insecure Kafka configuration."""

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
        "kafka.py",
        "celery.py",
    }
)
_KAFKA_PLAINTEXT_RE = re.compile(
    r"(KAFKA_BOOTSTRAP_SERVERS|KAFKA_BROKERS|BOOTSTRAP_SERVERS)\s*=\s*['\"][^'\"]*['\"]",
    re.IGNORECASE,
)
_KAFKA_NO_SASL_RE = re.compile(
    r"(SECURITY_PROTOCOL|KAFKA_SECURITY_PROTOCOL)\s*=\s*['\"]PLAINTEXT['\"]",
    re.IGNORECASE,
)
_KAFKA_SASL_PLAIN_RE = re.compile(
    r"(SASL_MECHANISM|KAFKA_SASL_MECHANISM)\s*=\s*['\"]PLAIN['\"]",
    re.IGNORECASE,
)
_KAFKA_HARDCODED_PASSWORD_RE = re.compile(
    r"(KAFKA_PASSWORD|SASL_PASSWORD)\s*=\s*['\"][^'\"]+['\"]",
    re.IGNORECASE,
)
_KAFKA_SSL_FALSE_RE = re.compile(
    r"(KAFKA_SSL|SSL_CHECK_HOSTNAME)\s*=\s*False",
    re.IGNORECASE,
)


@dataclass
class InsecureKafkaSettingsFinding:
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
class InsecureKafkaSettingsStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _bool_value(node: ast.AST) -> bool | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, bool):
        return node.value
    if isinstance(node, ast.NameConstant):  # noqa: SIM114 — py310 compat
        return node.value
    return None


def _string_value(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


class _InsecureKafkaSettingsVisitor(ast.NodeVisitor):
    def __init__(self, path: str, filename: str) -> None:
        self.path = path
        self.filename = filename
        self.findings: list[InsecureKafkaSettingsFinding] = []

    def _add(
        self,
        lineno: int,
        pattern: str,
        severity: str,
        message: str,
        setting: str = "",
    ) -> None:
        self.findings.append(
            InsecureKafkaSettingsFinding(
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
            if not isinstance(target, ast.Name):
                continue
            name = target.id.upper()
            if name in {"SECURITY_PROTOCOL", "KAFKA_SECURITY_PROTOCOL"}:
                value = _string_value(node.value)
                if value and value.upper() == "PLAINTEXT":
                    self._add(
                        node.lineno,
                        "kafka_plaintext_protocol",
                        "critical",
                        f"{target.id} is PLAINTEXT — use SASL_SSL or SSL",
                        setting=target.id,
                    )
            elif name in {"SASL_MECHANISM", "KAFKA_SASL_MECHANISM"}:
                value = _string_value(node.value)
                if value and value.upper() == "PLAIN":
                    self._add(
                        node.lineno,
                        "kafka_weak_sasl",
                        "medium",
                        f"{target.id} is PLAIN — prefer SCRAM-SHA-256 or SCRAM-SHA-512",
                        setting=target.id,
                    )
            elif name in {"KAFKA_SSL", "SSL_CHECK_HOSTNAME"}:
                if _bool_value(node.value) is False:
                    self._add(
                        node.lineno,
                        "kafka_ssl_disabled",
                        "high",
                        f"{target.id} is False — enable TLS for Kafka connections",
                        setting=target.id,
                    )
            elif name in {"KAFKA_PASSWORD", "SASL_PASSWORD"}:
                value = _string_value(node.value)
                if value is not None and len(value) >= 4:
                    self._add(
                        node.lineno,
                        "hardcoded_kafka_password",
                        "critical",
                        f"{target.id} is hardcoded — load Kafka credentials from environment",
                        setting=target.id,
                    )
        self.generic_visit(node)


class InsecureKafkaSettingsAnalyzer:
    """Detect insecure Kafka configuration in Django, Celery, and similar apps."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[InsecureKafkaSettingsFinding] = []
        self._stats: InsecureKafkaSettingsStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _scan_source(
        self, rel: str, source: str, filename: str
    ) -> list[InsecureKafkaSettingsFinding]:
        findings: list[InsecureKafkaSettingsFinding] = []
        try:
            tree = ast.parse(source, filename=rel)
            visitor = _InsecureKafkaSettingsVisitor(rel, filename)
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
            if _KAFKA_NO_SASL_RE.search(line):
                findings.append(
                    InsecureKafkaSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="kafka_plaintext_protocol",
                        severity="critical",
                        message="Kafka security protocol is PLAINTEXT — use SASL_SSL or SSL",
                        setting="SECURITY_PROTOCOL",
                    )
                )
            if _KAFKA_SASL_PLAIN_RE.search(line):
                findings.append(
                    InsecureKafkaSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="kafka_weak_sasl",
                        severity="medium",
                        message="Kafka SASL mechanism is PLAIN — prefer SCRAM-SHA-256",
                        setting="SASL_MECHANISM",
                    )
                )
            if _KAFKA_SSL_FALSE_RE.search(line):
                findings.append(
                    InsecureKafkaSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="kafka_ssl_disabled",
                        severity="high",
                        message="Kafka TLS is disabled",
                        setting="KAFKA_SSL",
                    )
                )
            if _KAFKA_HARDCODED_PASSWORD_RE.search(line):
                findings.append(
                    InsecureKafkaSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="hardcoded_kafka_password",
                        severity="critical",
                        message="Kafka password is hardcoded — load from environment variables",
                        setting="KAFKA_PASSWORD",
                    )
                )
        return findings

    def analyze(self) -> list[InsecureKafkaSettingsFinding]:
        if self._findings:
            return self._findings

        findings: list[InsecureKafkaSettingsFinding] = []
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
        self._stats = InsecureKafkaSettingsStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> InsecureKafkaSettingsStats:
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
            f"Insecure Kafka settings: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Insecure Kafka settings analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No insecure Kafka configuration patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
