"""InsecureJwtSettingsAnalyzer — detect insecure JWT configuration in settings."""

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
        "auth.py",
        "jwt.py",
    }
)
_JWT_VERIFY_FALSE_RE = re.compile(
    r"(JWT_VERIFY|JWT_VERIFY_SIGNATURE|JWT_AUTH)\s*=\s*False",
    re.IGNORECASE,
)
_JWT_ALGORITHM_NONE_RE = re.compile(
    r"JWT_ALGORITHM\s*=\s*['\"]none['\"]",
    re.IGNORECASE,
)
_JWT_HARDCODED_SECRET_RE = re.compile(
    r"(JWT_SECRET_KEY|JWT_SECRET|JWT_SIGNING_KEY)\s*=\s*['\"][^'\"]+['\"]",
    re.IGNORECASE,
)
_SIMPLE_JWT_VERIFY_FALSE_RE = re.compile(
    r"['\"]VERIFY['\"]\s*:\s*False",
    re.IGNORECASE,
)


@dataclass
class InsecureJwtSettingsFinding:
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
class InsecureJwtSettingsStats:
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


def _dict_bool_false(node: ast.AST, key: str) -> bool:
    if not isinstance(node, ast.Dict):
        return False
    for k, v in zip(node.keys, node.values):
        if (
            k
            and isinstance(k, ast.Constant)
            and isinstance(k.value, str)
            and k.value.upper() == key.upper()
            and _bool_value(v) is False
        ):
            return True
    return False


class _InsecureJwtSettingsVisitor(ast.NodeVisitor):
    def __init__(self, path: str, filename: str) -> None:
        self.path = path
        self.filename = filename
        self.findings: list[InsecureJwtSettingsFinding] = []

    def _add(
        self,
        lineno: int,
        pattern: str,
        severity: str,
        message: str,
        setting: str = "",
    ) -> None:
        self.findings.append(
            InsecureJwtSettingsFinding(
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
            if name in {"JWT_VERIFY", "JWT_VERIFY_SIGNATURE"}:
                if _bool_value(node.value) is False:
                    self._add(
                        node.lineno,
                        "jwt_verification_disabled",
                        "critical",
                        "JWT signature verification is disabled — tokens can be forged",
                        setting=target.id,
                    )
            elif name == "JWT_ALGORITHM":
                value = _string_value(node.value)
                if value and value.lower() == "none":
                    self._add(
                        node.lineno,
                        "jwt_algorithm_none",
                        "critical",
                        "JWT algorithm is 'none' — signatures are not enforced",
                        setting=target.id,
                    )
            elif name in {"JWT_SECRET_KEY", "JWT_SECRET", "JWT_SIGNING_KEY"}:
                value = _string_value(node.value)
                if value is not None:
                    if len(value) < 32:
                        self._add(
                            node.lineno,
                            "weak_jwt_secret",
                            "high",
                            f"{target.id} is too short — use a cryptographically random secret of 32+ characters",
                            setting=target.id,
                        )
            elif name == "SIMPLE_JWT":
                if _dict_bool_false(node.value, "VERIFY"):
                    self._add(
                        node.lineno,
                        "jwt_verification_disabled",
                        "critical",
                        "SIMPLE_JWT VERIFY is False — JWT signatures are not checked",
                        setting="SIMPLE_JWT",
                    )
                if _dict_bool_false(node.value, "VERIFY_SIGNATURE"):
                    self._add(
                        node.lineno,
                        "jwt_verification_disabled",
                        "critical",
                        "SIMPLE_JWT VERIFY_SIGNATURE is False — JWT signatures are not checked",
                        setting="SIMPLE_JWT",
                    )
        self.generic_visit(node)


class InsecureJwtSettingsAnalyzer:
    """Detect insecure JWT configuration in Django REST Framework and similar apps."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[InsecureJwtSettingsFinding] = []
        self._stats: InsecureJwtSettingsStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _scan_source(
        self, rel: str, source: str, filename: str
    ) -> list[InsecureJwtSettingsFinding]:
        findings: list[InsecureJwtSettingsFinding] = []
        try:
            tree = ast.parse(source, filename=rel)
            visitor = _InsecureJwtSettingsVisitor(rel, filename)
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
            if _JWT_VERIFY_FALSE_RE.search(line):
                findings.append(
                    InsecureJwtSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="jwt_verification_disabled",
                        severity="critical",
                        message="JWT signature verification is disabled — tokens can be forged",
                        setting="JWT_VERIFY",
                    )
                )
            if _JWT_ALGORITHM_NONE_RE.search(line):
                findings.append(
                    InsecureJwtSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="jwt_algorithm_none",
                        severity="critical",
                        message="JWT algorithm is 'none' — signatures are not enforced",
                        setting="JWT_ALGORITHM",
                    )
                )
            if _JWT_HARDCODED_SECRET_RE.search(line):
                secret_match = _JWT_HARDCODED_SECRET_RE.search(line)
                if secret_match:
                    secret_part = line[secret_match.start() :]
                    quote = "'" if "'" in secret_part.split("=", 1)[1] else '"'
                    parts = secret_part.split(quote)
                    if len(parts) >= 2 and len(parts[1]) < 32:
                        findings.append(
                            InsecureJwtSettingsFinding(
                                path=rel,
                                lineno=lineno,
                                pattern="weak_jwt_secret",
                                severity="high",
                                message="JWT secret is too short — use a cryptographically random secret of 32+ characters",
                                setting="JWT_SECRET_KEY",
                            )
                        )
            if "SIMPLE_JWT" in line and _SIMPLE_JWT_VERIFY_FALSE_RE.search(line):
                findings.append(
                    InsecureJwtSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="jwt_verification_disabled",
                        severity="critical",
                        message="SIMPLE_JWT VERIFY is False — JWT signatures are not checked",
                        setting="SIMPLE_JWT",
                    )
                )
        return findings

    def analyze(self) -> list[InsecureJwtSettingsFinding]:
        if self._findings:
            return self._findings

        findings: list[InsecureJwtSettingsFinding] = []
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
        self._stats = InsecureJwtSettingsStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> InsecureJwtSettingsStats:
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
            f"Insecure JWT settings: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Insecure JWT settings analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No insecure JWT configuration patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
