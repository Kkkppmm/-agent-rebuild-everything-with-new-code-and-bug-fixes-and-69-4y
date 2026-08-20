"""InsecureStorageSettingsAnalyzer — detect insecure file/storage configuration."""

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
        "storage.py",
    }
)
_FILESYSTEM_STORAGE_RE = re.compile(
    r"(django\.core\.files\.storage\.)?FileSystemStorage|FileSystemStorage",
    re.IGNORECASE,
)
_PUBLIC_ACL_RE = re.compile(
    r"AWS_DEFAULT_ACL\s*=\s*['\"]public-read['\"]|AWS_S3_OBJECT_PARAMETERS\s*=\s*\{[^}]*['\"]ACL['\"]\s*:\s*['\"]public-read['\"]",
    re.IGNORECASE,
)
_HARDCODED_AWS_KEY_RE = re.compile(
    r"AWS_(ACCESS_KEY_ID|SECRET_ACCESS_KEY)\s*=\s*['\"][^'\"]{8,}['\"]",
    re.IGNORECASE,
)
_DEFAULT_STORAGE_RE = re.compile(
    r"DEFAULT_FILE_STORAGE\s*=\s*['\"][^'\"]*FileSystemStorage",
    re.IGNORECASE,
)


@dataclass
class InsecureStorageSettingsFinding:
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
class InsecureStorageSettingsStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _dict_string_value(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _is_filesystem_storage(value: str) -> bool:
    return bool(_FILESYSTEM_STORAGE_RE.search(value))


def _is_public_acl(value: str) -> bool:
    return value.lower() in {"public-read", "public-read-write", "authenticated-read"}


class _InsecureStorageSettingsVisitor(ast.NodeVisitor):
    def __init__(self, path: str, filename: str) -> None:
        self.path = path
        self.filename = filename
        self.findings: list[InsecureStorageSettingsFinding] = []

    def _add(
        self,
        lineno: int,
        pattern: str,
        severity: str,
        message: str,
        setting: str = "",
    ) -> None:
        self.findings.append(
            InsecureStorageSettingsFinding(
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
            name = target.id
            value = _dict_string_value(node.value)
            if name in {"DEFAULT_FILE_STORAGE", "STATICFILES_STORAGE"} and value:
                if _is_filesystem_storage(value):
                    self._add(
                        node.lineno,
                        "filesystem_storage_in_production",
                        "medium",
                        f"{name} uses local FileSystemStorage — use S3/GCS for production",
                        setting=name,
                    )
            elif name == "AWS_DEFAULT_ACL" and value and _is_public_acl(value):
                self._add(
                    node.lineno,
                    "public_s3_acl",
                    "high",
                    f"AWS_DEFAULT_ACL='{value}' makes uploaded files publicly accessible",
                    setting="AWS_DEFAULT_ACL",
                )
            elif name in {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"} and value:
                if not value.startswith("os.environ") and len(value) >= 8:
                    self._add(
                        node.lineno,
                        "hardcoded_aws_credentials",
                        "critical",
                        f"{name} is hardcoded — use IAM roles or environment variables",
                        setting=name,
                    )
            elif name == "STORAGES" and isinstance(node.value, ast.Dict):
                self._scan_storages_dict(node.value)
        self.generic_visit(node)

    def _scan_storages_dict(self, node: ast.Dict) -> None:
        for storage_key, storage_config in zip(node.keys, node.values):
            if not isinstance(storage_config, ast.Dict):
                continue
            storage_name = _dict_string_value(storage_key) if storage_key else "default"
            for sk, sv in zip(storage_config.keys, storage_config.values):
                sk_name = _dict_string_value(sk) if sk else None
                if sk_name == "BACKEND":
                    backend = _dict_string_value(sv)
                    if backend and _is_filesystem_storage(backend):
                        self._add(
                            storage_config.lineno,
                            "filesystem_storage_in_production",
                            "medium",
                            f"STORAGES['{storage_name}'] uses FileSystemStorage — use cloud storage in production",
                            setting="STORAGES",
                        )


class InsecureStorageSettingsAnalyzer:
    """Detect insecure file/storage configuration in Django and similar apps."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[InsecureStorageSettingsFinding] = []
        self._stats: InsecureStorageSettingsStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _scan_source(
        self, rel: str, source: str, filename: str
    ) -> list[InsecureStorageSettingsFinding]:
        findings: list[InsecureStorageSettingsFinding] = []
        try:
            tree = ast.parse(source, filename=rel)
            visitor = _InsecureStorageSettingsVisitor(rel, filename)
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
            if _DEFAULT_STORAGE_RE.search(line) or (
                "DEFAULT_FILE_STORAGE" in line and _FILESYSTEM_STORAGE_RE.search(line)
            ):
                findings.append(
                    InsecureStorageSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="filesystem_storage_in_production",
                        severity="medium",
                        message="DEFAULT_FILE_STORAGE uses local FileSystemStorage — use S3/GCS for production",
                        setting="DEFAULT_FILE_STORAGE",
                    )
                )
            if _PUBLIC_ACL_RE.search(line):
                findings.append(
                    InsecureStorageSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="public_s3_acl",
                        severity="high",
                        message="S3 ACL set to public-read — uploaded files may be publicly accessible",
                        setting="AWS_DEFAULT_ACL",
                    )
                )
            if _HARDCODED_AWS_KEY_RE.search(line):
                findings.append(
                    InsecureStorageSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="hardcoded_aws_credentials",
                        severity="critical",
                        message="AWS credentials are hardcoded — use IAM roles or environment variables",
                        setting="AWS_ACCESS_KEY_ID",
                    )
                )
        return findings

    def analyze(self) -> list[InsecureStorageSettingsFinding]:
        if self._findings:
            return self._findings

        findings: list[InsecureStorageSettingsFinding] = []
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
        self._stats = InsecureStorageSettingsStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> InsecureStorageSettingsStats:
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
            f"Insecure storage settings: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Insecure storage settings analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No insecure storage configuration patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
