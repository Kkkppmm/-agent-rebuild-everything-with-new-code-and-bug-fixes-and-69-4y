"""Environment diagnostics for DevAI setups."""

from __future__ import annotations

import importlib.util
import os
import platform
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from devai.config_file import CONFIG_FILENAMES, find_config_file
from devai.core.config import DevAIConfig
from devai.health import HealthChecker, HealthResult


def _devai_version() -> str:
    try:
        from importlib.metadata import version

        return version("devai")
    except Exception:
        return "unknown"


@dataclass
class DoctorCheck:
    """A single diagnostic check result."""

    name: str
    passed: bool
    message: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "passed": self.passed,
            "message": self.message,
            "details": self.details,
        }


@dataclass
class DoctorResult:
    """Aggregated environment diagnostics."""

    checks: list[DoctorCheck] = field(default_factory=list)
    project_path: Path = field(default_factory=Path.cwd)

    @property
    def healthy(self) -> bool:
        return all(check.passed for check in self.checks)

    @property
    def failed(self) -> list[DoctorCheck]:
        return [check for check in self.checks if not check.passed]

    def to_dict(self) -> dict[str, Any]:
        return {
            "healthy": self.healthy,
            "project_path": str(self.project_path),
            "checks": [check.to_dict() for check in self.checks],
        }

    def summary(self) -> str:
        """Format diagnostics as human-readable text."""
        lines = [f"DevAI doctor — {'OK' if self.healthy else 'ISSUES FOUND'}"]
        lines.append(f"Project: {self.project_path}")
        lines.append("")
        for check in self.checks:
            status = "PASS" if check.passed else "FAIL"
            lines.append(f"[{status}] {check.name}: {check.message}")
        return "\n".join(lines)


class DevDoctor:
    """Run environment diagnostics for DevAI projects."""

    def __init__(
        self,
        project_path: str | Path | None = None,
        *,
        config: DevAIConfig | None = None,
        check_provider: bool = True,
        use_mock: bool = False,
    ) -> None:
        self.project_path = Path(project_path or Path.cwd()).resolve()
        self.config = config
        self.check_provider = check_provider
        self.use_mock = use_mock

    def run(self) -> DoctorResult:
        """Execute all diagnostic checks."""
        checks: list[DoctorCheck] = []
        checks.append(self._check_python())
        checks.append(self._check_devai_version())
        checks.append(self._check_optional_deps())
        checks.append(self._check_config_file())
        checks.append(self._check_api_key())
        checks.append(self._check_git())
        if self.check_provider:
            checks.append(self._check_provider())
        return DoctorResult(checks=checks, project_path=self.project_path)

    def _check_python(self) -> DoctorCheck:
        version = sys.version_info
        ok = version >= (3, 10)
        return DoctorCheck(
            name="python",
            passed=ok,
            message=f"Python {version.major}.{version.minor}.{version.micro}"
            + ("" if ok else " (requires >= 3.10)"),
            details={"platform": platform.platform()},
        )

    def _check_devai_version(self) -> DoctorCheck:
        return DoctorCheck(
            name="devai",
            passed=True,
            message=f"DevAI {_devai_version()} installed",
            details={"version": _devai_version()},
        )

    def _check_optional_deps(self) -> DoctorCheck:
        core = {"httpx": "httpx", "pydantic": "pydantic"}
        optional = {"openai": "openai", "yaml": "yaml"}
        installed: dict[str, bool] = {}
        for label, module in {**core, **optional}.items():
            installed[label] = importlib.util.find_spec(module) is not None
        missing_core = [name for name in core if not installed[name]]
        missing_optional = [name for name in optional if not installed[name]]
        if missing_core:
            message = f"Missing required: {', '.join(missing_core)}"
            passed = False
        elif missing_optional:
            message = f"Optional not installed: {', '.join(missing_optional)}"
            passed = True
        else:
            message = "All dependencies available"
            passed = True
        return DoctorCheck(
            name="dependencies",
            passed=passed,
            message=message,
            details=installed,
        )

    def _check_config_file(self) -> DoctorCheck:
        config_path = find_config_file(self.project_path)
        if config_path is None:
            return DoctorCheck(
                name="config",
                passed=True,
                message=f"No config file found (searched {', '.join(CONFIG_FILENAMES)})",
                details={"found": False},
            )
        return DoctorCheck(
            name="config",
            passed=True,
            message=f"Found {config_path.name}",
            details={"found": True, "path": str(config_path)},
        )

    def _check_api_key(self) -> DoctorCheck:
        if self.use_mock:
            return DoctorCheck(
                name="api_key",
                passed=True,
                message="Mock mode enabled",
                details={"source": "mock"},
            )

        key = None
        source = "none"
        if self.config is not None and self.config.api_key:
            key = self.config.api_key
            source = "config"
        elif os.environ.get("OPENAI_API_KEY"):
            key = os.environ["OPENAI_API_KEY"]
            source = "OPENAI_API_KEY"
        elif os.environ.get("DEVAI_API_KEY"):
            key = os.environ["DEVAI_API_KEY"]
            source = "DEVAI_API_KEY"

        if key:
            masked = key[:4] + "..." if len(key) > 8 else "***"
            return DoctorCheck(
                name="api_key",
                passed=True,
                message=f"API key set via {source} ({masked})",
                details={"source": source},
            )
        return DoctorCheck(
            name="api_key",
            passed=False,
            message="No API key found (set OPENAI_API_KEY, DEVAI_API_KEY, or use --mock)",
            details={"source": source},
        )

    def _check_git(self) -> DoctorCheck:
        git = shutil.which("git")
        if git is None:
            return DoctorCheck(
                name="git",
                passed=True,
                message="git not installed (optional)",
                details={"available": False},
            )
        git_dir = self.project_path / ".git"
        if git_dir.exists():
            return DoctorCheck(
                name="git",
                passed=True,
                message="git available and project is a repository",
                details={"available": True, "repo": True},
            )
        return DoctorCheck(
            name="git",
            passed=True,
            message="git available (project is not a git repo)",
            details={"available": True, "repo": False},
        )

    def _check_provider(self) -> DoctorCheck:
        if self.use_mock:
            from devai.core.client import MockLLMClient

            checker = HealthChecker(client=MockLLMClient())
        elif self.config is not None:
            checker = HealthChecker(config=self.config)
        else:
            config_path = find_config_file(self.project_path)
            if config_path is not None:
                from devai.config_file import load_config_file

                checker = HealthChecker(config=load_config_file(config_path))
            else:
                checker = HealthChecker(config=DevAIConfig())

        health: HealthResult = checker.check(probe=False)
        return DoctorCheck(
            name="provider",
            passed=health.healthy,
            message=health.message,
            details={
                "provider": health.provider,
                "model": health.model,
                "latency_ms": health.latency_ms,
            },
        )


def run_doctor(
    project_path: str | Path | None = None,
    *,
    use_mock: bool = False,
    check_provider: bool = True,
    **config_overrides: Any,
) -> DoctorResult:
    """One-line environment diagnostics."""
    config = DevAIConfig(**config_overrides) if config_overrides else None
    doctor = DevDoctor(
        project_path=project_path,
        config=config,
        check_provider=check_provider,
        use_mock=use_mock,
    )
    return doctor.run()
