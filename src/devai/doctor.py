"""Environment diagnostics for DevAI installations and projects."""

from __future__ import annotations

import importlib.metadata
import importlib.util
import platform
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from devai.core.config import DevAIConfig
from devai.health import HealthChecker, HealthResult

_DEVAI_VERSION = importlib.metadata.version("devai")


@dataclass
class DoctorResult:
    """Result of a single diagnostic check."""

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


class DevDoctor:
    """Run environment and configuration diagnostics for DevAI."""

    def __init__(
        self,
        *,
        project_path: str | Path | None = None,
        config: DevAIConfig | None = None,
        probe: bool = True,
    ) -> None:
        self.project_path = Path(project_path or Path.cwd()).resolve()
        self.config = config
        self.probe = probe

    def run(self) -> list[DoctorResult]:
        """Run all diagnostic checks and return results."""
        results = [
            self._check_python(),
            self._check_devai_version(),
            self._check_httpx(),
            self._check_optional_openai(),
            self._check_optional_yaml(),
            self._check_git(),
            self._check_config_file(),
            self._check_api_key(),
        ]
        health = self._check_provider_health()
        if health is not None:
            results.append(health)
        return results

    def passed(self) -> bool:
        """Return True if every diagnostic check passed."""
        return all(r.passed for r in self.run())

    def summary(self) -> str:
        """Format diagnostic results as markdown."""
        results = self.run()
        lines = ["# DevAI Doctor", ""]
        for result in results:
            icon = "✓" if result.passed else "✗"
            lines.append(f"- {icon} **{result.name}**: {result.message}")
        lines.append("")
        status = "All checks passed" if all(r.passed for r in results) else "Some checks failed"
        lines.append(f"**Status:** {status}")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        """Serialize all results to a dictionary."""
        results = self.run()
        return {
            "project_path": str(self.project_path),
            "passed": all(r.passed for r in results),
            "checks": [r.to_dict() for r in results],
        }

    def _check_python(self) -> DoctorResult:
        version = sys.version_info
        ok = version >= (3, 10)
        return DoctorResult(
            name="python",
            passed=ok,
            message=f"Python {version.major}.{version.minor}.{version.micro}"
            + ("" if ok else " (requires >= 3.10)"),
            details={
                "version": platform.python_version(),
                "implementation": platform.python_implementation(),
            },
        )

    def _check_devai_version(self) -> DoctorResult:
        return DoctorResult(
            name="devai",
            passed=True,
            message=f"DevAI {_DEVAI_VERSION}",
            details={"version": _DEVAI_VERSION},
        )

    def _check_httpx(self) -> DoctorResult:
        spec = importlib.util.find_spec("httpx")
        return DoctorResult(
            name="httpx",
            passed=spec is not None,
            message="httpx installed" if spec else "httpx not found (required dependency)",
        )

    def _check_optional_openai(self) -> DoctorResult:
        spec = importlib.util.find_spec("openai")
        installed = spec is not None
        return DoctorResult(
            name="openai-sdk",
            passed=True,
            message="openai SDK installed" if installed else "openai SDK not installed (optional)",
            details={"optional": True, "installed": installed},
        )

    def _check_optional_yaml(self) -> DoctorResult:
        spec = importlib.util.find_spec("yaml")
        installed = spec is not None
        return DoctorResult(
            name="pyyaml",
            passed=True,
            message="PyYAML installed" if installed else "PyYAML not installed (optional, for YAML programs)",
            details={"optional": True, "installed": installed},
        )

    def _check_git(self) -> DoctorResult:
        git = shutil.which("git")
        in_repo = False
        if git:
            try:
                import subprocess

                proc = subprocess.run(
                    [git, "rev-parse", "--is-inside-work-tree"],
                    cwd=self.project_path,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                in_repo = proc.returncode == 0 and proc.stdout.strip() == "true"
            except Exception:
                in_repo = False
        return DoctorResult(
            name="git",
            passed=git is not None,
            message="git available" if git else "git not found",
            details={"in_repo": in_repo, "path": git},
        )

    def _check_config_file(self) -> DoctorResult:
        from devai.config_file import find_config_file

        path = find_config_file(self.project_path)
        if path:
            return DoctorResult(
                name="config-file",
                passed=True,
                message=f"Found {path.name}",
                details={"path": str(path)},
            )
        return DoctorResult(
            name="config-file",
            passed=True,
            message="No .devai.yaml or devai.json (using defaults/env)",
            details={"optional": True},
        )

    def _check_api_key(self) -> DoctorResult:
        if self.config is not None:
            key = self.config.api_key
        else:
            from devai.config_file import find_config_file, load_config_file

            path = find_config_file(self.project_path)
            if path:
                try:
                    cfg = load_config_file(path)
                    key = cfg.api_key
                except Exception as exc:
                    return DoctorResult(
                        name="api-key",
                        passed=False,
                        message=f"Config load failed: {exc}",
                    )
            else:
                try:
                    cfg = DevAIConfig()
                    key = cfg.api_key
                except Exception:
                    key = None

        if key == "mock":
            return DoctorResult(
                name="api-key",
                passed=True,
                message="Using mock mode",
                details={"mode": "mock"},
            )
        if key:
            return DoctorResult(
                name="api-key",
                passed=True,
                message="API key configured",
                details={"preview": key[:4] + "..." if len(key) > 4 else "***"},
            )
        return DoctorResult(
            name="api-key",
            passed=True,
            message="No API key found (set OPENAI_API_KEY or .devai.yaml; use mock mode for local dev)",
            details={"warning": True},
        )

    def _check_provider_health(self) -> DoctorResult | None:
        try:
            if self.config is not None:
                checker = HealthChecker(config=self.config)
            else:
                from devai.config_file import find_config_file, load_config_file

                path = find_config_file(self.project_path)
                if path:
                    cfg = load_config_file(path)
                    checker = HealthChecker(config=cfg)
                else:
                    cfg = DevAIConfig()
                    if not cfg.api_key or cfg.api_key == "mock":
                        return DoctorResult(
                            name="provider-health",
                            passed=True,
                            message="Skipped (no API key configured)",
                            details={"skipped": True},
                        )
                    checker = HealthChecker(config=cfg)
            health: HealthResult = checker.check(probe=self.probe)
            return DoctorResult(
                name="provider-health",
                passed=health.healthy,
                message=health.message,
                details=health.to_dict(),
            )
        except Exception as exc:
            return DoctorResult(
                name="provider-health",
                passed=False,
                message=str(exc),
            )


def run_doctor(
    *,
    project_path: str | Path | None = None,
    probe: bool = True,
    **config_overrides: Any,
) -> list[DoctorResult]:
    """One-line environment diagnostics for DevAI."""
    config = None
    if config_overrides:
        config = DevAIConfig(**config_overrides)
    doctor = DevDoctor(project_path=project_path, config=config, probe=probe)
    return doctor.run()
