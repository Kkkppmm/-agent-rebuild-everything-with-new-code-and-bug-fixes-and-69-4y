"""Detect project type, language, and framework from a directory."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class ProjectProfile:
    """Detected characteristics of a software project."""

    root: str
    languages: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    package_managers: list[str] = field(default_factory=list)
    has_git: bool = False
    has_tests: bool = False
    has_ci: bool = False
    python_version: str | None = None

    @property
    def primary_language(self) -> str | None:
        return self.languages[0] if self.languages else None

    @property
    def summary(self) -> str:
        parts: list[str] = []
        if self.languages:
            parts.append(", ".join(self.languages))
        if self.frameworks:
            parts.append(" + ".join(self.frameworks))
        if self.package_managers:
            parts.append(f"({', '.join(self.package_managers)})")
        return " ".join(parts) if parts else "unknown project"

    def to_context(self) -> str:
        """Format profile as LLM context."""
        lines = [
            f"Project root: {self.root}",
            f"Languages: {', '.join(self.languages) or 'unknown'}",
            f"Frameworks: {', '.join(self.frameworks) or 'none detected'}",
            f"Package managers: {', '.join(self.package_managers) or 'none detected'}",
            f"Git: {'yes' if self.has_git else 'no'}",
            f"Tests: {'yes' if self.has_tests else 'no'}",
            f"CI: {'yes' if self.has_ci else 'no'}",
        ]
        if self.python_version:
            lines.append(f"Python version: {self.python_version}")
        return "\n".join(lines)


def _exists(root: Path, *parts: str) -> bool:
    return (root.joinpath(*parts)).exists()


def _has_glob(root: Path, pattern: str) -> bool:
    return any(root.glob(pattern))


class ProjectDetector:
    """Detect project type and tooling from filesystem signals."""

    def detect(self, path: str | Path = ".") -> ProjectProfile:
        root = Path(path).resolve()
        if not root.exists():
            raise FileNotFoundError(f"Project path not found: {path}")

        languages: list[str] = []
        frameworks: list[str] = []
        package_managers: list[str] = []
        python_version: str | None = None

        if _has_glob(root, "**/*.py") or _exists(root, "pyproject.toml") or _exists(root, "setup.py"):
            languages.append("python")
        if _has_glob(root, "**/*.js") or _has_glob(root, "**/*.ts"):
            languages.append("javascript")
        if _has_glob(root, "**/*.go"):
            languages.append("go")
        if _has_glob(root, "**/*.rs"):
            languages.append("rust")
        if _has_glob(root, "**/*.java"):
            languages.append("java")
        if _has_glob(root, "**/*.php"):
            languages.append("php")
        if _has_glob(root, "**/*.c") or _has_glob(root, "**/*.cpp") or _has_glob(root, "**/*.h"):
            languages.append("c/c++")

        if _exists(root, "pyproject.toml"):
            package_managers.append("pip/poetry")
            text = root.joinpath("pyproject.toml").read_text(encoding="utf-8", errors="replace")
            if "requires-python" in text:
                for line in text.splitlines():
                    if "requires-python" in line and ">=" in line:
                        python_version = line.split(">=")[-1].strip().strip('"').strip("'")
                        break
        if _exists(root, "requirements.txt"):
            if "pip/poetry" not in package_managers:
                package_managers.append("pip")
        if _exists(root, "package.json"):
            package_managers.append("npm")
        if _exists(root, "go.mod"):
            package_managers.append("go modules")
        if _exists(root, "Cargo.toml"):
            package_managers.append("cargo")
        if _exists(root, "composer.json"):
            package_managers.append("composer")
        if _exists(root, "CMakeLists.txt"):
            package_managers.append("cmake")
        if _exists(root, "meson.build"):
            package_managers.append("meson")
        if _exists(root, "conanfile.py") or _exists(root, "conanfile.txt"):
            package_managers.append("conan")
        if _exists(root, "vcpkg.json") or _exists(root, "vcpkg-configuration.json"):
            package_managers.append("vcpkg")
        if _exists(root, "flake.nix") or _exists(root, "shell.nix") or _exists(root, "default.nix"):
            package_managers.append("nix")
        if _exists(root, "Brewfile") or _has_glob(root, "Formula/*.rb"):
            package_managers.append("homebrew")
        if (
            _exists(root, ".mise.toml")
            or _exists(root, "mise.toml")
            or _exists(root, ".tool-versions")
            or _exists(root, ".rtx.toml")
            or _exists(root, "mise.lock")
        ):
            package_managers.append("mise")
        if _exists(root, "turbo.json") or _exists(root, "turbo.jsonc"):
            package_managers.append("turbo")
        if (
            _exists(root, "pnpm-workspace.yaml")
            or _exists(root, "pnpm-lock.yaml")
            or _has_glob(root, "**/pnpm-lock.yaml")
        ):
            package_managers.append("pnpm")
        if _exists(root, "bunfig.toml") or _exists(root, "bun.lock") or _exists(root, "bun.lockb"):
            package_managers.append("bun")
        if _exists(root, "deno.json") or _exists(root, "deno.jsonc"):
            package_managers.append("deno")

        if _exists(root, "manage.py"):
            frameworks.append("django")
        if _exists(root, "wsgi.py") or _exists(root, "asgi.py"):
            if "django" not in frameworks:
                frameworks.append("wsgi/asgi")
        if _has_glob(root, "**/fastapi/**/*.py") or _exists(root, "main.py"):
            main = root / "main.py"
            if main.exists():
                content = main.read_text(encoding="utf-8", errors="replace")
                if "FastAPI" in content:
                    frameworks.append("fastapi")
        if _exists(root, "app.py"):
            content = root.joinpath("app.py").read_text(encoding="utf-8", errors="replace")
            if "Flask" in content:
                frameworks.append("flask")
        if _exists(root, "package.json"):
            pkg = root.joinpath("package.json").read_text(encoding="utf-8", errors="replace")
            if '"next"' in pkg:
                frameworks.append("next.js")
            if '"react"' in pkg:
                frameworks.append("react")
            if '"express"' in pkg:
                frameworks.append("express")
        if _exists(root, "wrangler.toml") or _exists(root, "wrangler.jsonc"):
            frameworks.append("cloudflare workers")

        has_git = _exists(root, ".git")
        has_tests = (
            _exists(root, "tests")
            or _exists(root, "test")
            or _has_glob(root, "**/test_*.py")
            or _has_glob(root, "**/*_test.go")
        )
        has_ci = (
            _exists(root, ".github", "workflows")
            or _exists(root, ".gitlab-ci.yml")
            or _exists(root, "Jenkinsfile")
        )

        return ProjectProfile(
            root=str(root),
            languages=languages,
            frameworks=frameworks,
            package_managers=package_managers,
            has_git=has_git,
            has_tests=has_tests,
            has_ci=has_ci,
            python_version=python_version,
        )
