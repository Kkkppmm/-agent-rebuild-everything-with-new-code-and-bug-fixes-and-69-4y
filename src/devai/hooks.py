"""Git hooks installer for DevAI-powered developer workflows."""

from __future__ import annotations

from pathlib import Path

SUPPORTED_HOOKS = frozenset(
    {
        "pre-commit",
        "pre-push",
        "commit-msg",
        "post-commit",
    }
)

_HOOK_HEADER = "#!/bin/sh\n# DevAI-managed hook — edit with care or reinstall via devai hooks install\n"


def _hook_script(hook_name: str, preset: str, *, fail_on_issues: bool) -> str:
    if hook_name == "pre-commit":
        gate = "exit 1" if fail_on_issues else "exit 0"
        return (
            _HOOK_HEADER
            + f"devai ci --preset {preset} --staged --mock 2>/dev/null || "
            + f"devai ci --preset {preset} --staged || {gate}\n"
        )
    if hook_name == "pre-push":
        gate = "exit 1" if fail_on_issues else "exit 0"
        return (
            _HOOK_HEADER
            + f"devai ci --preset {preset} --diff \"$(git diff origin/main...HEAD)\" "
            + f"--mock 2>/dev/null || devai ci --preset {preset} "
            + f"--diff \"$(git diff origin/main...HEAD)\" || {gate}\n"
        )
    if hook_name == "commit-msg":
        return (
            _HOOK_HEADER
            + "MSG_FILE=\"$1\"\n"
            + "if [ -z \"$MSG_FILE\" ]; then exit 0; fi\n"
            + "MSG=$(cat \"$MSG_FILE\")\n"
            + "if echo \"$MSG\" | grep -qE '^(fix|feat|chore|docs|refactor|test|ci):'; then exit 0; fi\n"
            + "echo \"DevAI: commit message should start with fix:, feat:, chore:, docs:, refactor:, test:, or ci:\" >&2\n"
            + ("exit 1\n" if fail_on_issues else "exit 0\n")
        )
    if hook_name == "post-commit":
        return (
            _HOOK_HEADER
            + f"devai report {preset} --staged --format markdown "
            + "> /dev/null 2>&1 || true\n"
        )
    raise ValueError(f"Unsupported hook: {hook_name}")


class DevHooks:
    """Install and manage git hooks that run DevAI presets."""

    def __init__(
        self,
        project_path: str | Path = ".",
        *,
        preset: str = "pre-commit",
        fail_on_issues: bool = True,
    ) -> None:
        self.project_path = Path(project_path).resolve()
        self.preset = preset
        self.fail_on_issues = fail_on_issues
        self.hooks_dir = self.project_path / ".git" / "hooks"

    def generate(self, hook_name: str) -> str:
        """Generate hook script content without writing to disk."""
        if hook_name not in SUPPORTED_HOOKS:
            raise ValueError(
                f"Unsupported hook '{hook_name}'. Supported: {sorted(SUPPORTED_HOOKS)}"
            )
        return _hook_script(hook_name, self.preset, fail_on_issues=self.fail_on_issues)

    def install(self, hooks: list[str] | None = None) -> list[str]:
        """Install DevAI hooks into `.git/hooks`. Returns installed hook names."""
        if not self.hooks_dir.is_dir():
            raise FileNotFoundError(
                f"Git hooks directory not found: {self.hooks_dir}. Is this a git repo?"
            )
        target_hooks = hooks or ["pre-commit"]
        installed: list[str] = []
        for name in target_hooks:
            if name not in SUPPORTED_HOOKS:
                raise ValueError(f"Unsupported hook: {name}")
            path = self.hooks_dir / name
            path.write_text(self.generate(name), encoding="utf-8")
            path.chmod(0o755)
            installed.append(name)
        return installed

    def uninstall(self, hooks: list[str] | None = None) -> list[str]:
        """Remove DevAI-managed hooks. Returns removed hook names."""
        if not self.hooks_dir.is_dir():
            return []
        target_hooks = hooks or list(SUPPORTED_HOOKS)
        removed: list[str] = []
        for name in target_hooks:
            path = self.hooks_dir / name
            if not path.is_file():
                continue
            try:
                content = path.read_text(encoding="utf-8")
            except OSError:
                continue
            if "DevAI-managed hook" not in content:
                continue
            path.unlink()
            removed.append(name)
        return removed

    def list_installed(self) -> list[str]:
        """List DevAI-managed hooks currently installed."""
        if not self.hooks_dir.is_dir():
            return []
        found: list[str] = []
        for name in SUPPORTED_HOOKS:
            path = self.hooks_dir / name
            if not path.is_file():
                continue
            try:
                content = path.read_text(encoding="utf-8")
            except OSError:
                continue
            if "DevAI-managed hook" in content:
                found.append(name)
        return found

    def status(self) -> dict[str, str]:
        """Return status of each supported hook (installed, other, missing)."""
        result: dict[str, str] = {}
        for name in sorted(SUPPORTED_HOOKS):
            path = self.hooks_dir / name
            if not path.is_file():
                result[name] = "missing"
                continue
            try:
                content = path.read_text(encoding="utf-8")
            except OSError:
                result[name] = "unreadable"
                continue
            if "DevAI-managed hook" in content:
                result[name] = "installed"
            else:
                result[name] = "other"
        return result
