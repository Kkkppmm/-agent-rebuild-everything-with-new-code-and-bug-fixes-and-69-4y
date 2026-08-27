"""Tests for DevAI git hooks."""

from pathlib import Path

from devai.hooks import DevHooks, SUPPORTED_HOOKS


class TestDevHooks:
    def test_generate_pre_commit(self):
        hooks = DevHooks(preset="pre-commit")
        script = hooks.generate("pre-commit")
        assert "DevAI-managed hook" in script
        assert "pre-commit" in script
        assert script.startswith("#!/bin/sh")

    def test_generate_commit_msg(self):
        hooks = DevHooks(fail_on_issues=True)
        script = hooks.generate("commit-msg")
        assert "commit message" in script.lower()

    def test_install_and_uninstall(self, tmp_path: Path):
        git_dir = tmp_path / ".git" / "hooks"
        git_dir.mkdir(parents=True)
        hooks = DevHooks(tmp_path, preset="pre-commit")
        installed = hooks.install(["pre-commit", "commit-msg"])
        assert installed == ["pre-commit", "commit-msg"]
        assert (git_dir / "pre-commit").is_file()
        assert (git_dir / "commit-msg").is_file()
        assert hooks.list_installed() == ["commit-msg", "pre-commit"]

        status = hooks.status()
        assert status["pre-commit"] == "installed"
        assert status["pre-push"] == "missing"

        removed = hooks.uninstall(["pre-commit"])
        assert removed == ["pre-commit"]
        assert hooks.list_installed() == ["commit-msg"]

    def test_uninstall_skips_non_devai_hooks(self, tmp_path: Path):
        git_dir = tmp_path / ".git" / "hooks"
        git_dir.mkdir(parents=True)
        (git_dir / "pre-commit").write_text("#!/bin/sh\necho custom\n", encoding="utf-8")
        hooks = DevHooks(tmp_path)
        removed = hooks.uninstall(["pre-commit"])
        assert removed == []
        assert (git_dir / "pre-commit").is_file()

    def test_supported_hooks(self):
        assert "pre-commit" in SUPPORTED_HOOKS
        assert "pre-push" in SUPPORTED_HOOKS
