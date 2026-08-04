"""Tests for GitContext."""

from unittest.mock import patch

from devai import CodeAssistant, GitContext, MockLLMClient


class TestGitContext:
    def test_diff_delegates_to_get_git_diff(self):
        ctx = GitContext(staged=True, base="main")
        with patch("devai.git_context.get_git_diff", return_value="diff text") as mock_diff:
            assert ctx.diff() == "diff text"
            mock_diff.assert_called_once_with(staged=True, base="main", path=None)

    def test_review_changes(self):
        client = MockLLMClient(default_response="Looks good")
        assistant = CodeAssistant(client=client)
        ctx = GitContext()
        with patch.object(ctx, "diff", return_value="+def foo(): pass"):
            result = ctx.review_changes(assistant)
        assert result == "Looks good"

    def test_staged_factory(self):
        ctx = GitContext.staged_changes("/tmp/repo")
        assert ctx.staged is True
        assert str(ctx.repo_path) == "/tmp/repo"

    def test_against_factory(self):
        ctx = GitContext.against("main")
        assert ctx.base == "main"
