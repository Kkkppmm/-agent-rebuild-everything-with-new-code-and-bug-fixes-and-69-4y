"""Tests for ConventionalCommitsValidator."""

from devai.conventional_commits import ConventionalCommitsValidator


class TestConventionalCommitsValidator:
    def test_valid_feat(self):
        validator = ConventionalCommitsValidator()
        result = validator.validate("feat(api): add user endpoint")
        assert result.valid
        assert result.commit_type == "feat"
        assert result.scope == "api"
        assert result.description == "add user endpoint"

    def test_valid_fix_no_scope(self):
        validator = ConventionalCommitsValidator()
        result = validator.validate("fix: resolve null pointer")
        assert result.valid
        assert result.commit_type == "fix"
        assert result.scope is None

    def test_breaking_change(self):
        validator = ConventionalCommitsValidator()
        result = validator.validate("feat!: remove legacy API")
        assert result.valid
        assert result.breaking

    def test_invalid_type(self):
        validator = ConventionalCommitsValidator()
        result = validator.validate("invalid: bad commit")
        assert not result.valid
        assert any("Unknown type" in e for e in result.errors)

    def test_empty_message(self):
        validator = ConventionalCommitsValidator()
        result = validator.validate("")
        assert not result.valid

    def test_description_ends_with_period(self):
        validator = ConventionalCommitsValidator()
        result = validator.validate("fix: resolve bug.")
        assert not result.valid
        assert any("period" in e for e in result.errors)

    def test_missing_blank_line_before_body(self):
        validator = ConventionalCommitsValidator()
        result = validator.validate("fix: resolve bug\nBody without blank line")
        assert not result.valid

    def test_require_scope(self):
        validator = ConventionalCommitsValidator(require_scope=True)
        result = validator.validate("fix: no scope here")
        assert not result.valid
        scoped = validator.validate("fix(api): with scope")
        assert scoped.valid

    def test_lint_helper(self):
        validator = ConventionalCommitsValidator()
        assert validator.lint("feat: add feature") is None
        assert validator.lint("bad message") is not None

    def test_validate_batch(self):
        validator = ConventionalCommitsValidator()
        results = validator.validate_batch(["feat: a", "bad"])
        assert results[0].valid
        assert not results[1].valid
