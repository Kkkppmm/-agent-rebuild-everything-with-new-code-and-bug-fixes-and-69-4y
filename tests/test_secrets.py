"""Tests for DevAI SecretsScanner."""

from pathlib import Path

from devai.secrets import SecretsScanner, SecretFinding


class TestSecretsScanner:
    def test_detect_github_token(self):
        scanner = SecretsScanner(".")
        findings = scanner.scan_text('token = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"')
        assert any(f.kind == "github_token" for f in findings)

    def test_ignore_placeholders(self):
        scanner = SecretsScanner(".")
        findings = scanner.scan_text('api_key = "your_api_key_here"')
        assert findings == []

    def test_scan_file(self, tmp_path: Path):
        sample = tmp_path / "config.py"
        sample.write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8")
        scanner = SecretsScanner(str(tmp_path))
        findings = scanner.scan_file(sample)
        assert any(f.kind == "aws_access_key" for f in findings)

    def test_summary_and_context(self, tmp_path: Path):
        sample = tmp_path / "bad.py"
        sample.write_text('secret = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"\n', encoding="utf-8")
        scanner = SecretsScanner(str(tmp_path))
        scanner.scan()
        assert "Potential findings:" in scanner.summary()
        assert "Findings:" in scanner.to_context()

    def test_secret_finding_format(self):
        finding = SecretFinding(
            kind="github_token",
            path="app.py",
            lineno=1,
            snippet="token = ghp_...",
        )
        assert "github_token" in finding.format()
