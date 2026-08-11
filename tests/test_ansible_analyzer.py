"""Tests for AnsibleAnalyzer."""

from pathlib import Path

from devai.ansible_analyzer import AnsibleAnalyzer, AnsibleFinding


INSECURE_PLAYBOOK = """
---
- hosts: webservers
  become: yes
  tasks:
    - name: Install packages
      apt:
        name: nginx
        state: latest

    - name: Run setup script
      shell: curl -sSL https://example.com/install.sh | bash

    - name: Configure database
      ansible.builtin.template:
        src: db.conf.j2
        dest: /etc/db.conf
        mode: '0777'
      vars:
        db_password: "supersecret123"

    - name: Dangerous raw command
      raw: rm -rf /tmp/*
      ignore_errors: true
      no_log: false
"""

HARDENED_PLAYBOOK = """
---
- hosts: webservers
  become: true
  become_user: deploy
  tasks:
    - name: Install nginx
      ansible.builtin.apt:
        name: nginx=1.18.*
        state: present

    - name: Run migration
      ansible.builtin.command:
        cmd: /opt/app/bin/migrate
        creates: /var/lib/app/.migrated
      become_user: app
      no_log: true

    - name: Deploy config
      ansible.builtin.template:
        src: app.conf.j2
        dest: /etc/app/app.conf
        mode: "0640"
      vars:
        app_password: "{{ vault_app_password }}"
"""


def _write_playbook(tmp_path: Path, content: str, name: str = "site.yml") -> Path:
    ansible_dir = tmp_path / "ansible"
    ansible_dir.mkdir(parents=True)
    path = ansible_dir / name
    path.write_text(content, encoding="utf-8")
    return path


class TestAnsibleAnalyzer:
    def test_no_playbooks_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = AnsibleAnalyzer(str(tmp_path))
        assert analyzer.stats.files == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_playbook(self, tmp_path: Path):
        _write_playbook(tmp_path, INSECURE_PLAYBOOK)
        analyzer = AnsibleAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "curl_pipe_shell" in kinds
        assert "world_writable_mode" in kinds
        assert "raw_module" in kinds
        assert analyzer.stats.files == 1
        assert analyzer.health_score() < 50.0

    def test_hardened_playbook_scores_well(self, tmp_path: Path):
        _write_playbook(tmp_path, HARDENED_PLAYBOOK)
        analyzer = AnsibleAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)
        assert analyzer.stats.playbooks >= 1

    def test_summary_context_and_template(self, tmp_path: Path):
        _write_playbook(tmp_path, HARDENED_PLAYBOOK)
        analyzer = AnsibleAnalyzer(str(tmp_path))
        assert "Ansible" in analyzer.summary()
        assert "Ansible analysis" in analyzer.to_context()
        snippet = analyzer.generate_hardened_task_snippet()
        assert "no_log: true" in snippet
        assert "creates:" in snippet

    def test_finding_format(self):
        finding = AnsibleFinding(
            kind="hardcoded_secret",
            severity="high",
            message="test",
            path="ansible/site.yml",
            lineno=10,
        )
        assert "high" in finding.format()
        assert "site.yml" in finding.format()
