"""Tests for v6.95.0 VagrantAnalyzer integration."""

from pathlib import Path

from devai import DevAI, VagrantAnalyzer
from devai.project_health import ProjectHealth

HARDENED_VAGRANT = """\
# frozen_string_literal: true

Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/jammy64"
  config.vm.box_version = "20240126.0.0"
  config.vm.box_check_update = false

  config.ssh.insert_key = true
  config.ssh.forward_agent = false

  config.vm.network "forwarded_port", guest: 80, host: 8080, host_ip: "127.0.0.1"

  config.vm.provider "virtualbox" do |vb|
    vb.memory = 1024
    vb.cpus = 2
    vb.gui = false
  end

  config.vm.provision "shell", inline: <<-SHELL
    set -euo pipefail
    sudo apt-get update -y
  SHELL
end
"""

UNSAFE_VAGRANT = """\
Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/focal64:latest"
  config.vm.box_url = "http://mirror.example.com/boxes/ubuntu.box"
  config.ssh.password = "SuperSecret123!"
  config.ssh.insert_key = false
  config.ssh.forward_agent = true
  config.vagrant.plugins.auto_update = true

  config.vm.network "public_network"
  config.vm.network "forwarded_port", guest: 22, host: 2222, host_ip: "0.0.0.0"

  config.vm.provider "aws" do |aws|
    aws.access_key_id = "AKIAIOSFODNN7EXAMPLE"
    aws.secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  end

  config.vm.provider "docker" do |d|
    d.privileged = true
  end

  config.vm.provider "virtualbox" do |vb|
    vb.gui = true
  end

  config.vm.synced_folder ".", "/vagrant", type: "nfs", nfs_version: 3, nfs_udp: true

  config.vm.provision "shell", inline: <<-SHELL
    curl https://install.example.com/script.sh | bash
    export API_KEY="sk-live-1234567890abcdef"
  SHELL
end
"""


class TestVagrantAnalyzer:
    def test_finds_no_high_issues_in_hardened_config(self, tmp_path: Path):
        config = tmp_path / "Vagrantfile"
        config.write_text(HARDENED_VAGRANT, encoding="utf-8")
        analyzer = VagrantAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.stats.configs == 1
        assert analyzer.health_score() == 100.0

    def test_detects_unsafe_config(self, tmp_path: Path):
        config = tmp_path / "Vagrantfile"
        config.write_text(UNSAFE_VAGRANT, encoding="utf-8")
        analyzer = VagrantAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "ssh_password" in kinds
        assert "hardcoded_aws_key" in kinds
        assert "hardcoded_aws_secret" in kinds
        assert "hardcoded_secret" in kinds
        assert "latest_box_tag" in kinds
        assert "curl_pipe_shell" in kinds
        assert "insecure_ssh_key" in kinds
        assert "ssh_forward_agent" in kinds
        assert "public_network" in kinds
        assert "bind_all_interfaces" in kinds
        assert "insecure_box_url" in kinds
        assert "privileged_docker" in kinds
        assert "insecure_nfs" in kinds
        assert "gui_enabled" in kinds
        assert "auto_update_plugins" in kinds
        assert analyzer.stats.high_severity >= 4
        assert analyzer.health_score() < 50.0

    def test_summary_and_context(self, tmp_path: Path):
        config = tmp_path / "Vagrantfile"
        config.write_text(UNSAFE_VAGRANT, encoding="utf-8")
        analyzer = VagrantAnalyzer(str(tmp_path))
        assert "Vagrant:" in analyzer.summary()
        assert "Vagrant config analysis" in analyzer.to_context()

    def test_hardened_template(self):
        template = VagrantAnalyzer(".").generate_hardened_template()
        assert "forward_agent = false" in template
        assert "insert_key = true" in template
        assert "host_ip: \"127.0.0.1\"" in template

    def test_devai_facade(self, tmp_path: Path):
        config = tmp_path / "Vagrantfile"
        config.write_text(UNSAFE_VAGRANT, encoding="utf-8")
        ai = DevAI.mock()
        analyzer = ai.vagrant(str(tmp_path))
        assert isinstance(analyzer, VagrantAnalyzer)
        assert analyzer.stats.findings > 0

    def test_project_health_integration(self, tmp_path: Path):
        config = tmp_path / "Vagrantfile"
        config.write_text(UNSAFE_VAGRANT, encoding="utf-8")
        health = ProjectHealth(str(tmp_path)).analyze()
        names = {cat.name for cat in health.categories}
        assert "vagrant" in names
        vagrant_cat = next(cat for cat in health.categories if cat.name == "vagrant")
        assert vagrant_cat.score < 100.0
