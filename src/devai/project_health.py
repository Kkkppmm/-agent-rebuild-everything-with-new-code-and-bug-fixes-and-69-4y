"""ProjectHealth — unified project health dashboard for developers."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from devai.api_surface import APISurfaceAnalyzer
from devai.code_metrics import CodeMetrics
from devai.code_smells import CodeSmellDetector
from devai.complexity_hotspots import ComplexityHotspotAnalyzer
from devai.exception_analyzer import ExceptionHierarchyAnalyzer
from devai.module_coupling import ModuleCouplingAnalyzer
from devai.deps_parser import DependencyParser
from devai.env_vars import EnvVarAnalyzer
from devai.gitignore_analyzer import GitignoreAnalyzer
from devai.dockerfile_analyzer import DockerfileAnalyzer
from devai.workflow_analyzer import WorkflowAnalyzer
from devai.compose_analyzer import ComposeAnalyzer
from devai.precommit_analyzer import PrecommitAnalyzer
from devai.makefile_analyzer import MakefileAnalyzer
from devai.kubernetes_analyzer import KubernetesAnalyzer
from devai.terraform_analyzer import TerraformAnalyzer
from devai.nginx_analyzer import NginxAnalyzer
from devai.helm_analyzer import HelmAnalyzer
from devai.ansible_analyzer import AnsibleAnalyzer
from devai.jenkinsfile_analyzer import JenkinsfileAnalyzer
from devai.gitlab_ci_analyzer import GitLabCIAnalyzer
from devai.circleci_analyzer import CircleCIAnalyzer
from devai.bitbucket_pipelines_analyzer import BitbucketPipelinesAnalyzer
from devai.azure_pipelines_analyzer import AzurePipelinesAnalyzer
from devai.travis_ci_analyzer import TravisCIAnalyzer
from devai.buildkite_analyzer import BuildkiteAnalyzer
from devai.drone_ci_analyzer import DroneCIAnalyzer
from devai.woodpecker_ci_analyzer import WoodpeckerCIAnalyzer
from devai.codefresh_analyzer import CodefreshAnalyzer
from devai.semaphore_ci_analyzer import SemaphoreCIAnalyzer
from devai.concourse_ci_analyzer import ConcourseCIAnalyzer
from devai.teamcity_analyzer import TeamCityAnalyzer
from devai.cloud_build_analyzer import CloudBuildAnalyzer
from devai.argo_workflows_analyzer import ArgoWorkflowsAnalyzer
from devai.tekton_analyzer import TektonAnalyzer
from devai.flux_cd_analyzer import FluxCDAnalyzer
from devai.argocd_analyzer import ArgoCDAnalyzer
from devai.aws_codebuild_analyzer import AWSCodeBuildAnalyzer
from devai.harness_ci_analyzer import HarnessCIAnalyzer
from devai.buddy_ci_analyzer import BuddyCIAnalyzer
from devai.appveyor_ci_analyzer import AppVeyorCIAnalyzer
from devai.gocd_ci_analyzer import GoCDCIAnalyzer
from devai.docstring_coverage import DocstringCoverage
from devai.project import DEFAULT_IGNORE_DIRS
from devai.secrets import SecretsScanner
from devai.tech_debt import TechDebtScanner
from devai.test_mapper import TestMapper
from devai.typing_coverage import TypingCoverage


@dataclass
class HealthCategory:
    """Score and summary for one health dimension."""

    name: str
    score: float
    summary: str
    details: dict = field(default_factory=dict)


@dataclass
class ProjectHealthReport:
    """Aggregate project health report."""

    root: str
    overall_score: float
    categories: list[HealthCategory] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    def summary(self) -> str:
        """Return a human-readable summary."""
        lines = [
            f"Project health: {self.overall_score:.0f}/100",
            f"Root: {self.root}",
            "",
        ]
        for cat in self.categories:
            lines.append(f"  {cat.name}: {cat.score:.0f}/100 — {cat.summary}")
        if self.recommendations:
            lines.append("")
            lines.append("Recommendations:")
            for rec in self.recommendations:
                lines.append(f"  - {rec}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        """Export as a JSON-serializable dict."""
        return {
            "root": self.root,
            "overall_score": self.overall_score,
            "categories": [
                {
                    "name": c.name,
                    "score": c.score,
                    "summary": c.summary,
                    "details": c.details,
                }
                for c in self.categories
            ],
            "recommendations": self.recommendations,
        }

    def to_json(self, indent: int = 2) -> str:
        """Export as formatted JSON."""
        return json.dumps(self.to_dict(), indent=indent)

    def to_markdown(self) -> str:
        """Export as a Markdown report."""
        lines = [
            "# Project Health Report",
            "",
            f"**Overall score:** {self.overall_score:.0f}/100",
            f"**Root:** `{self.root}`",
            "",
            "## Categories",
            "",
            "| Category | Score | Summary |",
            "|----------|-------|---------|",
        ]
        for cat in self.categories:
            safe_summary = cat.summary.replace("|", "\\|")
            lines.append(f"| {cat.name} | {cat.score:.0f} | {safe_summary} |")
        if self.recommendations:
            lines.extend(["", "## Recommendations", ""])
            for rec in self.recommendations:
                lines.append(f"- {rec}")
        return "\n".join(lines)


class ProjectHealth:
    """Run static analysis across a project and produce a unified health report.

    Combines code metrics, typing coverage, docstring coverage, test mapping,
    dependency hygiene, and secrets scanning into a single developer dashboard.
    """

    WEIGHTS = {
        "metrics": 0.06,
        "typing": 0.13,
        "docstrings": 0.09,
        "tests": 0.16,
        "dependencies": 0.06,
        "secrets": 0.09,
        "smells": 0.08,
        "tech_debt": 0.07,
        "api_surface": 0.07,
        "hotspots": 0.05,
        "exceptions": 0.06,
        "coupling": 0.06,
        "env": 0.04,
        "gitignore": 0.04,
        "dockerfile": 0.03,
        "workflows": 0.03,
        "compose": 0.03,
        "precommit": 0.03,
        "makefile": 0.02,
        "kubernetes": 0.02,
        "terraform": 0.02,
        "nginx": 0.02,
        "helm": 0.02,
        "ansible": 0.02,
        "jenkins": 0.02,
        "gitlab_ci": 0.02,
        "circleci": 0.02,
        "bitbucket_pipelines": 0.02,
        "azure_pipelines": 0.02,
        "travis_ci": 0.02,
        "buildkite": 0.02,
        "drone_ci": 0.02,
        "woodpecker_ci": 0.02,
        "codefresh": 0.02,
        "semaphore_ci": 0.02,
        "concourse_ci": 0.02,
        "teamcity": 0.02,
        "cloud_build": 0.02,
        "tekton": 0.02,
        "argo_workflows": 0.02,
        "flux_cd": 0.02,
        "argocd": 0.02,
        "aws_codebuild": 0.02,
        "harness_ci": 0.02,
        "buddy_ci": 0.02,
        "appveyor_ci": 0.02,
        "gocd_ci": 0.02,
    }

    def __init__(
        self,
        root: str,
        *,
        source_dir: str = "src",
        test_dir: str = "tests",
        complexity_threshold: int = 10,
        ignore_dirs: set[str] | None = None,
        scan_secrets: bool = True,
    ) -> None:
        self.root = Path(root)
        self.source_dir = source_dir
        self.test_dir = test_dir
        self.complexity_threshold = complexity_threshold
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self.scan_secrets = scan_secrets
        self._report: ProjectHealthReport | None = None

    def _score_complexity(self, metrics: CodeMetrics) -> tuple[float, str, dict]:
        metrics.analyze()
        project = metrics.project
        high = metrics.high_complexity()
        if project.total_functions == 0:
            return 100.0, "No functions to analyze", {"high_complexity": 0}

        ratio = len(high) / project.total_functions
        score = max(0.0, 100.0 - ratio * 200.0)
        summary = (
            f"avg complexity {project.avg_complexity}, "
            f"{len(high)} high-complexity functions"
        )
        return round(score, 1), summary, {
            "avg_complexity": project.avg_complexity,
            "max_complexity": project.max_complexity,
            "high_complexity_count": len(high),
            "total_functions": project.total_functions,
            "total_sloc": project.total_sloc,
        }

    def _score_typing(self, typing: TypingCoverage) -> tuple[float, str, dict]:
        typing.analyze()
        pct = typing.coverage_pct()
        stats = typing.stats
        summary = f"{pct}% fully typed ({stats.fully_typed}/{stats.total_functions})"
        return pct, summary, {
            "coverage_pct": pct,
            "fully_typed": stats.fully_typed,
            "partially_typed": stats.partially_typed,
            "untyped": stats.untyped,
            "gaps": len(typing._gaps),
        }

    def _score_docstrings(self, docstrings: DocstringCoverage) -> tuple[float, str, dict]:
        docstrings.analyze()
        pct = docstrings.coverage_pct()
        stats = docstrings.stats
        summary = f"{pct}% documented ({stats.documented}/{stats.total_items})"
        return pct, summary, {
            "coverage_pct": pct,
            "documented": stats.documented,
            "undocumented": stats.undocumented,
            "gaps": len(docstrings._gaps),
        }

    def _score_tests(self, mapper: TestMapper) -> tuple[float, str, dict]:
        report = mapper.map()
        pct = report.coverage_pct
        summary = f"{pct}% modules have tests ({report.tested}/{report.total_modules})"
        return pct, summary, {
            "coverage_pct": pct,
            "tested": report.tested,
            "total_modules": report.total_modules,
            "untested_count": len(report.untested),
        }

    def _score_dependencies(self, deps: DependencyParser) -> tuple[float, str, dict]:
        all_deps = deps.parse()
        if not all_deps:
            return 100.0, "No dependencies declared", {"total": 0}

        unpinned = deps.unpinned()
        dupes = deps.duplicates()
        unpinned_ratio = len(unpinned) / len(all_deps)
        dupe_penalty = min(30.0, len(dupes) * 10.0)
        score = max(0.0, 100.0 - unpinned_ratio * 70.0 - dupe_penalty)
        summary = f"{len(all_deps)} deps, {len(unpinned)} unpinned, {len(dupes)} duplicates"
        return round(score, 1), summary, {
            "total": len(all_deps),
            "unpinned": len(unpinned),
            "duplicates": len(dupes),
        }

    def _score_secrets(self, scanner: SecretsScanner) -> tuple[float, str, dict]:
        findings = scanner.scan()
        if not findings:
            return 100.0, "No potential secrets found", {"findings": 0}
        high = sum(1 for f in findings if f.confidence == "high")
        penalty = min(100.0, len(findings) * 15.0 + high * 10.0)
        score = max(0.0, 100.0 - penalty)
        summary = f"{len(findings)} potential secrets ({high} high confidence)"
        return round(score, 1), summary, {
            "findings": len(findings),
            "high_confidence": high,
        }

    def _score_smells(self, detector: CodeSmellDetector) -> tuple[float, str, dict]:
        smells = detector.analyze()
        score = detector.health_score()
        stats = detector.stats
        high = sum(1 for s in smells if s.severity == "high")
        summary = f"{len(smells)} smells ({high} high severity)"
        return score, summary, {
            "total_smells": len(smells),
            "high_severity": high,
            "by_kind": stats.by_kind,
            "density": stats.smell_density,
        }

    def _score_gitignore(self, analyzer: GitignoreAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        high = sum(1 for g in analyzer._gaps if g.severity == "high")
        summary = (
            f"{stats.covered}/{stats.recommended} patterns covered, "
            f"{stats.gaps} gap(s)"
        )
        return score, summary, {
            "patterns": stats.patterns,
            "covered": stats.covered,
            "recommended": stats.recommended,
            "gaps": stats.gaps,
            "exposed_files": stats.exposed_files,
            "high_severity": high,
        }

    def _score_dockerfile(self, analyzer: DockerfileAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.dockerfiles == 0:
            return 100.0, "No Dockerfiles found", {"dockerfiles": 0, "findings": 0}
        summary = (
            f"{stats.dockerfiles} Dockerfile(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "dockerfiles": stats.dockerfiles,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_workflows(self, analyzer: WorkflowAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.workflows == 0:
            return 100.0, "No GitHub Actions workflows found", {"workflows": 0, "findings": 0}
        summary = (
            f"{stats.workflows} workflow(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "workflows": stats.workflows,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_compose(self, analyzer: ComposeAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.compose_files == 0:
            return 100.0, "No Docker Compose files found", {"compose_files": 0, "findings": 0}
        summary = (
            f"{stats.compose_files} Compose file(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "compose_files": stats.compose_files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_precommit(self, analyzer: PrecommitAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.config_files == 0:
            return 100.0, "No pre-commit config found", {"config_files": 0, "findings": 0}
        summary = (
            f"{stats.config_files} config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "config_files": stats.config_files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_makefile(self, analyzer: MakefileAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.makefiles == 0:
            return 100.0, "No Makefiles found", {"makefiles": 0, "findings": 0}
        summary = (
            f"{stats.makefiles} Makefile(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "makefiles": stats.makefiles,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_kubernetes(self, analyzer: KubernetesAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.manifests == 0:
            return 100.0, "No Kubernetes manifests found", {"manifests": 0, "findings": 0}
        summary = (
            f"{stats.manifests} manifest(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "manifests": stats.manifests,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_terraform(self, analyzer: TerraformAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.terraform_files == 0:
            return 100.0, "No Terraform files found", {"terraform_files": 0, "findings": 0}
        summary = (
            f"{stats.terraform_files} Terraform file(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "terraform_files": stats.terraform_files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_nginx(self, analyzer: NginxAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Nginx configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Nginx config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_helm(self, analyzer: HelmAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.charts == 0:
            return 100.0, "No Helm charts found", {"charts": 0, "findings": 0}
        summary = (
            f"{stats.charts} Helm chart(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "charts": stats.charts,
            "files": stats.files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_ansible(self, analyzer: AnsibleAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.files == 0:
            return 100.0, "No Ansible playbooks found", {"playbooks": 0, "findings": 0}
        summary = (
            f"{stats.playbooks} Ansible playbook(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "playbooks": stats.playbooks,
            "files": stats.files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_jenkins(self, analyzer: JenkinsfileAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.pipelines == 0:
            return 100.0, "No Jenkins pipelines found", {"pipelines": 0, "findings": 0}
        summary = (
            f"{stats.pipelines} Jenkins pipeline(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "pipelines": stats.pipelines,
            "files": stats.files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_gitlab_ci(self, analyzer: GitLabCIAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.pipelines == 0:
            return 100.0, "No GitLab CI pipelines found", {"pipelines": 0, "findings": 0}
        summary = (
            f"{stats.pipelines} GitLab CI pipeline(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "pipelines": stats.pipelines,
            "files": stats.files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_circleci(self, analyzer: CircleCIAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.pipelines == 0:
            return 100.0, "No CircleCI configs found", {"pipelines": 0, "findings": 0}
        summary = (
            f"{stats.pipelines} CircleCI config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "pipelines": stats.pipelines,
            "files": stats.files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_bitbucket_pipelines(
        self, analyzer: BitbucketPipelinesAnalyzer
    ) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.pipelines == 0:
            return 100.0, "No Bitbucket Pipelines found", {"pipelines": 0, "findings": 0}
        summary = (
            f"{stats.pipelines} Bitbucket Pipelines file(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "pipelines": stats.pipelines,
            "files": stats.files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_azure_pipelines(
        self, analyzer: AzurePipelinesAnalyzer
    ) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.pipelines == 0:
            return 100.0, "No Azure Pipelines found", {"pipelines": 0, "findings": 0}
        summary = (
            f"{stats.pipelines} Azure Pipelines file(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "pipelines": stats.pipelines,
            "files": stats.files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_travis_ci(self, analyzer: TravisCIAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Travis CI configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Travis CI config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "files": stats.files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_buildkite(self, analyzer: BuildkiteAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.pipelines == 0:
            return 100.0, "No Buildkite pipelines found", {"pipelines": 0, "findings": 0}
        summary = (
            f"{stats.pipelines} Buildkite pipeline(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "pipelines": stats.pipelines,
            "files": stats.files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_drone_ci(self, analyzer: DroneCIAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.pipelines == 0:
            return 100.0, "No Drone CI pipelines found", {"pipelines": 0, "findings": 0}
        summary = (
            f"{stats.pipelines} Drone CI pipeline(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "pipelines": stats.pipelines,
            "files": stats.files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_woodpecker_ci(self, analyzer: WoodpeckerCIAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.pipelines == 0:
            return 100.0, "No Woodpecker CI pipelines found", {"pipelines": 0, "findings": 0}
        summary = (
            f"{stats.pipelines} Woodpecker CI pipeline(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "pipelines": stats.pipelines,
            "files": stats.files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_codefresh(self, analyzer: CodefreshAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.pipelines == 0:
            return 100.0, "No Codefresh pipelines found", {"pipelines": 0, "findings": 0}
        summary = (
            f"{stats.pipelines} Codefresh pipeline(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "pipelines": stats.pipelines,
            "files": stats.files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_semaphore_ci(self, analyzer: SemaphoreCIAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.pipelines == 0:
            return 100.0, "No Semaphore CI pipelines found", {"pipelines": 0, "findings": 0}
        summary = (
            f"{stats.pipelines} Semaphore CI pipeline(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "pipelines": stats.pipelines,
            "files": stats.files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_concourse_ci(self, analyzer: ConcourseCIAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.pipelines == 0:
            return 100.0, "No Concourse CI pipelines found", {"pipelines": 0, "findings": 0}
        summary = (
            f"{stats.pipelines} Concourse CI pipeline(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "pipelines": stats.pipelines,
            "files": stats.files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_teamcity(self, analyzer: TeamCityAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.pipelines == 0:
            return 100.0, "No TeamCity configs found", {"pipelines": 0, "findings": 0}
        summary = (
            f"{stats.pipelines} TeamCity config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "pipelines": stats.pipelines,
            "files": stats.files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_cloud_build(self, analyzer: CloudBuildAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.pipelines == 0:
            return 100.0, "No Cloud Build configs found", {"pipelines": 0, "findings": 0}
        summary = (
            f"{stats.pipelines} Cloud Build config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "pipelines": stats.pipelines,
            "files": stats.files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_tekton(self, analyzer: TektonAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.pipelines == 0:
            return 100.0, "No Tekton configs found", {"pipelines": 0, "findings": 0}
        summary = (
            f"{stats.pipelines} Tekton config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "pipelines": stats.pipelines,
            "files": stats.files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_argo_workflows(
        self, analyzer: ArgoWorkflowsAnalyzer
    ) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.workflows == 0:
            return 100.0, "No Argo Workflows configs found", {"workflows": 0, "findings": 0}
        summary = (
            f"{stats.workflows} Argo Workflows config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "workflows": stats.workflows,
            "files": stats.files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_flux_cd(self, analyzer: FluxCDAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.manifests == 0:
            return 100.0, "No Flux CD manifests found", {"manifests": 0, "findings": 0}
        summary = (
            f"{stats.manifests} Flux CD manifest(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "manifests": stats.manifests,
            "files": stats.files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_argocd(self, analyzer: ArgoCDAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.applications == 0:
            return 100.0, "No Argo CD applications found", {"applications": 0, "findings": 0}
        summary = (
            f"{stats.applications} Argo CD application(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "applications": stats.applications,
            "files": stats.files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_aws_codebuild(self, analyzer: AWSCodeBuildAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.buildspecs == 0:
            return 100.0, "No AWS CodeBuild buildspecs found", {"buildspecs": 0, "findings": 0}
        summary = (
            f"{stats.buildspecs} AWS CodeBuild buildspec(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "buildspecs": stats.buildspecs,
            "files": stats.files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_harness_ci(self, analyzer: HarnessCIAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.pipelines == 0:
            return 100.0, "No Harness CI pipelines found", {"pipelines": 0, "findings": 0}
        summary = (
            f"{stats.pipelines} Harness CI pipeline(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "pipelines": stats.pipelines,
            "files": stats.files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_buddy_ci(self, analyzer: BuddyCIAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.pipelines == 0:
            return 100.0, "No Buddy CI pipelines found", {"pipelines": 0, "findings": 0}
        summary = (
            f"{stats.pipelines} Buddy CI pipeline(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "pipelines": stats.pipelines,
            "files": stats.files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_gocd_ci(self, analyzer: GoCDCIAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.pipelines == 0:
            return 100.0, "No GoCD CI pipelines found", {"pipelines": 0, "findings": 0}
        summary = (
            f"{stats.pipelines} GoCD CI pipeline(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "pipelines": stats.pipelines,
            "files": stats.files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_appveyor_ci(self, analyzer: AppVeyorCIAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No AppVeyor CI configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} AppVeyor CI config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "files": stats.files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_env(self, analyzer: EnvVarAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        high = sum(1 for g in analyzer._gaps if g.severity == "high")
        summary = (
            f"{stats.referenced} referenced, {stats.example_vars} in .env.example, "
            f"{stats.gaps} gap(s)"
        )
        return score, summary, {
            "referenced": stats.referenced,
            "example_vars": stats.example_vars,
            "gaps": stats.gaps,
            "high_severity": high,
        }

    def _score_tech_debt(self, scanner: TechDebtScanner) -> tuple[float, str, dict]:
        items = scanner.scan()
        score = scanner.health_score()
        stats = scanner.stats
        critical = sum(1 for i in items if i.marker in ("FIXME", "BUG", "HACK"))
        summary = f"{len(items)} markers in {stats.files_with_debt} files ({critical} critical)"
        return score, summary, {
            "total_items": len(items),
            "files_with_debt": stats.files_with_debt,
            "critical": critical,
            "by_marker": stats.by_marker,
        }

    def _build_recommendations(self, categories: list[HealthCategory]) -> list[str]:
        recs: list[str] = []
        for cat in categories:
            if cat.name == "typing" and cat.score < 80:
                recs.append("Add type hints to untyped functions to improve maintainability")
            elif cat.name == "docstrings" and cat.score < 70:
                recs.append("Document public functions, methods, and classes with docstrings")
            elif cat.name == "tests" and cat.score < 60:
                untested = cat.details.get("untested_count", 0)
                if untested:
                    recs.append(f"Add tests for {untested} untested module(s)")
            elif cat.name == "metrics" and cat.details.get("high_complexity_count", 0) > 0:
                recs.append(
                    "Refactor high-complexity functions to reduce cyclomatic complexity"
                )
            elif cat.name == "dependencies" and cat.details.get("unpinned", 0) > 0:
                recs.append("Pin unpinned dependencies with exact versions for reproducibility")
            elif cat.name == "secrets" and cat.details.get("findings", 0) > 0:
                recs.append("Review and remove hardcoded secrets; use environment variables")
            elif cat.name == "smells" and cat.details.get("high_severity", 0) > 0:
                recs.append("Refactor high-severity code smells (deep nesting, bare except, god classes)")
            elif cat.name == "tech_debt" and cat.details.get("critical", 0) > 0:
                recs.append("Address critical tech-debt markers (FIXME, BUG, HACK) before release")
            elif cat.name == "api_surface" and cat.score < 70:
                recs.append("Document public API symbols and declare __all__ in package modules")
            elif cat.name == "hotspots" and cat.details.get("hotspots", 0) > 0:
                recs.append("Refactor complexity hotspots — start with the highest-scoring files")
            elif cat.name == "exceptions" and cat.details.get("bare_except", 0) > 0:
                recs.append("Replace bare except handlers with specific exception types")
            elif cat.name == "coupling" and cat.details.get("circular_imports", 0) > 0:
                recs.append("Break circular import chains to improve module stability")
            elif cat.name == "env" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Sync .env.example with code — add missing env vars referenced in source"
                )
            elif cat.name == "gitignore" and cat.details.get("exposed_files", 0) > 0:
                recs.append(
                    "Add .gitignore rules for sensitive files (.env, keys) present in the repo"
                )
            elif cat.name == "gitignore" and cat.score < 70:
                recs.append(
                    "Improve .gitignore coverage — add recommended patterns for your stack"
                )
            elif cat.name == "dockerfile" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Dockerfiles — add non-root USER, pin base images, and remove secrets from ENV"
                )
            elif cat.name == "dockerfile" and cat.score < 70 and cat.details.get("dockerfiles", 0) > 0:
                recs.append(
                    "Review Dockerfile findings — prefer COPY over ADD and avoid curl-pipe-to-shell"
                )
            elif cat.name == "workflows" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden GitHub Actions workflows — pin actions to SHAs and avoid pull_request_target"
                )
            elif cat.name == "workflows" and cat.score < 70 and cat.details.get("workflows", 0) > 0:
                recs.append(
                    "Review workflow findings — restrict permissions and avoid secrets in env blocks"
                )
            elif cat.name == "compose" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Docker Compose files — avoid privileged mode, host mounts, and secrets in environment"
                )
            elif cat.name == "compose" and cat.score < 70 and cat.details.get("compose_files", 0) > 0:
                recs.append(
                    "Review Compose findings — pin images, set resource limits, and run services as non-root"
                )
            elif cat.name == "precommit" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden pre-commit config — pin hook revisions and avoid curl-pipe-to-shell entries"
                )
            elif cat.name == "precommit" and cat.score < 70 and cat.details.get("config_files", 0) > 0:
                recs.append(
                    "Review pre-commit findings — pin repos to tags/SHAs and audit local hooks"
                )
            elif cat.name == "makefile" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Makefiles — avoid curl-pipe-to-shell, chmod 777, and secrets in variables"
                )
            elif cat.name == "kubernetes" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Kubernetes manifests — disable privileged mode and run as non-root"
                )
            elif cat.name == "terraform" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Terraform — restrict security groups, enable encryption, and use secret manager"
                )
            elif cat.name == "nginx" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Nginx — use TLSv1.2+, enable HSTS, and verify upstream TLS"
                )
            elif cat.name == "helm" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Helm charts — disable privileged mode, pin image tags, and use secrets for credentials"
                )
            elif cat.name == "ansible" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Ansible playbooks — use Vault for secrets, avoid raw/shell pipes, and set restrictive file modes"
                )
            elif cat.name == "jenkins" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Jenkins pipelines — use credentials store, single-quoted sh steps, and labeled agents"
                )
            elif cat.name == "gitlab_ci" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden GitLab CI — use CI/CD variables, pin images, and restrict merge request token scope"
                )
            elif cat.name == "circleci" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden CircleCI — pin orbs, use contexts for secrets, and restrict setup_remote_docker"
                )
            elif cat.name == "bitbucket_pipelines" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Bitbucket Pipelines — use repository variables, pin images, and restrict fork PR secrets"
                )
            elif cat.name == "azure_pipelines" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Azure Pipelines — use variable groups/Key Vault, pin tasks, and restrict fork PR secrets"
                )
            elif cat.name == "travis_ci" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Travis CI — use encrypted env vars, pin language versions, and avoid curl-pipe-to-shell"
                )
            elif cat.name == "buildkite" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Buildkite — use secrets, pin plugins, and restrict propagate_environment"
                )
            elif cat.name == "drone_ci" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Drone CI — use secrets, avoid trusted mode, and restrict privileged containers"
                )
            elif cat.name == "woodpecker_ci" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Woodpecker CI — use secrets, avoid trusted mode, and restrict privileged containers"
                )
            elif cat.name == "codefresh" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Codefresh — use encrypted variables, restrict deploy steps, and avoid privileged containers"
                )
            elif cat.name == "semaphore_ci" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Semaphore CI — use secrets, restrict auto-promote rules, and avoid privileged containers"
                )
            elif cat.name == "concourse_ci" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Concourse CI — use credentials manager, avoid privileged tasks, and pin image tags"
                )
            elif cat.name == "teamcity" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden TeamCity — use credentials manager, restrict VCS triggers, and avoid privileged containers"
                )
            elif cat.name == "cloud_build" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Cloud Build — use Secret Manager, dedicated service accounts, and avoid privileged containers"
                )
            elif cat.name == "tekton" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Tekton — use Kubernetes secrets, runAsNonRoot, and avoid hostPath/docker socket mounts"
                )
            elif cat.name == "argo_workflows" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Argo Workflows — use Kubernetes secrets, runAsNonRoot, and avoid hostNetwork/hostPID"
                )
            elif cat.name == "flux_cd" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Flux CD — use HTTPS git sources, enable prune/wait, and avoid force apply or cluster-admin RBAC"
                )
            elif cat.name == "argocd" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Argo CD — pin targetRevision, restrict destination namespaces, enable prune/selfHeal, and avoid wildcard destinations"
                )
            elif cat.name == "aws_codebuild" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden AWS CodeBuild — use Secrets Manager/SSM, enable artifact encryption, and avoid privileged Docker"
                )
            elif cat.name == "harness_ci" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Harness CI — use Secret Manager references, runAsNonRoot, disable automountServiceAccountToken, and avoid privileged containers"
                )
            elif cat.name == "buddy_ci" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Buddy CI — use encrypted variables/vault, pin Docker image tags, disable docker_privileged_mode, and sanitize Buddy variables in scripts"
                )
            elif cat.name == "appveyor_ci" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden AppVeyor CI — use encrypted variables, disable enable_rdp, pin version/stack, and sanitize APPVEYOR_* variables in scripts"
                )
            elif cat.name == "gocd_ci" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden GoCD CI — use secure_variables, pin container image tags, disable privileged/host network, and sanitize GO_* variables in tasks"
                )
        return recs

    def analyze(self) -> ProjectHealthReport:
        """Run all analyzers and return a unified health report."""
        if self._report is not None:
            return self._report

        root_str = str(self.root)
        categories: list[HealthCategory] = []

        metrics = CodeMetrics(
            root_str,
            complexity_threshold=self.complexity_threshold,
            ignore_dirs=self.ignore_dirs,
        )
        score, summary, details = self._score_complexity(metrics)
        categories.append(HealthCategory("metrics", score, summary, details))

        typing = TypingCoverage(root_str, ignore_dirs=self.ignore_dirs)
        score, summary, details = self._score_typing(typing)
        categories.append(HealthCategory("typing", score, summary, details))

        docstrings = DocstringCoverage(root_str, ignore_dirs=self.ignore_dirs)
        score, summary, details = self._score_docstrings(docstrings)
        categories.append(HealthCategory("docstrings", score, summary, details))

        mapper = TestMapper(
            root_str,
            source_dir=self.source_dir,
            test_dir=self.test_dir,
            ignore_dirs=self.ignore_dirs,
        )
        score, summary, details = self._score_tests(mapper)
        categories.append(HealthCategory("tests", score, summary, details))

        deps = DependencyParser(root_str)
        score, summary, details = self._score_dependencies(deps)
        categories.append(HealthCategory("dependencies", score, summary, details))

        if self.scan_secrets:
            scanner = SecretsScanner(root_str, ignore_dirs=self.ignore_dirs)
            score, summary, details = self._score_secrets(scanner)
            categories.append(HealthCategory("secrets", score, summary, details))

        smells = CodeSmellDetector(root_str, ignore_dirs=self.ignore_dirs)
        score, summary, details = self._score_smells(smells)
        categories.append(HealthCategory("smells", score, summary, details))

        debt = TechDebtScanner(root_str, ignore_dirs=self.ignore_dirs)
        score, summary, details = self._score_tech_debt(debt)
        categories.append(HealthCategory("tech_debt", score, summary, details))

        api = APISurfaceAnalyzer(root_str, source_dir=self.source_dir, ignore_dirs=self.ignore_dirs)
        api.analyze()
        api_score = api.health_score()
        api_stats = api.stats
        api_summary = (
            f"{api_stats.public_symbols} public symbols, "
            f"{api_stats.coverage_pct}% documented"
        )
        categories.append(
            HealthCategory(
                "api_surface",
                api_score,
                api_summary,
                {
                    "public_symbols": api_stats.public_symbols,
                    "documented": api_stats.documented,
                    "undocumented": api_stats.undocumented,
                    "coverage_pct": api_stats.coverage_pct,
                },
            )
        )

        hotspots = ComplexityHotspotAnalyzer(
            root_str,
            complexity_threshold=self.complexity_threshold,
            ignore_dirs=self.ignore_dirs,
        )
        hotspots.analyze()
        hs_score = hotspots.health_score()
        hs_stats = hotspots.stats
        hs_summary = (
            f"{hs_stats.hotspots} hotspot files, "
            f"{hs_stats.total_high_complexity} high-complexity functions"
        )
        categories.append(
            HealthCategory(
                "hotspots",
                hs_score,
                hs_summary,
                {
                    "hotspots": hs_stats.hotspots,
                    "total_high_complexity": hs_stats.total_high_complexity,
                    "worst_score": hs_stats.worst_score,
                },
            )
        )

        exc_analyzer = ExceptionHierarchyAnalyzer(root_str, ignore_dirs=self.ignore_dirs)
        exc_analyzer.analyze()
        exc_score = exc_analyzer.health_score()
        exc_stats = exc_analyzer.stats
        exc_summary = (
            f"{exc_stats.custom_exceptions} custom exceptions, "
            f"{exc_stats.broad_handlers} risky handlers"
        )
        categories.append(
            HealthCategory(
                "exceptions",
                exc_score,
                exc_summary,
                {
                    "custom_exceptions": exc_stats.custom_exceptions,
                    "broad_handlers": exc_stats.broad_handlers,
                    "bare_except": exc_stats.bare_except,
                },
            )
        )

        coupling = ModuleCouplingAnalyzer(root_str, ignore_dirs=self.ignore_dirs)
        coupling.analyze()
        coup_score = coupling.health_score()
        coup_stats = coupling.stats
        coup_summary = (
            f"{coup_stats.total_modules} modules, "
            f"{coup_stats.circular_imports} circular imports"
        )
        categories.append(
            HealthCategory(
                "coupling",
                coup_score,
                coup_summary,
                {
                    "total_modules": coup_stats.total_modules,
                    "avg_instability": coup_stats.avg_instability,
                    "circular_imports": coup_stats.circular_imports,
                    "highly_coupled": coup_stats.highly_coupled,
                },
            )
        )

        env_analyzer = EnvVarAnalyzer(root_str, ignore_dirs=self.ignore_dirs)
        score, summary, details = self._score_env(env_analyzer)
        categories.append(HealthCategory("env", score, summary, details))

        gitignore = GitignoreAnalyzer(root_str)
        score, summary, details = self._score_gitignore(gitignore)
        categories.append(HealthCategory("gitignore", score, summary, details))

        dockerfile = DockerfileAnalyzer(root_str)
        score, summary, details = self._score_dockerfile(dockerfile)
        categories.append(HealthCategory("dockerfile", score, summary, details))

        workflows = WorkflowAnalyzer(root_str)
        score, summary, details = self._score_workflows(workflows)
        categories.append(HealthCategory("workflows", score, summary, details))

        compose = ComposeAnalyzer(root_str)
        score, summary, details = self._score_compose(compose)
        categories.append(HealthCategory("compose", score, summary, details))

        precommit = PrecommitAnalyzer(root_str)
        score, summary, details = self._score_precommit(precommit)
        categories.append(HealthCategory("precommit", score, summary, details))

        makefile = MakefileAnalyzer(root_str)
        score, summary, details = self._score_makefile(makefile)
        categories.append(HealthCategory("makefile", score, summary, details))

        kubernetes = KubernetesAnalyzer(root_str)
        score, summary, details = self._score_kubernetes(kubernetes)
        categories.append(HealthCategory("kubernetes", score, summary, details))

        terraform = TerraformAnalyzer(root_str)
        score, summary, details = self._score_terraform(terraform)
        categories.append(HealthCategory("terraform", score, summary, details))

        nginx = NginxAnalyzer(root_str)
        score, summary, details = self._score_nginx(nginx)
        categories.append(HealthCategory("nginx", score, summary, details))

        helm = HelmAnalyzer(root_str)
        score, summary, details = self._score_helm(helm)
        categories.append(HealthCategory("helm", score, summary, details))

        ansible = AnsibleAnalyzer(root_str)
        score, summary, details = self._score_ansible(ansible)
        categories.append(HealthCategory("ansible", score, summary, details))

        jenkins = JenkinsfileAnalyzer(root_str)
        score, summary, details = self._score_jenkins(jenkins)
        categories.append(HealthCategory("jenkins", score, summary, details))

        gitlab_ci = GitLabCIAnalyzer(root_str)
        score, summary, details = self._score_gitlab_ci(gitlab_ci)
        categories.append(HealthCategory("gitlab_ci", score, summary, details))

        circleci = CircleCIAnalyzer(root_str)
        score, summary, details = self._score_circleci(circleci)
        categories.append(HealthCategory("circleci", score, summary, details))

        bitbucket_pipelines = BitbucketPipelinesAnalyzer(root_str)
        score, summary, details = self._score_bitbucket_pipelines(bitbucket_pipelines)
        categories.append(HealthCategory("bitbucket_pipelines", score, summary, details))

        azure_pipelines = AzurePipelinesAnalyzer(root_str)
        score, summary, details = self._score_azure_pipelines(azure_pipelines)
        categories.append(HealthCategory("azure_pipelines", score, summary, details))

        travis_ci = TravisCIAnalyzer(root_str)
        score, summary, details = self._score_travis_ci(travis_ci)
        categories.append(HealthCategory("travis_ci", score, summary, details))

        buildkite = BuildkiteAnalyzer(root_str)
        score, summary, details = self._score_buildkite(buildkite)
        categories.append(HealthCategory("buildkite", score, summary, details))

        drone_ci = DroneCIAnalyzer(root_str)
        score, summary, details = self._score_drone_ci(drone_ci)
        categories.append(HealthCategory("drone_ci", score, summary, details))

        woodpecker_ci = WoodpeckerCIAnalyzer(root_str)
        score, summary, details = self._score_woodpecker_ci(woodpecker_ci)
        categories.append(HealthCategory("woodpecker_ci", score, summary, details))

        codefresh = CodefreshAnalyzer(root_str)
        score, summary, details = self._score_codefresh(codefresh)
        categories.append(HealthCategory("codefresh", score, summary, details))

        semaphore_ci = SemaphoreCIAnalyzer(root_str)
        score, summary, details = self._score_semaphore_ci(semaphore_ci)
        categories.append(HealthCategory("semaphore_ci", score, summary, details))

        concourse_ci = ConcourseCIAnalyzer(root_str)
        score, summary, details = self._score_concourse_ci(concourse_ci)
        categories.append(HealthCategory("concourse_ci", score, summary, details))

        teamcity = TeamCityAnalyzer(root_str)
        score, summary, details = self._score_teamcity(teamcity)
        categories.append(HealthCategory("teamcity", score, summary, details))

        cloud_build = CloudBuildAnalyzer(root_str)
        score, summary, details = self._score_cloud_build(cloud_build)
        categories.append(HealthCategory("cloud_build", score, summary, details))

        tekton = TektonAnalyzer(root_str)
        score, summary, details = self._score_tekton(tekton)
        categories.append(HealthCategory("tekton", score, summary, details))

        argo_workflows = ArgoWorkflowsAnalyzer(root_str)
        score, summary, details = self._score_argo_workflows(argo_workflows)
        categories.append(HealthCategory("argo_workflows", score, summary, details))

        flux_cd = FluxCDAnalyzer(root_str)
        score, summary, details = self._score_flux_cd(flux_cd)
        categories.append(HealthCategory("flux_cd", score, summary, details))

        argocd = ArgoCDAnalyzer(root_str)
        score, summary, details = self._score_argocd(argocd)
        categories.append(HealthCategory("argocd", score, summary, details))

        aws_codebuild = AWSCodeBuildAnalyzer(root_str)
        score, summary, details = self._score_aws_codebuild(aws_codebuild)
        categories.append(HealthCategory("aws_codebuild", score, summary, details))

        harness_ci = HarnessCIAnalyzer(root_str)
        score, summary, details = self._score_harness_ci(harness_ci)
        categories.append(HealthCategory("harness_ci", score, summary, details))

        buddy_ci = BuddyCIAnalyzer(root_str)
        score, summary, details = self._score_buddy_ci(buddy_ci)
        categories.append(HealthCategory("buddy_ci", score, summary, details))

        appveyor_ci = AppVeyorCIAnalyzer(root_str)
        score, summary, details = self._score_appveyor_ci(appveyor_ci)
        categories.append(HealthCategory("appveyor_ci", score, summary, details))

        gocd_ci = GoCDCIAnalyzer(root_str)
        score, summary, details = self._score_gocd_ci(gocd_ci)
        categories.append(HealthCategory("gocd_ci", score, summary, details))

        overall = 0.0
        weight_sum = 0.0
        for cat in categories:
            weight = self.WEIGHTS.get(cat.name, 0.1)
            overall += cat.score * weight
            weight_sum += weight
        overall_score = round(overall / weight_sum if weight_sum else 0.0, 1)

        recommendations = self._build_recommendations(categories)
        self._report = ProjectHealthReport(
            root=root_str,
            overall_score=overall_score,
            categories=categories,
            recommendations=recommendations,
        )
        return self._report

    @property
    def report(self) -> ProjectHealthReport:
        """Return the health report (runs analysis on first access)."""
        if self._report is None:
            self.analyze()
        return self._report

    def summary(self) -> str:
        """Return a human-readable summary."""
        return self.report.summary()

    def to_context(self) -> str:
        """Build LLM-ready context describing project health."""
        report = self.analyze()
        lines = [
            "Project health analysis:",
            report.summary(),
            "",
            "Category details:",
        ]
        for cat in report.categories:
            lines.append(f"  [{cat.name}] {cat.score:.0f}/100")
            for key, value in cat.details.items():
                lines.append(f"    {key}: {value}")
        return "\n".join(lines)
