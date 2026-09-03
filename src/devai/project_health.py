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
from devai.devcontainer_analyzer import DevContainerAnalyzer
from devai.aws_codepipeline_analyzer import AWSCodePipelineAnalyzer
from devai.harness_ci_analyzer import HarnessCIAnalyzer
from devai.buddy_ci_analyzer import BuddyCIAnalyzer
from devai.dependabot_analyzer import DependabotAnalyzer
from devai.renovate_analyzer import RenovateAnalyzer
from devai.snyk_analyzer import SnykAnalyzer
from devai.trivy_analyzer import TrivyAnalyzer
from devai.grype_analyzer import GrypeAnalyzer
from devai.syft_analyzer import SyftAnalyzer
from devai.cosign_analyzer import CosignAnalyzer
from devai.semgrep_analyzer import SemgrepAnalyzer
from devai.bandit_analyzer import BanditAnalyzer
from devai.checkov_analyzer import CheckovAnalyzer
from devai.kyverno_analyzer import KyvernoAnalyzer
from devai.falco_analyzer import FalcoAnalyzer
from devai.opa_analyzer import OPAAnalyzer
from devai.vault_analyzer import VaultAnalyzer
from devai.consul_analyzer import ConsulAnalyzer
from devai.nomad_analyzer import NomadAnalyzer
from devai.packer_analyzer import PackerAnalyzer
from devai.vagrant_analyzer import VagrantAnalyzer
from devai.terragrunt_analyzer import TerragruntAnalyzer
from devai.pulumi_analyzer import PulumiAnalyzer
from devai.cloudformation_analyzer import CloudFormationAnalyzer
from devai.crossplane_analyzer import CrossplaneAnalyzer
from devai.kustomize_analyzer import KustomizeAnalyzer
from devai.skaffold_analyzer import SkaffoldAnalyzer
from devai.tilt_analyzer import TiltAnalyzer
from devai.devspace_analyzer import DevSpaceAnalyzer
from devai.garden_analyzer import GardenAnalyzer
from devai.telepresence_analyzer import TelepresenceAnalyzer
from devai.earthly_analyzer import EarthlyAnalyzer
from devai.bazel_analyzer import BazelAnalyzer
from devai.buck_analyzer import BuckAnalyzer
from devai.gradle_analyzer import GradleAnalyzer
from devai.maven_analyzer import MavenAnalyzer
from devai.poetry_analyzer import PoetryAnalyzer
from devai.pip_analyzer import PipAnalyzer
from devai.pipfile_analyzer import PipfileAnalyzer
from devai.conda_analyzer import CondaAnalyzer
from devai.pixi_analyzer import PixiAnalyzer
from devai.hatch_analyzer import HatchAnalyzer
from devai.flit_analyzer import FlitAnalyzer
from devai.pdm_analyzer import PdmAnalyzer
from devai.uv_analyzer import UvAnalyzer
from devai.rye_analyzer import RyeAnalyzer
from devai.piptools_analyzer import PipToolsAnalyzer
from devai.setuptools_analyzer import SetuptoolsAnalyzer
from devai.cibuildwheel_analyzer import CibuildwheelAnalyzer
from devai.maturin_analyzer import MaturinAnalyzer
from devai.scikit_build_analyzer import ScikitBuildAnalyzer
from devai.npm_analyzer import NpmAnalyzer
from devai.pnpm_analyzer import PnpmAnalyzer
from devai.bun_analyzer import BunAnalyzer
from devai.deno_analyzer import DenoAnalyzer
from devai.cargo_analyzer import CargoAnalyzer
from devai.go_mod_analyzer import GoModAnalyzer
from devai.composer_analyzer import ComposerAnalyzer
from devai.bundler_analyzer import BundlerAnalyzer
from devai.mix_analyzer import MixAnalyzer
from devai.sbt_analyzer import SbtAnalyzer
from devai.leiningen_analyzer import LeiningenAnalyzer
from devai.cmake_analyzer import CMakeAnalyzer
from devai.meson_analyzer import MesonAnalyzer
from devai.conan_analyzer import ConanAnalyzer
from devai.vcpkg_analyzer import VcpkgAnalyzer
from devai.nix_analyzer import NixAnalyzer
from devai.mise_analyzer import MiseAnalyzer
from devai.turbo_analyzer import TurboAnalyzer
from devai.nx_analyzer import NxAnalyzer
from devai.direnv_analyzer import DirenvAnalyzer
from devai.just_analyzer import JustAnalyzer
from devai.taskfile_analyzer import TaskfileAnalyzer
from devai.lefthook_analyzer import LefthookAnalyzer
from devai.eslint_analyzer import ESLintAnalyzer
from devai.jest_analyzer import JestAnalyzer
from devai.vitest_analyzer import VitestAnalyzer
from devai.playwright_analyzer import PlaywrightAnalyzer
from devai.cypress_analyzer import CypressAnalyzer
from devai.mocha_analyzer import MochaAnalyzer
from devai.pytest_analyzer import PytestAnalyzer
from devai.tox_analyzer import ToxAnalyzer
from devai.nox_analyzer import NoxAnalyzer
from devai.invoke_analyzer import InvokeAnalyzer
from devai.fabric_analyzer import FabricAnalyzer
from devai.doit_analyzer import DoitAnalyzer
from devai.taskipy_analyzer import TaskipyAnalyzer
from devai.commitizen_analyzer import CommitizenAnalyzer
from devai.towncrier_analyzer import TowncrierAnalyzer
from devai.semantic_release_analyzer import SemanticReleaseAnalyzer
from devai.ruff_analyzer import RuffAnalyzer
from devai.mypy_analyzer import MypyAnalyzer
from devai.coverage_analyzer import CoverageAnalyzer
from devai.black_analyzer import BlackAnalyzer
from devai.isort_analyzer import IsortAnalyzer
from devai.flake8_analyzer import Flake8Analyzer
from devai.pyright_analyzer import PyrightAnalyzer
from devai.basedpyright_analyzer import BasedpyrightAnalyzer
from devai.ty_analyzer import TyAnalyzer
from devai.pyrefly_analyzer import PyreflyAnalyzer
from devai.mkdocs_analyzer import MkDocsAnalyzer
from devai.sphinx_analyzer import SphinxAnalyzer
from devai.gitbook_analyzer import GitBookAnalyzer
from devai.readthedocs_analyzer import ReadTheDocsAnalyzer
from devai.pylint_analyzer import PylintAnalyzer
from devai.golangci_analyzer import GolangciLintAnalyzer
from devai.rubocop_analyzer import RuboCopAnalyzer
from devai.shellcheck_analyzer import ShellcheckAnalyzer
from devai.yamllint_analyzer import YamllintAnalyzer
from devai.hadolint_analyzer import HadolintAnalyzer
from devai.markdownlint_analyzer import MarkdownlintAnalyzer
from devai.tsconfig_analyzer import TsconfigAnalyzer
from devai.vite_analyzer import ViteAnalyzer
from devai.next_analyzer import NextAnalyzer
from devai.astro_analyzer import AstroAnalyzer
from devai.nuxt_analyzer import NuxtAnalyzer
from devai.qwik_analyzer import QwikAnalyzer
from devai.gatsby_analyzer import GatsbyAnalyzer
from devai.hono_analyzer import HonoAnalyzer
from devai.fastify_analyzer import FastifyAnalyzer
from devai.express_analyzer import ExpressAnalyzer
from devai.nestjs_analyzer import NestJSAnalyzer
from devai.fastapi_analyzer import FastAPIAnalyzer
from devai.flask_analyzer import FlaskAnalyzer
from devai.django_analyzer import DjangoAnalyzer
from devai.starlette_analyzer import StarletteAnalyzer
from devai.litestar_analyzer import LitestarAnalyzer
from devai.aiohttp_analyzer import AiohttpAnalyzer
from devai.quart_analyzer import QuartAnalyzer
from devai.sanic_analyzer import SanicAnalyzer
from devai.falcon_analyzer import FalconAnalyzer
from devai.tornado_analyzer import TornadoAnalyzer
from devai.cherrypy_analyzer import CherryPyAnalyzer
from devai.bottle_analyzer import BottleAnalyzer
from devai.pyramid_analyzer import PyramidAnalyzer
from devai.web2py_analyzer import Web2pyAnalyzer
from devai.robyn_analyzer import RobynAnalyzer
from devai.blacksheep_analyzer import BlacksheepAnalyzer
from devai.streamlit_analyzer import StreamlitAnalyzer
from devai.gradio_analyzer import GradioAnalyzer
from devai.chainlit_analyzer import ChainlitAnalyzer
from devai.llamaindex_analyzer import LlamaIndexAnalyzer
from devai.langchain_analyzer import LangChainAnalyzer
from devai.sveltekit_analyzer import SvelteKitAnalyzer
from devai.remix_analyzer import RemixAnalyzer
from devai.solid_analyzer import SolidAnalyzer
from devai.webpack_analyzer import WebpackAnalyzer
from devai.webdriverio_analyzer import WebdriverIOAnalyzer
from devai.husky_analyzer import HuskyAnalyzer
from devai.biome_analyzer import BiomeAnalyzer
from devai.prettier_analyzer import PrettierAnalyzer
from devai.stylelint_analyzer import StylelintAnalyzer
from devai.commitlint_analyzer import CommitlintAnalyzer
from devai.editorconfig_analyzer import EditorConfigAnalyzer
from devai.pants_analyzer import PantsAnalyzer
from devai.appveyor_ci_analyzer import AppVeyorCIAnalyzer
from devai.gocd_ci_analyzer import GoCDCIAnalyzer
from devai.cirrus_ci_analyzer import CirrusCIAnalyzer
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
        "devcontainer": 0.02,
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
        "aws_codepipeline": 0.02,
        "harness_ci": 0.02,
        "buddy_ci": 0.02,
        "dependabot": 0.02,
        "renovate": 0.02,
        "snyk": 0.02,
        "trivy": 0.02,
        "grype": 0.02,
        "syft": 0.02,
        "cosign": 0.02,
        "semgrep": 0.02,
        "bandit": 0.02,
        "checkov": 0.02,
        "kyverno": 0.02,
        "falco": 0.02,
        "opa": 0.02,
        "vault": 0.02,
        "consul": 0.02,
        "nomad": 0.02,
        "packer": 0.02,
        "vagrant": 0.02,
        "terragrunt": 0.02,
        "pulumi": 0.02,
        "cloudformation": 0.02,
        "crossplane": 0.02,
        "kustomize": 0.02,
        "skaffold": 0.02,
        "tilt": 0.02,
        "devspace": 0.02,
        "garden": 0.02,
        "telepresence": 0.02,
        "earthly": 0.02,
        "bazel": 0.02,
        "pants": 0.02,
        "buck": 0.02,
        "gradle": 0.02,
        "maven": 0.02,
        "poetry": 0.02,
        "pip": 0.02,
        "uv": 0.02,
        "rye": 0.02,
        "piptools": 0.02,
        "setuptools": 0.02,
        "cibuildwheel": 0.02,
        "maturin": 0.02,
        "scikit_build": 0.02,
        "pnpm": 0.02,
        "bun": 0.02,
        "deno": 0.02,
        "cargo": 0.02,
        "go_mod": 0.02,
        "composer": 0.02,
        "bundler": 0.02,
        "mix": 0.02,
        "sbt": 0.02,
        "leiningen": 0.02,
        "cmake": 0.02,
        "meson": 0.02,
        "conan": 0.02,
        "vcpkg": 0.02,
        "nix": 0.02,
        "mise": 0.02,
        "turbo": 0.02,
        "nx": 0.02,
        "direnv": 0.02,
        "just": 0.02,
        "taskfile": 0.02,
        "lefthook": 0.02,
        "eslint": 0.02,
        "jest": 0.02,
        "vitest": 0.02,
        "playwright": 0.02,
        "cypress": 0.02,
        "mocha": 0.02,
        "pytest": 0.02,
        "tox": 0.02,
        "nox": 0.02,
        "invoke": 0.02,
        "fabric": 0.02,
        "doit": 0.02,
        "taskipy": 0.02,
        "commitizen": 0.02,
        "towncrier": 0.02,
        "semantic_release": 0.02,
        "ruff": 0.02,
        "flake8": 0.02,
        "pyright": 0.02,
        "basedpyright": 0.02,
        "ty": 0.02,
        "pyrefly": 0.02,
        "mkdocs": 0.02,
        "sphinx": 0.02,
        "gitbook": 0.02,
        "readthedocs": 0.02,
        "pylint": 0.02,
        "golangci": 0.02,
        "rubocop": 0.02,
        "shellcheck": 0.02,
        "yamllint": 0.02,
        "hadolint": 0.02,
        "markdownlint": 0.02,
        "tsconfig": 0.02,
        "vite": 0.02,
        "next": 0.02,
        "astro": 0.02,
        "nuxt": 0.02,
        "webpack": 0.02,
        "mypy": 0.02,
        "webdriverio": 0.02,
        "husky": 0.02,
        "biome": 0.02,
        "prettier": 0.02,
        "stylelint": 0.02,
        "commitlint": 0.02,
        "editorconfig": 0.02,
        "appveyor_ci": 0.02,
        "gocd_ci": 0.02,
        "cirrus_ci": 0.02,
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

    def _score_devcontainer(self, analyzer: DevContainerAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No dev container configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} dev container config(s), {stats.findings} finding(s) "
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

    def _score_aws_codepipeline(self, analyzer: AWSCodePipelineAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.pipelines == 0:
            return 100.0, "No AWS CodePipeline configs found", {"pipelines": 0, "findings": 0}
        summary = (
            f"{stats.pipelines} AWS CodePipeline config(s), {stats.findings} finding(s) "
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

    def _score_dependabot(self, analyzer: DependabotAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Dependabot configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Dependabot config(s), {stats.ecosystems} ecosystem(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "files": stats.files,
            "ecosystems": stats.ecosystems,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_renovate(self, analyzer: RenovateAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Renovate configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Renovate config(s), {stats.managers} manager(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "files": stats.files,
            "managers": stats.managers,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_snyk(self, analyzer: SnykAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Snyk configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Snyk config(s) ({stats.policy_files} policy, {stats.cli_files} cli), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "files": stats.files,
            "policy_files": stats.policy_files,
            "cli_files": stats.cli_files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_trivy(self, analyzer: TrivyAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Trivy configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Trivy config(s) ({stats.ignore_files} ignore, {stats.cli_files} cli), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "files": stats.files,
            "ignore_files": stats.ignore_files,
            "cli_files": stats.cli_files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_grype(self, analyzer: GrypeAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Grype configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Grype config(s) ({stats.ignore_files} ignore, {stats.cli_files} cli), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "files": stats.files,
            "ignore_files": stats.ignore_files,
            "cli_files": stats.cli_files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_syft(self, analyzer: SyftAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Syft configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Syft config(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "files": stats.files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_cosign(self, analyzer: CosignAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Cosign configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Cosign config(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "files": stats.files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_semgrep(self, analyzer: SemgrepAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Semgrep configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Semgrep config(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "files": stats.files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_bandit(self, analyzer: BanditAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Bandit configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Bandit config(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "files": stats.files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_checkov(self, analyzer: CheckovAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Checkov configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Checkov config(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "files": stats.files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_kyverno(self, analyzer: KyvernoAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.policies == 0:
            return 100.0, "No Kyverno policies found", {"policies": 0, "findings": 0}
        summary = (
            f"{stats.policies} Kyverno policy file(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "policies": stats.policies,
            "files": stats.files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_falco(self, analyzer: FalcoAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.rules_files == 0:
            return 100.0, "No Falco rules found", {"rules_files": 0, "findings": 0}
        summary = (
            f"{stats.rules_files} Falco rules file(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "rules_files": stats.rules_files,
            "files": stats.files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_opa(self, analyzer: OPAAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.policies == 0:
            return 100.0, "No OPA policies found", {"policies": 0, "findings": 0}
        summary = (
            f"{stats.policies} OPA policy file(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "policies": stats.policies,
            "files": stats.files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_vault(self, analyzer: VaultAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Vault configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Vault config file(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "files": stats.files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_consul(self, analyzer: ConsulAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Consul configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Consul config file(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "files": stats.files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_nomad(self, analyzer: NomadAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Nomad configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Nomad config file(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "files": stats.files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_packer(self, analyzer: PackerAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Packer configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Packer config file(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "files": stats.files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_vagrant(self, analyzer: VagrantAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Vagrant configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Vagrant config file(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "files": stats.files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_terragrunt(self, analyzer: TerragruntAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Terragrunt configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Terragrunt config file(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "files": stats.files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_pulumi(self, analyzer: PulumiAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.files == 0:
            return 100.0, "No Pulumi projects found", {"projects": 0, "findings": 0}
        summary = (
            f"{stats.projects} Pulumi project(s), {stats.files} file(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "projects": stats.projects,
            "files": stats.files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_cloudformation(self, analyzer: CloudFormationAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.templates == 0:
            return 100.0, "No CloudFormation templates found", {"templates": 0, "findings": 0}
        summary = (
            f"{stats.templates} CloudFormation template(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "templates": stats.templates,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_crossplane(self, analyzer: CrossplaneAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.manifests == 0:
            return 100.0, "No Crossplane manifests found", {"manifests": 0, "findings": 0}
        summary = (
            f"{stats.manifests} Crossplane manifest(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "manifests": stats.manifests,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_kustomize(self, analyzer: KustomizeAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.overlays == 0:
            return 100.0, "No Kustomize overlays found", {"overlays": 0, "findings": 0}
        summary = (
            f"{stats.overlays} Kustomize overlay(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "overlays": stats.overlays,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_skaffold(self, analyzer: SkaffoldAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Skaffold configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Skaffold config(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_tilt(self, analyzer: TiltAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Tilt configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Tilt config(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_devspace(self, analyzer: DevSpaceAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No DevSpace configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} DevSpace config(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_garden(self, analyzer: GardenAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Garden configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Garden config(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_telepresence(self, analyzer: TelepresenceAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Telepresence configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Telepresence config(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_earthly(self, analyzer: EarthlyAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Earthly configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Earthly config(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_bazel(self, analyzer: BazelAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Bazel configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Bazel config(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_pants(self, analyzer: PantsAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Pants configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Pants config(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_buck(self, analyzer: BuckAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Buck configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Buck config(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_gradle(self, analyzer: GradleAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Gradle configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Gradle config(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_maven(self, analyzer: MavenAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Maven configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Maven config(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_poetry(self, analyzer: PoetryAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Poetry configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Poetry config(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_pip(self, analyzer: PipAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No pip configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} pip config(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_pipfile(self, analyzer: PipfileAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Pipenv configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Pipenv config(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_conda(self, analyzer: CondaAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Conda configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Conda config(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_pixi(self, analyzer: PixiAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Pixi configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Pixi config(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_hatch(self, analyzer: HatchAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Hatch configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Hatch config(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_flit(self, analyzer: FlitAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Flit configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Flit config(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_pdm(self, analyzer: PdmAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No PDM configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} PDM config(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_uv(self, analyzer: UvAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No uv configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} uv config(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_rye(self, analyzer: RyeAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Rye configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Rye project(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_piptools(self, analyzer: PipToolsAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No pip-tools configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} pip-tools config(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_setuptools(self, analyzer: SetuptoolsAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No setuptools configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} setuptools config(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_cibuildwheel(self, analyzer: CibuildwheelAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No cibuildwheel configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} cibuildwheel config(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_maturin(self, analyzer: MaturinAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No maturin configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} maturin config(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_scikit_build(self, analyzer: ScikitBuildAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No scikit-build configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} scikit-build config(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_npm(self, analyzer: NpmAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No npm configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} npm config(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_pnpm(self, analyzer: PnpmAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No pnpm configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} pnpm config(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_bun(self, analyzer: BunAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Bun configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Bun config(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_deno(self, analyzer: DenoAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Deno configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Deno config(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_jest(self, analyzer: JestAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.config_files == 0:
            return 100.0, "No Jest configs found", {"config_files": 0, "findings": 0}
        summary = (
            f"{stats.config_files} Jest config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "config_files": stats.config_files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_vitest(self, analyzer: VitestAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Vitest configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Vitest config(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_playwright(self, analyzer: PlaywrightAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.config_files == 0:
            return 100.0, "No Playwright configs found", {"config_files": 0, "findings": 0}
        summary = (
            f"{stats.config_files} Playwright config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "config_files": stats.config_files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_cypress(self, analyzer: CypressAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.config_files == 0:
            return 100.0, "No Cypress configs found", {"config_files": 0, "findings": 0}
        summary = (
            f"{stats.config_files} Cypress config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "config_files": stats.config_files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_mocha(self, analyzer: MochaAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.config_files == 0:
            return 100.0, "No Mocha configs found", {"config_files": 0, "findings": 0}
        summary = (
            f"{stats.config_files} Mocha config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "config_files": stats.config_files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_pytest(self, analyzer: PytestAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.config_files == 0:
            return 100.0, "No pytest configs found", {"config_files": 0, "findings": 0}
        summary = (
            f"{stats.config_files} pytest config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "config_files": stats.config_files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_tox(self, analyzer: ToxAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.config_files == 0:
            return 100.0, "No tox configs found", {"config_files": 0, "findings": 0}
        summary = (
            f"{stats.config_files} tox config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "config_files": stats.config_files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_nox(self, analyzer: NoxAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.config_files == 0:
            return 100.0, "No nox configs found", {"config_files": 0, "findings": 0}
        summary = (
            f"{stats.config_files} nox config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "config_files": stats.config_files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_invoke(self, analyzer: InvokeAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.config_files == 0:
            return 100.0, "No Invoke configs found", {"config_files": 0, "findings": 0}
        summary = (
            f"{stats.config_files} Invoke config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "config_files": stats.config_files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_fabric(self, analyzer: FabricAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.config_files == 0:
            return 100.0, "No Fabric configs found", {"config_files": 0, "findings": 0}
        summary = (
            f"{stats.config_files} Fabric config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "config_files": stats.config_files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_doit(self, analyzer: DoitAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.config_files == 0:
            return 100.0, "No Doit configs found", {"config_files": 0, "findings": 0}
        summary = (
            f"{stats.config_files} Doit config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "config_files": stats.config_files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_taskipy(self, analyzer: TaskipyAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.config_files == 0:
            return 100.0, "No Taskipy configs found", {"config_files": 0, "findings": 0}
        summary = (
            f"{stats.config_files} Taskipy config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "config_files": stats.config_files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_commitizen(self, analyzer: CommitizenAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.config_files == 0:
            return 100.0, "No Commitizen configs found", {"config_files": 0, "findings": 0}
        summary = (
            f"{stats.config_files} Commitizen config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "config_files": stats.config_files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_towncrier(self, analyzer: TowncrierAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.config_files == 0:
            return 100.0, "No Towncrier configs found", {"config_files": 0, "findings": 0}
        summary = (
            f"{stats.config_files} Towncrier config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "config_files": stats.config_files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_semantic_release(
        self, analyzer: SemanticReleaseAnalyzer
    ) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.config_files == 0:
            return 100.0, "No semantic-release configs found", {"config_files": 0, "findings": 0}
        summary = (
            f"{stats.config_files} semantic-release config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "config_files": stats.config_files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_ruff(self, analyzer: RuffAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.config_files == 0:
            return 100.0, "No Ruff configs found", {"config_files": 0, "findings": 0}
        summary = (
            f"{stats.config_files} Ruff config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "config_files": stats.config_files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_mypy(self, analyzer: MypyAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.config_files == 0:
            return 100.0, "No mypy configs found", {"config_files": 0, "findings": 0}
        summary = (
            f"{stats.config_files} mypy config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "config_files": stats.config_files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_coverage(self, analyzer: CoverageAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.config_files == 0:
            return 100.0, "No coverage configs found", {"config_files": 0, "findings": 0}
        summary = (
            f"{stats.config_files} coverage config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "config_files": stats.config_files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_black(self, analyzer: BlackAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.config_files == 0:
            return 100.0, "No Black configs found", {"config_files": 0, "findings": 0}
        summary = (
            f"{stats.config_files} Black config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "config_files": stats.config_files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_isort(self, analyzer: IsortAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.config_files == 0:
            return 100.0, "No isort configs found", {"config_files": 0, "findings": 0}
        summary = (
            f"{stats.config_files} isort config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "config_files": stats.config_files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_flake8(self, analyzer: Flake8Analyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.config_files == 0:
            return 100.0, "No flake8 configs found", {"config_files": 0, "findings": 0}
        summary = (
            f"{stats.config_files} flake8 config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "config_files": stats.config_files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_pyright(self, analyzer: PyrightAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.config_files == 0:
            return 100.0, "No Pyright configs found", {"config_files": 0, "findings": 0}
        summary = (
            f"{stats.config_files} Pyright config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "config_files": stats.config_files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_basedpyright(self, analyzer: BasedpyrightAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.config_files == 0:
            return 100.0, "No Basedpyright configs found", {"config_files": 0, "findings": 0}
        summary = (
            f"{stats.config_files} Basedpyright config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "config_files": stats.config_files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_ty(self, analyzer: TyAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.config_files == 0:
            return 100.0, "No ty configs found", {"config_files": 0, "findings": 0}
        summary = (
            f"{stats.config_files} ty config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "config_files": stats.config_files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_pyrefly(self, analyzer: PyreflyAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.config_files == 0:
            return 100.0, "No Pyrefly configs found", {"config_files": 0, "findings": 0}
        summary = (
            f"{stats.config_files} Pyrefly config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "config_files": stats.config_files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_mkdocs(self, analyzer: MkDocsAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.config_files == 0:
            return 100.0, "No MkDocs configs found", {"config_files": 0, "findings": 0}
        summary = (
            f"{stats.config_files} MkDocs config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "config_files": stats.config_files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_sphinx(self, analyzer: SphinxAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.config_files == 0:
            return 100.0, "No Sphinx configs found", {"config_files": 0, "findings": 0}
        summary = (
            f"{stats.config_files} Sphinx config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "config_files": stats.config_files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_gitbook(self, analyzer: GitBookAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.config_files == 0:
            return 100.0, "No GitBook configs found", {"config_files": 0, "findings": 0}
        summary = (
            f"{stats.config_files} GitBook config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "config_files": stats.config_files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_readthedocs(self, analyzer: ReadTheDocsAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.config_files == 0:
            return 100.0, "No Read the Docs configs found", {"config_files": 0, "findings": 0}
        summary = (
            f"{stats.config_files} Read the Docs config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "config_files": stats.config_files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_pylint(self, analyzer: PylintAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.config_files == 0:
            return 100.0, "No pylint configs found", {"config_files": 0, "findings": 0}
        summary = (
            f"{stats.config_files} pylint config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "config_files": stats.config_files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_golangci(self, analyzer: GolangciLintAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.config_files == 0:
            return 100.0, "No golangci-lint configs found", {"config_files": 0, "findings": 0}
        summary = (
            f"{stats.config_files} golangci-lint config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "config_files": stats.config_files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_rubocop(self, analyzer: RuboCopAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.config_files == 0:
            return 100.0, "No RuboCop configs found", {"config_files": 0, "findings": 0}
        summary = (
            f"{stats.config_files} RuboCop config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "config_files": stats.config_files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_shellcheck(self, analyzer: ShellcheckAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.config_files == 0:
            return 100.0, "No ShellCheck configs found", {"config_files": 0, "findings": 0}
        summary = (
            f"{stats.config_files} ShellCheck config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "config_files": stats.config_files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_yamllint(self, analyzer: YamllintAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.config_files == 0:
            return 100.0, "No yamllint configs found", {"config_files": 0, "findings": 0}
        summary = (
            f"{stats.config_files} yamllint config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "config_files": stats.config_files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_hadolint(self, analyzer: HadolintAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.config_files == 0:
            return 100.0, "No Hadolint configs found", {"config_files": 0, "findings": 0}
        summary = (
            f"{stats.config_files} Hadolint config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "config_files": stats.config_files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_markdownlint(self, analyzer: MarkdownlintAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.config_files == 0:
            return 100.0, "No markdownlint configs found", {"config_files": 0, "findings": 0}
        summary = (
            f"{stats.config_files} markdownlint config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "config_files": stats.config_files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_tsconfig(self, analyzer: TsconfigAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.config_files == 0:
            return 100.0, "No TypeScript compiler configs found", {"config_files": 0, "findings": 0}
        summary = (
            f"{stats.config_files} TypeScript config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "config_files": stats.config_files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_vite(self, analyzer: ViteAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Vite configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Vite config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_next(self, analyzer: NextAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Next.js configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Next.js config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_astro(self, analyzer: AstroAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Astro configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Astro config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_qwik(self, analyzer: QwikAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Qwik City configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Qwik City config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_gatsby(self, analyzer: GatsbyAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Gatsby configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Gatsby config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_hono(self, analyzer: HonoAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Hono app files found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Hono file(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_fastify(self, analyzer: FastifyAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Fastify app files found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Fastify file(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_express(self, analyzer: ExpressAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Express app files found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Express file(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_nestjs(self, analyzer: NestJSAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No NestJS app files found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} NestJS file(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_fastapi(self, analyzer: FastAPIAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No FastAPI app files found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} FastAPI file(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_flask(self, analyzer: FlaskAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Flask app files found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Flask file(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_django(self, analyzer: DjangoAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Django app files found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Django file(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_starlette(self, analyzer: StarletteAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Starlette app files found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Starlette file(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_litestar(self, analyzer: LitestarAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Litestar app files found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Litestar file(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_aiohttp(self, analyzer: AiohttpAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No aiohttp app files found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} aiohttp file(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_quart(self, analyzer: QuartAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Quart app files found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Quart file(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_sanic(self, analyzer: SanicAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Sanic app files found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Sanic file(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_falcon(self, analyzer: FalconAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Falcon app files found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Falcon file(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_tornado(self, analyzer: TornadoAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Tornado app files found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Tornado file(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_cherrypy(self, analyzer: CherryPyAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No CherryPy app files found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} CherryPy file(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_bottle(self, analyzer: BottleAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Bottle app files found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Bottle file(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_pyramid(self, analyzer: PyramidAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Pyramid app files found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Pyramid file(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_web2py(self, analyzer: Web2pyAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No web2py app files found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} web2py file(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_robyn(self, analyzer: RobynAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Robyn app files found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Robyn file(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_blacksheep(self, analyzer: BlacksheepAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No BlackSheep app files found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} BlackSheep file(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_streamlit(self, analyzer: StreamlitAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Streamlit app files found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Streamlit file(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_gradio(self, analyzer: GradioAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Gradio app files found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Gradio file(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_chainlit(self, analyzer: ChainlitAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Chainlit app files found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Chainlit file(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_llamaindex(self, analyzer: LlamaIndexAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No LlamaIndex app files found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} LlamaIndex file(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_langchain(self, analyzer: LangChainAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No LangChain app files found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} LangChain file(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_sveltekit(self, analyzer: SvelteKitAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No SvelteKit configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} SvelteKit config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_remix(self, analyzer: RemixAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Remix configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Remix config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_solid(self, analyzer: SolidAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No SolidJS configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} SolidJS config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_nuxt(self, analyzer: NuxtAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Nuxt configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Nuxt config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_webpack(self, analyzer: WebpackAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Webpack configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Webpack config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_webdriverio(self, analyzer: WebdriverIOAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.config_files == 0:
            return 100.0, "No WebdriverIO configs found", {"config_files": 0, "findings": 0}
        summary = (
            f"{stats.config_files} WebdriverIO config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "config_files": stats.config_files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_cargo(self, analyzer: CargoAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Cargo configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Cargo project(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_go_mod(self, analyzer: GoModAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Go module configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Go module(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_composer(self, analyzer: ComposerAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Composer configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Composer project(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_bundler(self, analyzer: BundlerAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Bundler configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Bundler project(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_mix(self, analyzer: MixAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Mix configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Mix project(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_sbt(self, analyzer: SbtAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No sbt configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} sbt project(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_leiningen(self, analyzer: LeiningenAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Leiningen configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Leiningen project(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_cmake(self, analyzer: CMakeAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No CMake configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} CMake project(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_meson(self, analyzer: MesonAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Meson configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Meson project(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_conan(self, analyzer: ConanAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Conan configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Conan project(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_vcpkg(self, analyzer: VcpkgAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Vcpkg configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Vcpkg project(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_nix(self, analyzer: NixAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Nix configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Nix project(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_mise(self, analyzer: MiseAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No mise configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} mise config(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_turbo(self, analyzer: TurboAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No turbo configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} turbo config(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_nx(self, analyzer: NxAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No Nx configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} Nx config(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_direnv(self, analyzer: DirenvAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.configs == 0:
            return 100.0, "No direnv configs found", {"configs": 0, "findings": 0}
        summary = (
            f"{stats.configs} direnv config(s), "
            f"{stats.findings} finding(s) ({stats.high_severity} high)"
        )
        return score, summary, {
            "configs": stats.configs,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_just(self, analyzer: JustAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.justfiles == 0:
            return 100.0, "No justfiles found", {"justfiles": 0, "findings": 0}
        summary = (
            f"{stats.justfiles} justfile(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "justfiles": stats.justfiles,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_taskfile(self, analyzer: TaskfileAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.taskfiles == 0:
            return 100.0, "No Taskfiles found", {"taskfiles": 0, "findings": 0}
        summary = (
            f"{stats.taskfiles} Taskfile(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "taskfiles": stats.taskfiles,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_lefthook(self, analyzer: LefthookAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.config_files == 0:
            return 100.0, "No lefthook configs found", {"config_files": 0, "findings": 0}
        summary = (
            f"{stats.config_files} lefthook config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "config_files": stats.config_files,
            "hooks": stats.hooks,
            "commands": stats.commands,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_eslint(self, analyzer: ESLintAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.config_files == 0:
            return 100.0, "No ESLint configs found", {"config_files": 0, "findings": 0}
        summary = (
            f"{stats.config_files} ESLint config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "config_files": stats.config_files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_husky(self, analyzer: HuskyAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.hook_files == 0 and not analyzer.info.prepare_script:
            return 100.0, "No Husky hooks found", {"hook_files": 0, "findings": 0}
        summary = (
            f"{stats.hook_files} Husky hook(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "hook_files": stats.hook_files,
            "hooks": stats.hooks,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_biome(self, analyzer: BiomeAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.config_files == 0:
            return 100.0, "No Biome configs found", {"config_files": 0, "findings": 0}
        summary = (
            f"{stats.config_files} Biome config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "config_files": stats.config_files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_prettier(self, analyzer: PrettierAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.config_files == 0:
            return 100.0, "No Prettier configs found", {"config_files": 0, "findings": 0}
        summary = (
            f"{stats.config_files} Prettier config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "config_files": stats.config_files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_stylelint(self, analyzer: StylelintAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.config_files == 0:
            return 100.0, "No Stylelint configs found", {"config_files": 0, "findings": 0}
        summary = (
            f"{stats.config_files} Stylelint config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "config_files": stats.config_files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_commitlint(self, analyzer: CommitlintAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.config_files == 0:
            return 100.0, "No Commitlint configs found", {"config_files": 0, "findings": 0}
        summary = (
            f"{stats.config_files} Commitlint config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "config_files": stats.config_files,
            "findings": stats.findings,
            "high_severity": stats.high_severity,
            "medium_severity": stats.medium_severity,
            "low_severity": stats.low_severity,
        }

    def _score_editorconfig(self, analyzer: EditorConfigAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.config_files == 0:
            return 100.0, "No EditorConfig files found", {"config_files": 0, "findings": 0}
        summary = (
            f"{stats.config_files} EditorConfig file(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high)"
        )
        return score, summary, {
            "config_files": stats.config_files,
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

    def _score_cirrus_ci(self, analyzer: CirrusCIAnalyzer) -> tuple[float, str, dict]:
        analyzer.analyze()
        score = analyzer.health_score()
        stats = analyzer.stats
        if stats.pipelines == 0:
            return 100.0, "No Cirrus CI pipelines found", {"pipelines": 0, "findings": 0}
        summary = (
            f"{stats.pipelines} Cirrus CI pipeline(s), {stats.findings} finding(s) "
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
            elif cat.name == "devcontainer" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden dev containers — use non-root remoteUser, avoid docker.sock mounts, and reference secrets via ${localEnv:VAR}"
                )
            elif cat.name == "aws_codebuild" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden AWS CodeBuild — use Secrets Manager/SSM, enable artifact encryption, and avoid privileged Docker"
                )
            elif cat.name == "aws_codepipeline" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden AWS CodePipeline — enable KMS artifact encryption, add manual approval before production, and apply least-privilege IAM"
                )
            elif cat.name == "harness_ci" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Harness CI — use Secret Manager references, runAsNonRoot, disable automountServiceAccountToken, and avoid privileged containers"
                )
            elif cat.name == "buddy_ci" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Buddy CI — use encrypted variables/vault, pin Docker image tags, disable docker_privileged_mode, and sanitize Buddy variables in scripts"
                )
            elif cat.name == "dependabot" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Dependabot — use GitHub secrets for registry credentials, disable insecure-external-code-execution, and group security updates"
                )
            elif cat.name == "renovate" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Renovate — use encrypted hostRules tokens, keep vulnerabilityAlerts enabled, and restrict postUpgradeTasks shell commands"
                )
            elif cat.name == "snyk" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Snyk — store SNYK_TOKEN in CI secrets, avoid wildcard ignores, and set expires dates on suppressions"
                )
            elif cat.name == "trivy" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Trivy — use exit-code 1 in CI, avoid wildcard .trivyignore entries, and store registry credentials in secrets"
                )
            elif cat.name == "grype" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Grype — set fail-on-severity to high, avoid wildcard .grypeignore entries, and store registry credentials in secrets"
                )
            elif cat.name == "syft" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Syft — use cyclonedx-json or spdx-json output, avoid wildcard excludes, and store registry credentials in secrets"
                )
            elif cat.name == "cosign" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Cosign — enable Rekor/tlog verification, use KMS for keys, and enforce deny-by-default signing policies"
                )
            elif cat.name == "semgrep" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Semgrep — use SEMGREP_APP_TOKEN env var, avoid wildcard path excludes, and keep security rules at ERROR severity"
                )
            elif cat.name == "bandit" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Bandit — avoid wildcard skips/excludes, do not disable shell injection tests, and scope assert_used skips to test files"
                )
            elif cat.name == "checkov" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Checkov — disable soft-fail, avoid wildcard skip-check/path patterns, and use BC_API_KEY env var for Bridgecrew tokens"
                )
            elif cat.name == "kyverno" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Kyverno — set validationFailureAction to Enforce, use failurePolicy: Fail, and avoid wildcard namespace excludes or PolicyExceptions"
                )
            elif cat.name == "falco" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Falco — avoid enabled: false, tighten wildcard conditions, scope suppress/exception blocks, and use WARNING+ priority for runtime threats"
                )
            elif cat.name == "opa" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden OPA — set default allow = false, avoid unconditional allow rules, disable TLS bypass, and scope glob patterns"
                )
            elif cat.name == "vault" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Vault — enable TLS on listeners, remove dev mode, configure auto-unseal seal, and avoid hardcoded tokens"
                )
            elif cat.name == "consul" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Consul — enable ACLs with default deny, configure gossip encrypt, enable TLS verification, and remove hardcoded tokens"
                )
            elif cat.name == "nomad" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Nomad — enable ACLs with default deny, configure TLS on HTTP/RPC, disable raw_exec and allow_privileged, and remove hardcoded tokens"
                )
            elif cat.name == "packer" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Packer — use variables for secrets, pin AMI/image tags, enable EBS encryption, and avoid curl-pipe-to-shell provisioners"
                )
            elif cat.name == "vagrant" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Vagrant — pin box_version, bind forwarded ports to 127.0.0.1, use SSH keys instead of passwords, and avoid curl-pipe-to-shell provisioners"
                )
            elif cat.name == "terragrunt" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Terragrunt — enable S3 encryption and DynamoDB state locking, remove hardcoded secrets, pin module sources, and restrict mock_outputs"
                )
            elif cat.name == "pulumi" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Pulumi — use 'pulumi config set --secret' for credentials, enable encrypted cloud backends, pin plugin versions, and protect production resources"
                )
            elif cat.name == "cloudformation" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden CloudFormation — use NoEcho parameters and Secrets Manager, enable BlockPublicAccess and encryption, restrict IAM to least privilege, and set DeletionPolicy: Retain on data resources"
                )
            elif cat.name == "crossplane" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Crossplane — pin provider package versions, use IRSA or secretRef for credentials, enable TLS verification, apply least-privilege IAM, and set deletionPolicy: Orphan on production resources"
                )
            elif cat.name == "kustomize" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Kustomize — use HTTPS remote bases, pin git refs, avoid exec plugins, store secrets in ExternalSecrets, pin image tags, and keep loadRestrictor enabled"
                )
            elif cat.name == "skaffold" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Skaffold — pin image tags, use TLS registries, avoid docker.sock mounts, enable statusCheck, restrict kubeContext to dev clusters, and never hardcode build secrets"
                )
            elif cat.name == "tilt" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Tilt — pin image tags, use TLS registries, avoid docker.sock mounts, enable secret scrubbing, restrict allow_k8s_contexts to dev clusters, and never hardcode env secrets"
                )
            elif cat.name == "devspace" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden DevSpace — pin image tags, use TLS registries, disable SSH into pods, exclude sensitive sync paths, avoid force deploy, and never hardcode vars or secret values"
                )
            elif cat.name == "garden" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Garden — pin image tags, use TLS registries, prefer cluster-build, exclude sensitive sync paths, avoid inline kubeconfig, and never hardcode environment variables"
                )
            elif cat.name == "telepresence" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Telepresence — scope intercepts to dev namespaces, disable docker.sock mounts, use namespaced manager RBAC, avoid .env envFile sync, and never hardcode intercept env secrets"
                )
            elif cat.name == "earthly" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Earthly — use ARG --secret for credentials, pin image tags, avoid docker.sock mounts, disable privileged WITH DOCKER, and never embed secrets in RUN commands"
                )
            elif cat.name == "bazel" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Bazel — pin http_archive with sha256, pin git_repository commits, keep sandbox enabled, avoid privileged containers, and never hardcode secrets in BUILD files"
                )
            elif cat.name == "pants" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Pants — pin pants_version exactly, use HTTPS registries, avoid privileged docker_image targets, never hardcode secrets in pants.toml or BUILD files, and use Pants secrets for environment variables"
                )
            elif cat.name == "buck" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Buck — pin remote_file with sha256, keep TLS verification enabled, use HTTPS Maven repos, avoid curl-pipe-to-shell in genrules, and never hardcode secrets in BUCK or .buckconfig files"
                )
            elif cat.name == "gradle" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Gradle — disable allowInsecureProtocol, pin dependency versions, use HTTPS Maven repos, avoid curl-pipe-to-shell in exec tasks, and never hardcode signing passwords or secrets in build.gradle or gradle.properties"
                )
            elif cat.name == "maven" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Maven — pin dependency versions, use HTTPS repositories, avoid wildcard mirrorOf, never hardcode server passwords in settings.xml, and avoid curl-pipe-to-shell in exec-maven-plugin"
                )
            elif cat.name == "poetry" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Poetry — commit poetry.lock, use HTTPS PyPI sources, pin git dependencies to tags/commits, store PyPI tokens via poetry config or CI secrets, and avoid curl-pipe-to-shell in scripts"
                )
            elif cat.name == "pip" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden pip — pin dependencies with ==, maintain constraints.txt, use HTTPS index URLs, store PyPI tokens via env vars or CI secrets, avoid --trusted-host bypasses, and never embed credentials in requirements files"
                )
            elif cat.name == "uv" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden uv — commit uv.lock, use HTTPS index URLs, pin git dependencies to tags/commits, store PyPI tokens via UV_INDEX_URL or CI secrets, keep native-tls enabled, and avoid curl-pipe-to-shell in scripts"
                )
            elif cat.name == "rye" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Rye — commit rye.lock, use HTTPS index URLs, pin git dependencies to tags/commits, store PyPI tokens via keyring or CI secrets, keep managed=true, and avoid curl-pipe-to-shell in script hooks"
                )
            elif cat.name == "piptools" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden pip-tools — run pip-compile and commit requirements.txt, use HTTPS index URLs, pin git dependencies to tags/commits, store PyPI tokens via env vars or CI secrets, avoid --allow-unsafe and --emit-index-url, and never embed credentials in .in files"
                )
            elif cat.name == "setuptools" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden setuptools — migrate to pyproject.toml with pinned dependencies, use HTTPS index URLs, pin git dependencies to tags/commits, store PyPI tokens via TWINE_PASSWORD or CI secrets, avoid exec/subprocess in setup.py, remove dependency_links, and pin setup_requires"
                )
            elif cat.name == "cibuildwheel" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden cibuildwheel — pin dependency-versions, use official quay.io/pypa images, store PyPI tokens via CIBW_* env vars from CI secrets, avoid curl-pipe-to-shell in before-all/before-build hooks, pin pip installs in test-command, and limit environment-pass to required vars"
                )
            elif cat.name == "maturin" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden maturin — store PyPI/Cargo tokens via MATURIN_PYPI_TOKEN and CARGO_REGISTRY_TOKEN from CI secrets, keep module-name and python-source within project root, pin git dependencies to commit SHAs in Cargo.toml, avoid curl-pipe-to-shell in before-build hooks, enable strip=true, and run auditwheel repair in CI"
                )
            elif cat.name == "scikit_build" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden scikit-build — store PyPI tokens via TWINE_PASSWORD from CI secrets, keep cmake.source-dir and add_subdirectory paths within project root, pin FetchContent/git dependencies to tags or commit SHAs in CMakeLists.txt, avoid execute_process with network downloads, keep CMAKE_TLS_VERIFY enabled, and review wheel/sdist include patterns"
                )
            elif cat.name == "cargo" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Cargo — commit Cargo.lock for binaries, use HTTPS registry URLs, pin git dependencies to commits, store tokens via CARGO_REGISTRY_TOKEN or credentials.toml, disable git-fetch-with-cli, and keep TLS revocation checks enabled"
                )
            elif cat.name == "go_mod" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Go modules — commit go.sum, use HTTPS GOPROXY, keep GOSUMDB enabled, avoid broad GOINSECURE/GONOSUMDB, pin replace directives, store private module credentials via netrc or CI secrets, and review //go:generate commands"
                )
            elif cat.name == "composer" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Composer — commit composer.lock, use HTTPS repositories, keep secure-http enabled, gitignore auth.json, store tokens via COMPOSER_AUTH or CI secrets, pin VCS dependencies to tags/commits, and explicitly allow only required plugins"
                )
            elif cat.name == "bundler" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Bundler — commit Gemfile.lock, use HTTPS gem sources, gitignore .bundle/config, store credentials via BUNDLE_* env vars or CI secrets, pin git gems to tags/commits, and review install hooks"
                )
            elif cat.name == "mix" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Mix — commit mix.lock, use HTTPS Hex repos, store HEX_API_KEY via env vars, pin git deps to tags/commits, use runtime.exs for production secrets, and review mix aliases"
                )
            elif cat.name == "sbt" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden sbt — use HTTPS resolvers and publishTo, store credentials in ~/.sbt/.credentials (gitignored), pin git deps to tags/commits, and review sys.process tasks"
                )
            elif cat.name == "leiningen" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Leiningen — use HTTPS repositories, store deploy credentials in ~/.lein/credentials.clj (gitignored), pin git deps to tags/commits, and review shell aliases"
                )
            elif cat.name == "cmake" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden CMake — use HTTPS download URLs, pin FetchContent/ExternalProject to tags/commits, store secrets via env vars, keep CMAKE_TLS_VERIFY ON, add EXPECTED_HASH to file(DOWNLOAD), and review execute_process calls"
                )
            elif cat.name == "meson" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Meson — use HTTPS source_url values, pin wrap-git revision to tags/commits, add source_hash to wrap-file downloads, store secrets via meson options or env vars, and review run_command calls"
                )
            elif cat.name == "conan" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Conan — use HTTPS remotes, pin git deps to tags/commits, add sha256 to tools.get downloads, store credentials via Conan secrets or env vars, keep verify_ssl enabled, and review self.run calls"
                )
            elif cat.name == "vcpkg" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Vcpkg — use HTTPS registry URLs, pin builtin-baseline and REF to commit SHAs, add SHA512 to vcpkg_download_distfile, store credentials via env vars, keep TLS verification enabled, and review vcpkg_execute_required_process calls"
                )
            elif cat.name == "nix" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Nix — use HTTPS substituters, pin flake inputs to commit SHAs in flake.lock, add sha256 to fetchTarball/fetchGit, store secrets via sops-nix or agenix, keep TLS verification enabled, and review runCommand/writeShellScript calls"
                )
            elif cat.name == "mise" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden mise — pin tool versions explicitly, use HTTPS plugin URLs, store secrets via mise env files or CI secrets, keep TLS verification enabled, and review task run scripts for curl|sh and privilege escalation"
                )
            elif cat.name == "turbo" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Turborepo — enable remote cache signatures, avoid globalPassThroughEnv for secrets, exclude .env and credential files from inputs/globalDependencies, use HTTPS remote cache URLs, and keep sensitive env vars out of cache keys"
                )
            elif cat.name == "pnpm" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden pnpm — keep verify-store-integrity and strict-ssl enabled, avoid shamefully-hoist, pin pnpm.overrides to exact versions, commit pnpm-lock.yaml, store tokens via env vars, and review .pnpmfile hooks for eval or remote require"
                )
            elif cat.name == "bun" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Bun — enable install.frozenLockfile in CI, avoid trustedDependencies=[\"*\"], keep strict-ssl enabled, commit bun.lock, store tokens via env vars, and review lifecycle scripts for curl-pipe-to-shell patterns"
                )
            elif cat.name == "nx" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Nx — store nxCloudAccessToken in NX_CLOUD_ACCESS_TOKEN env var, exclude .env and credential files from namedInputs/inputs, use HTTPS for Nx Cloud URLs, and keep secrets out of target options env blocks"
                )
            elif cat.name == "direnv" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden direnv — keep strict_env enabled, use dotenv_if_exists with gitignored .env.local, avoid watch_file on credential files, use HTTPS source_env URLs, pin flake.lock for use flake, and review eval hooks for curl|sh"
                )
            elif cat.name == "just" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden justfile — use env_var for secrets, avoid curl|sh in recipes, do not sudo or chmod 777, avoid git push --force, use HTTPS for imports, and review [script] shebang recipes"
                )
            elif cat.name == "appveyor_ci" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden AppVeyor CI — use encrypted variables, disable enable_rdp, pin version/stack, and sanitize APPVEYOR_* variables in scripts"
                )
            elif cat.name == "gocd_ci" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden GoCD CI — use secure_variables, pin container image tags, disable privileged/host network, and sanitize GO_* variables in tasks"
                )
            elif cat.name == "cirrus_ci" and cat.details.get("high_severity", 0) > 0:
                recs.append(
                    "Harden Cirrus CI — use encrypted variables, pin image tags, disable privileged/host network, and sanitize CIRRUS_* variables in scripts"
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

        devcontainer = DevContainerAnalyzer(root_str)
        score, summary, details = self._score_devcontainer(devcontainer)
        categories.append(HealthCategory("devcontainer", score, summary, details))

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

        aws_codepipeline = AWSCodePipelineAnalyzer(root_str)
        score, summary, details = self._score_aws_codepipeline(aws_codepipeline)
        categories.append(HealthCategory("aws_codepipeline", score, summary, details))

        harness_ci = HarnessCIAnalyzer(root_str)
        score, summary, details = self._score_harness_ci(harness_ci)
        categories.append(HealthCategory("harness_ci", score, summary, details))

        buddy_ci = BuddyCIAnalyzer(root_str)
        score, summary, details = self._score_buddy_ci(buddy_ci)
        categories.append(HealthCategory("buddy_ci", score, summary, details))

        dependabot = DependabotAnalyzer(root_str)
        score, summary, details = self._score_dependabot(dependabot)
        categories.append(HealthCategory("dependabot", score, summary, details))

        renovate = RenovateAnalyzer(root_str)
        score, summary, details = self._score_renovate(renovate)
        categories.append(HealthCategory("renovate", score, summary, details))

        snyk = SnykAnalyzer(root_str)
        score, summary, details = self._score_snyk(snyk)
        categories.append(HealthCategory("snyk", score, summary, details))

        trivy = TrivyAnalyzer(root_str)
        score, summary, details = self._score_trivy(trivy)
        categories.append(HealthCategory("trivy", score, summary, details))

        grype = GrypeAnalyzer(root_str)
        score, summary, details = self._score_grype(grype)
        categories.append(HealthCategory("grype", score, summary, details))

        syft = SyftAnalyzer(root_str)
        score, summary, details = self._score_syft(syft)
        categories.append(HealthCategory("syft", score, summary, details))

        cosign = CosignAnalyzer(root_str)
        score, summary, details = self._score_cosign(cosign)
        categories.append(HealthCategory("cosign", score, summary, details))

        semgrep = SemgrepAnalyzer(root_str)
        score, summary, details = self._score_semgrep(semgrep)
        categories.append(HealthCategory("semgrep", score, summary, details))

        bandit = BanditAnalyzer(root_str)
        score, summary, details = self._score_bandit(bandit)
        categories.append(HealthCategory("bandit", score, summary, details))

        checkov = CheckovAnalyzer(root_str)
        score, summary, details = self._score_checkov(checkov)
        categories.append(HealthCategory("checkov", score, summary, details))

        kyverno = KyvernoAnalyzer(root_str)
        score, summary, details = self._score_kyverno(kyverno)
        categories.append(HealthCategory("kyverno", score, summary, details))

        falco = FalcoAnalyzer(root_str)
        score, summary, details = self._score_falco(falco)
        categories.append(HealthCategory("falco", score, summary, details))

        opa = OPAAnalyzer(root_str)
        score, summary, details = self._score_opa(opa)
        categories.append(HealthCategory("opa", score, summary, details))

        vault = VaultAnalyzer(root_str)
        score, summary, details = self._score_vault(vault)
        categories.append(HealthCategory("vault", score, summary, details))

        consul = ConsulAnalyzer(root_str)
        score, summary, details = self._score_consul(consul)
        categories.append(HealthCategory("consul", score, summary, details))

        nomad = NomadAnalyzer(root_str)
        score, summary, details = self._score_nomad(nomad)
        categories.append(HealthCategory("nomad", score, summary, details))

        packer = PackerAnalyzer(root_str)
        score, summary, details = self._score_packer(packer)
        categories.append(HealthCategory("packer", score, summary, details))

        vagrant = VagrantAnalyzer(root_str)
        score, summary, details = self._score_vagrant(vagrant)
        categories.append(HealthCategory("vagrant", score, summary, details))

        terragrunt = TerragruntAnalyzer(root_str)
        score, summary, details = self._score_terragrunt(terragrunt)
        categories.append(HealthCategory("terragrunt", score, summary, details))

        pulumi = PulumiAnalyzer(root_str)
        score, summary, details = self._score_pulumi(pulumi)
        categories.append(HealthCategory("pulumi", score, summary, details))

        cloudformation = CloudFormationAnalyzer(root_str)
        score, summary, details = self._score_cloudformation(cloudformation)
        categories.append(HealthCategory("cloudformation", score, summary, details))

        crossplane = CrossplaneAnalyzer(root_str)
        score, summary, details = self._score_crossplane(crossplane)
        categories.append(HealthCategory("crossplane", score, summary, details))

        kustomize = KustomizeAnalyzer(root_str)
        score, summary, details = self._score_kustomize(kustomize)
        categories.append(HealthCategory("kustomize", score, summary, details))

        skaffold = SkaffoldAnalyzer(root_str)
        score, summary, details = self._score_skaffold(skaffold)
        categories.append(HealthCategory("skaffold", score, summary, details))

        tilt = TiltAnalyzer(root_str)
        score, summary, details = self._score_tilt(tilt)
        categories.append(HealthCategory("tilt", score, summary, details))

        devspace = DevSpaceAnalyzer(root_str)
        score, summary, details = self._score_devspace(devspace)
        categories.append(HealthCategory("devspace", score, summary, details))

        garden = GardenAnalyzer(root_str)
        score, summary, details = self._score_garden(garden)
        categories.append(HealthCategory("garden", score, summary, details))

        telepresence = TelepresenceAnalyzer(root_str)
        score, summary, details = self._score_telepresence(telepresence)
        categories.append(HealthCategory("telepresence", score, summary, details))

        earthly = EarthlyAnalyzer(root_str)
        score, summary, details = self._score_earthly(earthly)
        categories.append(HealthCategory("earthly", score, summary, details))

        bazel = BazelAnalyzer(root_str)
        score, summary, details = self._score_bazel(bazel)
        categories.append(HealthCategory("bazel", score, summary, details))

        pants = PantsAnalyzer(root_str)
        score, summary, details = self._score_pants(pants)
        categories.append(HealthCategory("pants", score, summary, details))

        buck = BuckAnalyzer(root_str)
        score, summary, details = self._score_buck(buck)
        categories.append(HealthCategory("buck", score, summary, details))

        gradle = GradleAnalyzer(root_str)
        score, summary, details = self._score_gradle(gradle)
        categories.append(HealthCategory("gradle", score, summary, details))

        maven = MavenAnalyzer(root_str)
        score, summary, details = self._score_maven(maven)
        categories.append(HealthCategory("maven", score, summary, details))

        poetry = PoetryAnalyzer(root_str)
        score, summary, details = self._score_poetry(poetry)
        categories.append(HealthCategory("poetry", score, summary, details))

        pip = PipAnalyzer(root_str)
        score, summary, details = self._score_pip(pip)
        categories.append(HealthCategory("pip", score, summary, details))

        pipfile = PipfileAnalyzer(root_str)
        score, summary, details = self._score_pipfile(pipfile)
        categories.append(HealthCategory("pipenv", score, summary, details))

        conda = CondaAnalyzer(root_str)
        score, summary, details = self._score_conda(conda)
        categories.append(HealthCategory("conda", score, summary, details))

        pixi = PixiAnalyzer(root_str)
        score, summary, details = self._score_pixi(pixi)
        categories.append(HealthCategory("pixi", score, summary, details))

        hatch = HatchAnalyzer(root_str)
        score, summary, details = self._score_hatch(hatch)
        categories.append(HealthCategory("hatch", score, summary, details))

        flit = FlitAnalyzer(root_str)
        score, summary, details = self._score_flit(flit)
        categories.append(HealthCategory("flit", score, summary, details))

        pdm = PdmAnalyzer(root_str)
        score, summary, details = self._score_pdm(pdm)
        categories.append(HealthCategory("pdm", score, summary, details))

        uv = UvAnalyzer(root_str)
        score, summary, details = self._score_uv(uv)
        categories.append(HealthCategory("uv", score, summary, details))

        rye = RyeAnalyzer(root_str)
        score, summary, details = self._score_rye(rye)
        categories.append(HealthCategory("rye", score, summary, details))

        piptools = PipToolsAnalyzer(root_str)
        score, summary, details = self._score_piptools(piptools)
        categories.append(HealthCategory("piptools", score, summary, details))

        setuptools = SetuptoolsAnalyzer(root_str)
        score, summary, details = self._score_setuptools(setuptools)
        categories.append(HealthCategory("setuptools", score, summary, details))

        cibuildwheel = CibuildwheelAnalyzer(root_str)
        score, summary, details = self._score_cibuildwheel(cibuildwheel)
        categories.append(HealthCategory("cibuildwheel", score, summary, details))

        maturin = MaturinAnalyzer(root_str)
        score, summary, details = self._score_maturin(maturin)
        categories.append(HealthCategory("maturin", score, summary, details))

        scikit_build = ScikitBuildAnalyzer(root_str)
        score, summary, details = self._score_scikit_build(scikit_build)
        categories.append(HealthCategory("scikit_build", score, summary, details))

        npm = NpmAnalyzer(root_str)
        score, summary, details = self._score_npm(npm)
        categories.append(HealthCategory("npm", score, summary, details))

        pnpm = PnpmAnalyzer(root_str)
        score, summary, details = self._score_pnpm(pnpm)
        categories.append(HealthCategory("pnpm", score, summary, details))

        bun = BunAnalyzer(root_str)
        score, summary, details = self._score_bun(bun)
        categories.append(HealthCategory("bun", score, summary, details))

        deno = DenoAnalyzer(root_str)
        score, summary, details = self._score_deno(deno)
        categories.append(HealthCategory("deno", score, summary, details))

        cargo = CargoAnalyzer(root_str)
        score, summary, details = self._score_cargo(cargo)
        categories.append(HealthCategory("cargo", score, summary, details))

        go_mod = GoModAnalyzer(root_str)
        score, summary, details = self._score_go_mod(go_mod)
        categories.append(HealthCategory("go_mod", score, summary, details))

        composer = ComposerAnalyzer(root_str)
        score, summary, details = self._score_composer(composer)
        categories.append(HealthCategory("composer", score, summary, details))

        bundler = BundlerAnalyzer(root_str)
        score, summary, details = self._score_bundler(bundler)
        categories.append(HealthCategory("bundler", score, summary, details))

        mix = MixAnalyzer(root_str)
        score, summary, details = self._score_mix(mix)
        categories.append(HealthCategory("mix", score, summary, details))

        sbt = SbtAnalyzer(root_str)
        score, summary, details = self._score_sbt(sbt)
        categories.append(HealthCategory("sbt", score, summary, details))

        leiningen = LeiningenAnalyzer(root_str)
        score, summary, details = self._score_leiningen(leiningen)
        categories.append(HealthCategory("leiningen", score, summary, details))

        cmake = CMakeAnalyzer(root_str)
        score, summary, details = self._score_cmake(cmake)
        categories.append(HealthCategory("cmake", score, summary, details))

        meson = MesonAnalyzer(root_str)
        score, summary, details = self._score_meson(meson)
        categories.append(HealthCategory("meson", score, summary, details))

        conan = ConanAnalyzer(root_str)
        score, summary, details = self._score_conan(conan)
        categories.append(HealthCategory("conan", score, summary, details))

        vcpkg = VcpkgAnalyzer(root_str)
        score, summary, details = self._score_vcpkg(vcpkg)
        categories.append(HealthCategory("vcpkg", score, summary, details))

        nix = NixAnalyzer(root_str)
        score, summary, details = self._score_nix(nix)
        categories.append(HealthCategory("nix", score, summary, details))

        mise = MiseAnalyzer(root_str)
        score, summary, details = self._score_mise(mise)
        categories.append(HealthCategory("mise", score, summary, details))

        turbo = TurboAnalyzer(root_str)
        score, summary, details = self._score_turbo(turbo)
        categories.append(HealthCategory("turbo", score, summary, details))

        nx = NxAnalyzer(root_str)
        score, summary, details = self._score_nx(nx)
        categories.append(HealthCategory("nx", score, summary, details))

        direnv = DirenvAnalyzer(root_str)
        score, summary, details = self._score_direnv(direnv)
        categories.append(HealthCategory("direnv", score, summary, details))

        just = JustAnalyzer(root_str)
        score, summary, details = self._score_just(just)
        categories.append(HealthCategory("just", score, summary, details))

        taskfile = TaskfileAnalyzer(root_str)
        score, summary, details = self._score_taskfile(taskfile)
        categories.append(HealthCategory("taskfile", score, summary, details))

        lefthook = LefthookAnalyzer(root_str)
        score, summary, details = self._score_lefthook(lefthook)
        categories.append(HealthCategory("lefthook", score, summary, details))

        eslint = ESLintAnalyzer(root_str)
        score, summary, details = self._score_eslint(eslint)
        categories.append(HealthCategory("eslint", score, summary, details))

        jest = JestAnalyzer(root_str)
        score, summary, details = self._score_jest(jest)
        categories.append(HealthCategory("jest", score, summary, details))

        vitest = VitestAnalyzer(root_str)
        score, summary, details = self._score_vitest(vitest)
        categories.append(HealthCategory("vitest", score, summary, details))

        playwright = PlaywrightAnalyzer(root_str)
        score, summary, details = self._score_playwright(playwright)
        categories.append(HealthCategory("playwright", score, summary, details))

        cypress = CypressAnalyzer(root_str)
        score, summary, details = self._score_cypress(cypress)
        categories.append(HealthCategory("cypress", score, summary, details))

        mocha = MochaAnalyzer(root_str)
        score, summary, details = self._score_mocha(mocha)
        categories.append(HealthCategory("mocha", score, summary, details))

        pytest = PytestAnalyzer(root_str)
        score, summary, details = self._score_pytest(pytest)
        categories.append(HealthCategory("pytest", score, summary, details))

        tox = ToxAnalyzer(root_str)
        score, summary, details = self._score_tox(tox)
        categories.append(HealthCategory("tox", score, summary, details))

        nox = NoxAnalyzer(root_str)
        score, summary, details = self._score_nox(nox)
        categories.append(HealthCategory("nox", score, summary, details))

        invoke = InvokeAnalyzer(root_str)
        score, summary, details = self._score_invoke(invoke)
        categories.append(HealthCategory("invoke", score, summary, details))

        fabric = FabricAnalyzer(root_str)
        score, summary, details = self._score_fabric(fabric)
        categories.append(HealthCategory("fabric", score, summary, details))

        doit = DoitAnalyzer(root_str)
        score, summary, details = self._score_doit(doit)
        categories.append(HealthCategory("doit", score, summary, details))

        taskipy = TaskipyAnalyzer(root_str)
        score, summary, details = self._score_taskipy(taskipy)
        categories.append(HealthCategory("taskipy", score, summary, details))

        commitizen = CommitizenAnalyzer(root_str)
        score, summary, details = self._score_commitizen(commitizen)
        categories.append(HealthCategory("commitizen", score, summary, details))

        towncrier = TowncrierAnalyzer(root_str)
        score, summary, details = self._score_towncrier(towncrier)
        categories.append(HealthCategory("towncrier", score, summary, details))

        semantic_release = SemanticReleaseAnalyzer(root_str)
        score, summary, details = self._score_semantic_release(semantic_release)
        categories.append(HealthCategory("semantic_release", score, summary, details))

        ruff = RuffAnalyzer(root_str)
        score, summary, details = self._score_ruff(ruff)
        categories.append(HealthCategory("ruff", score, summary, details))

        mypy = MypyAnalyzer(root_str)
        score, summary, details = self._score_mypy(mypy)
        categories.append(HealthCategory("mypy", score, summary, details))

        coverage = CoverageAnalyzer(root_str)
        score, summary, details = self._score_coverage(coverage)
        categories.append(HealthCategory("coverage", score, summary, details))

        black = BlackAnalyzer(root_str)
        score, summary, details = self._score_black(black)
        categories.append(HealthCategory("black", score, summary, details))

        isort = IsortAnalyzer(root_str)
        score, summary, details = self._score_isort(isort)
        categories.append(HealthCategory("isort", score, summary, details))

        flake8 = Flake8Analyzer(root_str)
        score, summary, details = self._score_flake8(flake8)
        categories.append(HealthCategory("flake8", score, summary, details))

        pyright = PyrightAnalyzer(root_str)
        score, summary, details = self._score_pyright(pyright)
        categories.append(HealthCategory("pyright", score, summary, details))

        basedpyright = BasedpyrightAnalyzer(root_str)
        score, summary, details = self._score_basedpyright(basedpyright)
        categories.append(HealthCategory("basedpyright", score, summary, details))

        ty = TyAnalyzer(root_str)
        score, summary, details = self._score_ty(ty)
        categories.append(HealthCategory("ty", score, summary, details))

        pyrefly = PyreflyAnalyzer(root_str)
        score, summary, details = self._score_pyrefly(pyrefly)
        categories.append(HealthCategory("pyrefly", score, summary, details))

        mkdocs = MkDocsAnalyzer(root_str)
        score, summary, details = self._score_mkdocs(mkdocs)
        categories.append(HealthCategory("mkdocs", score, summary, details))

        sphinx = SphinxAnalyzer(root_str)
        score, summary, details = self._score_sphinx(sphinx)
        categories.append(HealthCategory("sphinx", score, summary, details))

        gitbook = GitBookAnalyzer(root_str)
        score, summary, details = self._score_gitbook(gitbook)
        categories.append(HealthCategory("gitbook", score, summary, details))

        readthedocs = ReadTheDocsAnalyzer(root_str)
        score, summary, details = self._score_readthedocs(readthedocs)
        categories.append(HealthCategory("readthedocs", score, summary, details))

        pylint = PylintAnalyzer(root_str)
        score, summary, details = self._score_pylint(pylint)
        categories.append(HealthCategory("pylint", score, summary, details))

        golangci = GolangciLintAnalyzer(root_str)
        score, summary, details = self._score_golangci(golangci)
        categories.append(HealthCategory("golangci", score, summary, details))

        rubocop = RuboCopAnalyzer(root_str)
        score, summary, details = self._score_rubocop(rubocop)
        categories.append(HealthCategory("rubocop", score, summary, details))

        shellcheck = ShellcheckAnalyzer(root_str)
        score, summary, details = self._score_shellcheck(shellcheck)
        categories.append(HealthCategory("shellcheck", score, summary, details))

        yamllint = YamllintAnalyzer(root_str)
        score, summary, details = self._score_yamllint(yamllint)
        categories.append(HealthCategory("yamllint", score, summary, details))

        hadolint = HadolintAnalyzer(root_str)
        score, summary, details = self._score_hadolint(hadolint)
        categories.append(HealthCategory("hadolint", score, summary, details))

        markdownlint = MarkdownlintAnalyzer(root_str)
        score, summary, details = self._score_markdownlint(markdownlint)
        categories.append(HealthCategory("markdownlint", score, summary, details))

        tsconfig = TsconfigAnalyzer(root_str)
        score, summary, details = self._score_tsconfig(tsconfig)
        categories.append(HealthCategory("tsconfig", score, summary, details))

        vite = ViteAnalyzer(root_str)
        score, summary, details = self._score_vite(vite)
        categories.append(HealthCategory("vite", score, summary, details))

        nextjs = NextAnalyzer(root_str)
        score, summary, details = self._score_next(nextjs)
        categories.append(HealthCategory("next", score, summary, details))

        astro = AstroAnalyzer(root_str)
        score, summary, details = self._score_astro(astro)
        categories.append(HealthCategory("astro", score, summary, details))

        qwik = QwikAnalyzer(root_str)
        score, summary, details = self._score_qwik(qwik)
        categories.append(HealthCategory("qwik", score, summary, details))

        gatsby = GatsbyAnalyzer(root_str)
        score, summary, details = self._score_gatsby(gatsby)
        categories.append(HealthCategory("gatsby", score, summary, details))

        hono = HonoAnalyzer(root_str)
        score, summary, details = self._score_hono(hono)
        categories.append(HealthCategory("hono", score, summary, details))

        fastify = FastifyAnalyzer(root_str)
        score, summary, details = self._score_fastify(fastify)
        categories.append(HealthCategory("fastify", score, summary, details))

        express = ExpressAnalyzer(root_str)
        score, summary, details = self._score_express(express)
        categories.append(HealthCategory("express", score, summary, details))

        nestjs = NestJSAnalyzer(root_str)
        score, summary, details = self._score_nestjs(nestjs)
        categories.append(HealthCategory("nestjs", score, summary, details))

        fastapi = FastAPIAnalyzer(root_str)
        score, summary, details = self._score_fastapi(fastapi)
        categories.append(HealthCategory("fastapi", score, summary, details))

        flask = FlaskAnalyzer(root_str)
        score, summary, details = self._score_flask(flask)
        categories.append(HealthCategory("flask", score, summary, details))

        django = DjangoAnalyzer(root_str)
        score, summary, details = self._score_django(django)
        categories.append(HealthCategory("django", score, summary, details))

        starlette = StarletteAnalyzer(root_str)
        score, summary, details = self._score_starlette(starlette)
        categories.append(HealthCategory("starlette", score, summary, details))

        litestar = LitestarAnalyzer(root_str)
        score, summary, details = self._score_litestar(litestar)
        categories.append(HealthCategory("litestar", score, summary, details))

        aiohttp = AiohttpAnalyzer(root_str)
        score, summary, details = self._score_aiohttp(aiohttp)
        categories.append(HealthCategory("aiohttp", score, summary, details))

        quart = QuartAnalyzer(root_str)
        score, summary, details = self._score_quart(quart)
        categories.append(HealthCategory("quart", score, summary, details))

        sanic = SanicAnalyzer(root_str)
        score, summary, details = self._score_sanic(sanic)
        categories.append(HealthCategory("sanic", score, summary, details))

        falcon = FalconAnalyzer(root_str)
        score, summary, details = self._score_falcon(falcon)
        categories.append(HealthCategory("falcon", score, summary, details))

        tornado = TornadoAnalyzer(root_str)
        score, summary, details = self._score_tornado(tornado)
        categories.append(HealthCategory("tornado", score, summary, details))

        cherrypy = CherryPyAnalyzer(root_str)
        score, summary, details = self._score_cherrypy(cherrypy)
        categories.append(HealthCategory("cherrypy", score, summary, details))

        bottle = BottleAnalyzer(root_str)
        score, summary, details = self._score_bottle(bottle)
        categories.append(HealthCategory("bottle", score, summary, details))

        pyramid = PyramidAnalyzer(root_str)
        score, summary, details = self._score_pyramid(pyramid)
        categories.append(HealthCategory("pyramid", score, summary, details))

        web2py = Web2pyAnalyzer(root_str)
        score, summary, details = self._score_web2py(web2py)
        categories.append(HealthCategory("web2py", score, summary, details))

        robyn = RobynAnalyzer(root_str)
        score, summary, details = self._score_robyn(robyn)
        categories.append(HealthCategory("robyn", score, summary, details))

        blacksheep = BlacksheepAnalyzer(root_str)
        score, summary, details = self._score_blacksheep(blacksheep)
        categories.append(HealthCategory("blacksheep", score, summary, details))

        streamlit = StreamlitAnalyzer(root_str)
        score, summary, details = self._score_streamlit(streamlit)
        categories.append(HealthCategory("streamlit", score, summary, details))

        gradio = GradioAnalyzer(root_str)
        score, summary, details = self._score_gradio(gradio)
        categories.append(HealthCategory("gradio", score, summary, details))

        chainlit = ChainlitAnalyzer(root_str)
        score, summary, details = self._score_chainlit(chainlit)
        categories.append(HealthCategory("chainlit", score, summary, details))

        llamaindex = LlamaIndexAnalyzer(root_str)
        score, summary, details = self._score_llamaindex(llamaindex)
        categories.append(HealthCategory("llamaindex", score, summary, details))

        langchain = LangChainAnalyzer(root_str)
        score, summary, details = self._score_langchain(langchain)
        categories.append(HealthCategory("langchain", score, summary, details))

        sveltekit = SvelteKitAnalyzer(root_str)
        score, summary, details = self._score_sveltekit(sveltekit)
        categories.append(HealthCategory("sveltekit", score, summary, details))

        remix = RemixAnalyzer(root_str)
        score, summary, details = self._score_remix(remix)
        categories.append(HealthCategory("remix", score, summary, details))

        solid = SolidAnalyzer(root_str)
        score, summary, details = self._score_solid(solid)
        categories.append(HealthCategory("solid", score, summary, details))

        nuxt = NuxtAnalyzer(root_str)
        score, summary, details = self._score_nuxt(nuxt)
        categories.append(HealthCategory("nuxt", score, summary, details))

        webpack = WebpackAnalyzer(root_str)
        score, summary, details = self._score_webpack(webpack)
        categories.append(HealthCategory("webpack", score, summary, details))

        webdriverio = WebdriverIOAnalyzer(root_str)
        score, summary, details = self._score_webdriverio(webdriverio)
        categories.append(HealthCategory("webdriverio", score, summary, details))

        husky = HuskyAnalyzer(root_str)
        score, summary, details = self._score_husky(husky)
        categories.append(HealthCategory("husky", score, summary, details))

        biome = BiomeAnalyzer(root_str)
        score, summary, details = self._score_biome(biome)
        categories.append(HealthCategory("biome", score, summary, details))

        prettier = PrettierAnalyzer(root_str)
        score, summary, details = self._score_prettier(prettier)
        categories.append(HealthCategory("prettier", score, summary, details))

        stylelint = StylelintAnalyzer(root_str)
        score, summary, details = self._score_stylelint(stylelint)
        categories.append(HealthCategory("stylelint", score, summary, details))

        commitlint = CommitlintAnalyzer(root_str)
        score, summary, details = self._score_commitlint(commitlint)
        categories.append(HealthCategory("commitlint", score, summary, details))

        editorconfig = EditorConfigAnalyzer(root_str)
        score, summary, details = self._score_editorconfig(editorconfig)
        categories.append(HealthCategory("editorconfig", score, summary, details))

        appveyor_ci = AppVeyorCIAnalyzer(root_str)
        score, summary, details = self._score_appveyor_ci(appveyor_ci)
        categories.append(HealthCategory("appveyor_ci", score, summary, details))

        gocd_ci = GoCDCIAnalyzer(root_str)
        score, summary, details = self._score_gocd_ci(gocd_ci)
        categories.append(HealthCategory("gocd_ci", score, summary, details))

        cirrus_ci = CirrusCIAnalyzer(root_str)
        score, summary, details = self._score_cirrus_ci(cirrus_ci)
        categories.append(HealthCategory("cirrus_ci", score, summary, details))

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
