"""DevAI — primary developer-facing entry point."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from devai.api_surface import APISurfaceAnalyzer
from devai.assistant import CodeAssistant
from devai.code_compare import CodeComparer, CompareResult
from devai.code_metrics import CodeMetrics
from devai.code_smells import CodeSmellDetector
from devai.complexity_hotspots import ComplexityHotspotAnalyzer
from devai.exception_analyzer import ExceptionHierarchyAnalyzer
from devai.import_graph import ImportGraph
from devai.module_coupling import ModuleCouplingAnalyzer
from devai.async_blocking import AsyncBlockingDetector
from devai.command_injection import CommandInjectionAnalyzer
from devai.dangerous_calls import DangerousCallsAnalyzer
from devai.debug_artifacts import DebugArtifactDetector
from devai.magic_numbers import MagicNumberDetector
from devai.env_vars import EnvVarAnalyzer
from devai.gitignore_analyzer import GitignoreAnalyzer
from devai.dockerfile_analyzer import DockerfileAnalyzer
from devai.devcontainer_analyzer import DevContainerAnalyzer
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
from devai.hatch_analyzer import HatchAnalyzer
from devai.maturin_analyzer import MaturinAnalyzer
from devai.cibuildwheel_analyzer import CibuildwheelAnalyzer
from devai.flit_analyzer import FlitAnalyzer
from devai.pdm_analyzer import PdmAnalyzer
from devai.uv_analyzer import UvAnalyzer
from devai.rye_analyzer import RyeAnalyzer
from devai.piptools_analyzer import PipToolsAnalyzer
from devai.setuptools_analyzer import SetuptoolsAnalyzer
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
from devai.ruff_analyzer import RuffAnalyzer
from devai.mypy_analyzer import MypyAnalyzer
from devai.coverage_analyzer import CoverageAnalyzer
from devai.black_analyzer import BlackAnalyzer
from devai.isort_analyzer import IsortAnalyzer
from devai.flake8_analyzer import Flake8Analyzer
from devai.pyright_analyzer import PyrightAnalyzer
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
from devai.hardcoded_config import HardcodedConfigAnalyzer
from devai.insecure_random import InsecureRandomAnalyzer
from devai.log_injection import LogInjectionAnalyzer
from devai.open_redirect import OpenRedirectAnalyzer
from devai.path_traversal import PathTraversalAnalyzer
from devai.resource_leaks import ResourceLeakAnalyzer
from devai.secrets import SecretsScanner
from devai.security_scan import SecurityScanner
from devai.sql_injection import SQLInjectionAnalyzer
from devai.ssrf import SSRFAnalyzer
from devai.timing_attack import TimingAttackAnalyzer
from devai.unsafe_deserialization import UnsafeDeserializationAnalyzer
from devai.naming_conventions import NamingConventionAnalyzer
from devai.dead_code import DeadCodeAnalyzer
from devai.docstring_coverage import DocstringCoverage
from devai.duplicate_code import DuplicateCodeDetector
from devai.tech_debt import TechDebtScanner
from devai.test_mapper import TestMapper
from devai.weak_crypto import WeakCryptoAnalyzer
from devai.project_health import ProjectHealth
from devai.program import DevProgram, ProgramResult
from devai.project_detect import ProjectDetector, ProjectProfile
from devai.prompt_registry import PromptRegistry
from devai.runtime import DevRuntime
from devai.workflow import DevWorkflow, WorkflowResult


class DevAI:
    """Primary developer-facing API for DevAI.

    Wraps :class:`DevRuntime` with convenient class methods and delegates
    common assistant and program operations.

    Example::

        from devai import DevAI

        ai = DevAI.mock()
        print(ai.review("def add(a, b): return a + b"))
        ai.run("pre-commit")
    """

    def __init__(self, runtime: DevRuntime) -> None:
        self._runtime = runtime

    @classmethod
    def mock(cls, *, project_path: str | Path | None = None, **kwargs: Any) -> DevAI:
        """Create a DevAI instance with a mock LLM (no API key required)."""
        return cls(DevRuntime.create(use_mock=True, project_path=project_path, **kwargs))

    @classmethod
    def openai(
        cls,
        *,
        api_key: str | None = None,
        model: str | None = None,
        project_path: str | Path | None = None,
        **kwargs: Any,
    ) -> DevAI:
        """Create a DevAI instance backed by the OpenAI API."""
        return cls(
            DevRuntime.create(
                provider="openai",
                api_key=api_key,
                model=model,
                project_path=project_path,
                **kwargs,
            )
        )

    @classmethod
    def ollama(
        cls,
        *,
        model: str | None = None,
        base_url: str = "http://localhost:11434/v1",
        project_path: str | Path | None = None,
        **kwargs: Any,
    ) -> DevAI:
        """Create a DevAI instance backed by a local Ollama server."""
        return cls(
            DevRuntime.create(
                provider="ollama",
                model=model,
                base_url=base_url,
                project_path=project_path,
                **kwargs,
            )
        )

    @classmethod
    def from_project(
        cls,
        path: str | Path | None = None,
        *,
        use_mock: bool = False,
        **kwargs: Any,
    ) -> DevAI:
        """Bootstrap from a project directory and optional ``.devai.yaml`` config."""
        return cls(DevRuntime.from_project(path, use_mock=use_mock, **kwargs))

    @property
    def runtime(self) -> DevRuntime:
        """Underlying :class:`DevRuntime` for advanced usage."""
        return self._runtime

    @property
    def assistant(self) -> CodeAssistant:
        """The wired :class:`CodeAssistant`."""
        return self._runtime.assistant

    def review(self, code: str) -> str:
        """Review code for issues and improvements."""
        return self._runtime.review(code)

    async def areview(self, code: str) -> str:
        """Async code review."""
        return await self._runtime.assistant.areview(code)

    def explain(self, code: str) -> str:
        """Explain what code does."""
        return self._runtime.explain(code)

    async def aexplain(self, code: str) -> str:
        """Async code explanation."""
        from devai.core.models import Message
        from devai.prompts import EXPLAIN

        msgs = []
        if EXPLAIN.system:
            msgs.append(Message.system(EXPLAIN.system))
        msgs.append(Message.user(EXPLAIN.format(code=code)))
        return await self._runtime.assistant.client.acomplete(msgs)

    def generate(self, spec: str) -> str:
        """Generate code from a specification."""
        return self._runtime.generate(spec)

    def debug(self, code: str, error: str) -> str:
        """Debug code given an error message."""
        return self._runtime.assistant.debug(code, error)

    def refactor(self, code: str, goals: str = "improve readability") -> str:
        """Refactor code toward a stated goal."""
        return self._runtime.assistant.refactor(code, goals=goals)

    def run(
        self,
        program: DevProgram | str,
        context: dict[str, str] | None = None,
        *,
        trace: bool = False,
    ) -> list[ProgramResult]:
        """Run a program, preset, or program file."""
        return self._runtime.run(program, context, trace=trace)

    async def arun(
        self,
        program: DevProgram | str,
        context: dict[str, str] | None = None,
        *,
        trace: bool = False,
    ) -> list[ProgramResult]:
        """Run a program asynchronously."""
        return await self._runtime.arun(program, context, trace=trace)

    def dry_run(
        self,
        program: DevProgram | str,
        context: dict[str, str] | None = None,
    ) -> list:
        """Preview program steps without calling the LLM."""
        return self._runtime.dry_run(program, context)

    def preset(self, name: str) -> DevProgram:
        """Load a built-in program preset."""
        return self._runtime.preset(name)

    def workflow(self, name: str = "workflow") -> DevWorkflow:
        """Create a new workflow bound to this instance."""
        return self._runtime.workflow(name)

    def run_workflow(
        self,
        workflow: DevWorkflow,
        context: dict[str, str] | None = None,
    ) -> WorkflowResult:
        """Execute a workflow and return structured results."""
        return self._runtime.run_workflow(workflow, context)

    def review_git(self, *, staged: bool = False, base: str | None = None) -> str:
        """Review git changes in the project."""
        return self._runtime.review_git(staged=staged, base=base)

    def doctor(self, *, probe: bool = True) -> list:
        """Run environment diagnostics."""
        return self._runtime.doctor(probe=probe)

    def compare(
        self,
        before: str | Path,
        after: str | Path,
        *,
        review: bool = False,
        before_label: str | None = None,
        after_label: str | None = None,
    ) -> CompareResult | str:
        """Compare two code sources. Set ``review=True`` for an AI review of changes."""
        comparer = CodeComparer(self._runtime.assistant)
        if review:
            return comparer.review_changes(
                before, after, before_label=before_label, after_label=after_label
            )
        return comparer.compare(before, after, before_label=before_label, after_label=after_label)

    def detect_project(self, path: str | Path = ".") -> ProjectProfile:
        """Detect project language, framework, and tooling from a directory."""
        return ProjectDetector().detect(path)

    def metrics(self, path: str | Path = ".", **kwargs: Any) -> CodeMetrics:
        """Analyze static code metrics (complexity, LOC, function counts) for a project."""
        return CodeMetrics(str(path), **kwargs)

    def docstrings(self, path: str | Path = ".", **kwargs: Any) -> DocstringCoverage:
        """Analyze docstring coverage for functions, methods, and classes."""
        return DocstringCoverage(str(path), **kwargs)

    def test_map(self, path: str | Path = ".", **kwargs: Any) -> TestMapper:
        """Map source modules to test files and find untested modules."""
        return TestMapper(str(path), **kwargs)

    def health(self, path: str | Path = ".", **kwargs: Any) -> ProjectHealth:
        """Run unified project health analysis (metrics, typing, tests, deps, secrets)."""
        return ProjectHealth(str(path), **kwargs)

    def smells(self, path: str | Path = ".", **kwargs: Any) -> CodeSmellDetector:
        """Detect code smells (long functions, deep nesting, bare except, god classes)."""
        return CodeSmellDetector(str(path), **kwargs)

    def tech_debt(self, path: str | Path = ".", **kwargs: Any) -> TechDebtScanner:
        """Scan for TODO, FIXME, HACK, and other tech-debt comment markers."""
        return TechDebtScanner(str(path), **kwargs)

    def duplicates(self, path: str | Path = ".", **kwargs: Any) -> DuplicateCodeDetector:
        """Find duplicate and near-duplicate code blocks across the project."""
        return DuplicateCodeDetector(str(path), **kwargs)

    def dead_code(self, path: str | Path = ".", **kwargs: Any) -> DeadCodeAnalyzer:
        """Find potentially unused top-level Python functions and classes."""
        return DeadCodeAnalyzer(str(path), **kwargs)

    def api_surface(self, path: str | Path = ".", **kwargs: Any) -> APISurfaceAnalyzer:
        """Map and analyze the public API surface of a Python package."""
        return APISurfaceAnalyzer(str(path), **kwargs)

    def hotspots(self, path: str | Path = ".", **kwargs: Any) -> ComplexityHotspotAnalyzer:
        """Rank files by complexity debt to prioritize refactoring."""
        return ComplexityHotspotAnalyzer(str(path), **kwargs)

    def imports(self, path: str | Path = ".", **kwargs: Any) -> ImportGraph:
        """Build and analyze Python import dependencies."""
        return ImportGraph(str(path), **kwargs)

    def exceptions(self, path: str | Path = ".", **kwargs: Any) -> ExceptionHierarchyAnalyzer:
        """Map custom exception classes and risky except handlers."""
        return ExceptionHierarchyAnalyzer(str(path), **kwargs)

    def coupling(self, path: str | Path = ".", **kwargs: Any) -> ModuleCouplingAnalyzer:
        """Measure module afferent/efferent coupling and instability."""
        return ModuleCouplingAnalyzer(str(path), **kwargs)

    def naming(self, path: str | Path = ".", **kwargs: Any) -> NamingConventionAnalyzer:
        """Check PEP 8 naming conventions for functions, classes, and variables."""
        return NamingConventionAnalyzer(str(path), **kwargs)

    def magic_numbers(self, path: str | Path = ".", **kwargs: Any) -> MagicNumberDetector:
        """Find unexplained numeric literals that should be named constants."""
        return MagicNumberDetector(str(path), **kwargs)

    def dangerous_calls(self, path: str | Path = ".", **kwargs: Any) -> DangerousCallsAnalyzer:
        """Detect risky calls (eval, exec, shell=True) and mutable default arguments."""
        return DangerousCallsAnalyzer(str(path), **kwargs)

    def secrets(self, path: str | Path = ".", **kwargs: Any) -> SecretsScanner:
        """Scan for hardcoded API keys, tokens, and credentials."""
        return SecretsScanner(str(path), **kwargs)

    def sql_injection(self, path: str | Path = ".", **kwargs: Any) -> SQLInjectionAnalyzer:
        """Detect dynamic SQL construction in database execute calls."""
        return SQLInjectionAnalyzer(str(path), **kwargs)

    def command_injection(self, path: str | Path = ".", **kwargs: Any) -> CommandInjectionAnalyzer:
        """Detect dynamic shell command construction in os/subprocess calls."""
        return CommandInjectionAnalyzer(str(path), **kwargs)

    def debug_artifacts(self, path: str | Path = ".", **kwargs: Any) -> DebugArtifactDetector:
        """Find print, breakpoint, and pdb debug code left in sources."""
        return DebugArtifactDetector(str(path), **kwargs)

    def async_blocking(self, path: str | Path = ".", **kwargs: Any) -> AsyncBlockingDetector:
        """Detect blocking calls inside async functions."""
        return AsyncBlockingDetector(str(path), **kwargs)

    def resource_leaks(self, path: str | Path = ".", **kwargs: Any) -> ResourceLeakAnalyzer:
        """Detect files, sockets, and connections opened without context managers."""
        return ResourceLeakAnalyzer(str(path), **kwargs)

    def insecure_random(self, path: str | Path = ".", **kwargs: Any) -> InsecureRandomAnalyzer:
        """Detect use of random module for security-sensitive values."""
        return InsecureRandomAnalyzer(str(path), **kwargs)

    def path_traversal(self, path: str | Path = ".", **kwargs: Any) -> PathTraversalAnalyzer:
        """Detect unsafe file path construction from user-controlled input."""
        return PathTraversalAnalyzer(str(path), **kwargs)

    def weak_crypto(self, path: str | Path = ".", **kwargs: Any) -> WeakCryptoAnalyzer:
        """Detect use of weak cryptographic algorithms (MD5, SHA1) for security."""
        return WeakCryptoAnalyzer(str(path), **kwargs)

    def log_injection(self, path: str | Path = ".", **kwargs: Any) -> LogInjectionAnalyzer:
        """Detect log injection risks from dynamic log message construction."""
        return LogInjectionAnalyzer(str(path), **kwargs)

    def ssrf(self, path: str | Path = ".", **kwargs: Any) -> SSRFAnalyzer:
        """Detect server-side request forgery risks in outbound HTTP calls."""
        return SSRFAnalyzer(str(path), **kwargs)

    def unsafe_deserialization(self, path: str | Path = ".", **kwargs: Any) -> UnsafeDeserializationAnalyzer:
        """Detect unsafe pickle, yaml.load, and marshal deserialization."""
        return UnsafeDeserializationAnalyzer(str(path), **kwargs)

    def open_redirect(self, path: str | Path = ".", **kwargs: Any) -> OpenRedirectAnalyzer:
        """Detect open redirect vulnerabilities in web handlers."""
        return OpenRedirectAnalyzer(str(path), **kwargs)

    def env_vars(self, path: str | Path = ".", **kwargs: Any) -> EnvVarAnalyzer:
        """Inventory environment variables and detect drift between code and env files."""
        return EnvVarAnalyzer(str(path), **kwargs)

    def gitignore(self, path: str | Path = ".", **kwargs: Any) -> GitignoreAnalyzer:
        """Audit .gitignore coverage and detect exposed sensitive files."""
        return GitignoreAnalyzer(str(path), **kwargs)

    def dockerfile(self, path: str | Path = ".", **kwargs: Any) -> DockerfileAnalyzer:
        """Audit Dockerfiles for security risks and container best practices."""
        return DockerfileAnalyzer(str(path), **kwargs)

    def devcontainer(self, path: str | Path = ".", **kwargs: Any) -> DevContainerAnalyzer:
        """Audit dev container configs for hardcoded secrets, privileged mode, and unsafe mounts."""
        return DevContainerAnalyzer(str(path), **kwargs)

    def workflows(self, path: str | Path = ".", **kwargs: Any) -> WorkflowAnalyzer:
        """Audit GitHub Actions workflows for security risks and CI best practices."""
        return WorkflowAnalyzer(str(path), **kwargs)

    def compose(self, path: str | Path = ".", **kwargs: Any) -> ComposeAnalyzer:
        """Audit Docker Compose files for security risks and container best practices."""
        return ComposeAnalyzer(str(path), **kwargs)

    def precommit(self, path: str | Path = ".", **kwargs: Any) -> PrecommitAnalyzer:
        """Audit pre-commit config files for unpinned hooks and unsafe entries."""
        return PrecommitAnalyzer(str(path), **kwargs)

    def makefile(self, path: str | Path = ".", **kwargs: Any) -> MakefileAnalyzer:
        """Audit Makefiles for security risks and build best practices."""
        return MakefileAnalyzer(str(path), **kwargs)

    def kubernetes(self, path: str | Path = ".", **kwargs: Any) -> KubernetesAnalyzer:
        """Audit Kubernetes manifests for privileged mode, host namespaces, and secrets in env."""
        return KubernetesAnalyzer(str(path), **kwargs)

    def terraform(self, path: str | Path = ".", **kwargs: Any) -> TerraformAnalyzer:
        """Audit Terraform files for open security groups, public S3 ACLs, and hardcoded secrets."""
        return TerraformAnalyzer(str(path), **kwargs)

    def nginx(self, path: str | Path = ".", **kwargs: Any) -> NginxAnalyzer:
        """Audit Nginx configs for weak TLS, security headers, and insecure proxy_pass."""
        return NginxAnalyzer(str(path), **kwargs)

    def helm(self, path: str | Path = ".", **kwargs: Any) -> HelmAnalyzer:
        """Audit Helm charts for privileged pods, latest tags, and hardcoded secrets."""
        return HelmAnalyzer(str(path), **kwargs)

    def ansible(self, path: str | Path = ".", **kwargs: Any) -> AnsibleAnalyzer:
        """Audit Ansible playbooks for hardcoded secrets, unsafe shell tasks, and weak defaults."""
        return AnsibleAnalyzer(str(path), **kwargs)

    def jenkins(self, path: str | Path = ".", **kwargs: Any) -> JenkinsfileAnalyzer:
        """Audit Jenkinsfiles for script injection, hardcoded secrets, and unsafe shell steps."""
        return JenkinsfileAnalyzer(str(path), **kwargs)

    def gitlab_ci(self, path: str | Path = ".", **kwargs: Any) -> GitLabCIAnalyzer:
        """Audit GitLab CI pipelines for hardcoded secrets, unsafe scripts, and weak defaults."""
        return GitLabCIAnalyzer(str(path), **kwargs)

    def circleci(self, path: str | Path = ".", **kwargs: Any) -> CircleCIAnalyzer:
        """Audit CircleCI configs for hardcoded secrets, unpinned orbs, and unsafe scripts."""
        return CircleCIAnalyzer(str(path), **kwargs)

    def bitbucket_pipelines(self, path: str | Path = ".", **kwargs: Any) -> BitbucketPipelinesAnalyzer:
        """Audit Bitbucket Pipelines for hardcoded secrets, unsafe scripts, and weak defaults."""
        return BitbucketPipelinesAnalyzer(str(path), **kwargs)

    def azure_pipelines(self, path: str | Path = ".", **kwargs: Any) -> AzurePipelinesAnalyzer:
        """Audit Azure Pipelines for hardcoded secrets, unsafe scripts, and weak defaults."""
        return AzurePipelinesAnalyzer(str(path), **kwargs)

    def travis_ci(self, path: str | Path = ".", **kwargs: Any) -> TravisCIAnalyzer:
        """Audit Travis CI configs for hardcoded secrets, unsafe scripts, and weak defaults."""
        return TravisCIAnalyzer(str(path), **kwargs)

    def buildkite(self, path: str | Path = ".", **kwargs: Any) -> BuildkiteAnalyzer:
        """Audit Buildkite pipelines for hardcoded secrets, unpinned plugins, and unsafe scripts."""
        return BuildkiteAnalyzer(str(path), **kwargs)

    def drone_ci(self, path: str | Path = ".", **kwargs: Any) -> DroneCIAnalyzer:
        """Audit Drone CI pipelines for hardcoded secrets, privileged containers, and unsafe scripts."""
        return DroneCIAnalyzer(str(path), **kwargs)

    def woodpecker_ci(self, path: str | Path = ".", **kwargs: Any) -> WoodpeckerCIAnalyzer:
        """Audit Woodpecker CI pipelines for hardcoded secrets, privileged containers, and unsafe scripts."""
        return WoodpeckerCIAnalyzer(str(path), **kwargs)

    def codefresh(self, path: str | Path = ".", **kwargs: Any) -> CodefreshAnalyzer:
        """Audit Codefresh pipelines for hardcoded secrets, privileged containers, and unsafe scripts."""
        return CodefreshAnalyzer(str(path), **kwargs)

    def semaphore_ci(self, path: str | Path = ".", **kwargs: Any) -> SemaphoreCIAnalyzer:
        """Audit Semaphore CI pipelines for hardcoded secrets, auto-promote rules, and unsafe scripts."""
        return SemaphoreCIAnalyzer(str(path), **kwargs)

    def concourse_ci(self, path: str | Path = ".", **kwargs: Any) -> ConcourseCIAnalyzer:
        """Audit Concourse CI pipelines for hardcoded secrets, privileged tasks, and unsafe scripts."""
        return ConcourseCIAnalyzer(str(path), **kwargs)

    def teamcity(self, path: str | Path = ".", **kwargs: Any) -> TeamCityAnalyzer:
        """Audit TeamCity pipelines for hardcoded secrets, VCS triggers, and unsafe scripts."""
        return TeamCityAnalyzer(str(path), **kwargs)

    def cloud_build(self, path: str | Path = ".", **kwargs: Any) -> CloudBuildAnalyzer:
        """Audit Google Cloud Build pipelines for hardcoded secrets, substitution injection, and unsafe scripts."""
        return CloudBuildAnalyzer(str(path), **kwargs)

    def tekton(self, path: str | Path = ".", **kwargs: Any) -> TektonAnalyzer:
        """Audit Tekton pipelines for hardcoded secrets, hostPath mounts, and unsafe scripts."""
        return TektonAnalyzer(str(path), **kwargs)

    def argo_workflows(self, path: str | Path = ".", **kwargs: Any) -> ArgoWorkflowsAnalyzer:
        """Audit Argo Workflows for hardcoded secrets, hostPath mounts, and unsafe scripts."""
        return ArgoWorkflowsAnalyzer(str(path), **kwargs)

    def flux_cd(self, path: str | Path = ".", **kwargs: Any) -> FluxCDAnalyzer:
        """Audit Flux CD GitOps configs for insecure sources, force apply, and hardcoded secrets."""
        return FluxCDAnalyzer(str(path), **kwargs)

    def argocd(self, path: str | Path = ".", **kwargs: Any) -> ArgoCDAnalyzer:
        """Audit Argo CD Applications for insecure sources, wildcard destinations, and weak sync policies."""
        return ArgoCDAnalyzer(str(path), **kwargs)

    def aws_codepipeline(self, path: str | Path = ".", **kwargs: Any) -> AWSCodePipelineAnalyzer:
        """Audit AWS CodePipeline configs for hardcoded secrets, weak IAM, and missing approvals."""
        return AWSCodePipelineAnalyzer(str(path), **kwargs)

    def aws_codebuild(self, path: str | Path = ".", **kwargs: Any) -> AWSCodeBuildAnalyzer:
        """Audit AWS CodeBuild buildspec files for hardcoded secrets, unencrypted artifacts, and unsafe scripts."""
        return AWSCodeBuildAnalyzer(str(path), **kwargs)

    def harness_ci(self, path: str | Path = ".", **kwargs: Any) -> HarnessCIAnalyzer:
        """Audit Harness CI pipelines for hardcoded secrets, privileged containers, and expression injection."""
        return HarnessCIAnalyzer(str(path), **kwargs)

    def buddy_ci(self, path: str | Path = ".", **kwargs: Any) -> BuddyCIAnalyzer:
        """Audit Buddy CI pipelines for hardcoded secrets, privileged Docker mode, and variable injection."""
        return BuddyCIAnalyzer(str(path), **kwargs)

    def dependabot(self, path: str | Path = ".", **kwargs: Any) -> DependabotAnalyzer:
        """Audit Dependabot configs for hardcoded registry credentials, unsafe settings, and weak defaults."""
        return DependabotAnalyzer(str(path), **kwargs)

    def renovate(self, path: str | Path = ".", **kwargs: Any) -> RenovateAnalyzer:
        """Audit Renovate configs for hardcoded host rule credentials, unsafe automerge, and weak defaults."""
        return RenovateAnalyzer(str(path), **kwargs)

    def snyk(self, path: str | Path = ".", **kwargs: Any) -> SnykAnalyzer:
        """Audit Snyk policy and CLI configs for hardcoded tokens, broad ignores, and weak defaults."""
        return SnykAnalyzer(str(path), **kwargs)

    def trivy(self, path: str | Path = ".", **kwargs: Any) -> TrivyAnalyzer:
        """Audit Trivy ignore files and CLI configs for hardcoded tokens, broad ignores, and fail-open settings."""
        return TrivyAnalyzer(str(path), **kwargs)

    def grype(self, path: str | Path = ".", **kwargs: Any) -> GrypeAnalyzer:
        """Audit Grype ignore files and CLI configs for hardcoded tokens, broad ignores, and fail-open settings."""
        return GrypeAnalyzer(str(path), **kwargs)

    def syft(self, path: str | Path = ".", **kwargs: Any) -> SyftAnalyzer:
        """Audit Syft SBOM configs for hardcoded tokens, broad exclusions, and disabled attestation."""
        return SyftAnalyzer(str(path), **kwargs)

    def cosign(self, path: str | Path = ".", **kwargs: Any) -> CosignAnalyzer:
        """Audit Cosign signing configs for hardcoded keys, disabled tlog verification, and permissive policies."""
        return CosignAnalyzer(str(path), **kwargs)

    def semgrep(self, path: str | Path = ".", **kwargs: Any) -> SemgrepAnalyzer:
        """Audit Semgrep rule configs for hardcoded tokens, disabled rules, and broad path exclusions."""
        return SemgrepAnalyzer(str(path), **kwargs)

    def bandit(self, path: str | Path = ".", **kwargs: Any) -> BanditAnalyzer:
        """Audit Bandit configs for hardcoded tokens, broad skips, and disabled security tests."""
        return BanditAnalyzer(str(path), **kwargs)

    def checkov(self, path: str | Path = ".", **kwargs: Any) -> CheckovAnalyzer:
        """Audit Checkov configs for hardcoded tokens, soft-fail, and wildcard skip-check patterns."""
        return CheckovAnalyzer(str(path), **kwargs)

    def kyverno(self, path: str | Path = ".", **kwargs: Any) -> KyvernoAnalyzer:
        """Audit Kyverno policy manifests for audit-only enforcement, broad excludes, and unsafe mutations."""
        return KyvernoAnalyzer(str(path), **kwargs)

    def falco(self, path: str | Path = ".", **kwargs: Any) -> FalcoAnalyzer:
        """Audit Falco runtime security rules for disabled rules, wildcard conditions, and broad suppressions."""
        return FalcoAnalyzer(str(path), **kwargs)

    def opa(self, path: str | Path = ".", **kwargs: Any) -> OPAAnalyzer:
        """Audit OPA Rego policies for permissive defaults, insecure http.send, and wildcard matches."""
        return OPAAnalyzer(str(path), **kwargs)

    def vault(self, path: str | Path = ".", **kwargs: Any) -> VaultAnalyzer:
        """Audit HashiCorp Vault configs for disabled TLS, dev mode, hardcoded tokens, and weak defaults."""
        return VaultAnalyzer(str(path), **kwargs)

    def consul(self, path: str | Path = ".", **kwargs: Any) -> ConsulAnalyzer:
        """Audit HashiCorp Consul configs for disabled ACLs/TLS, dev mode, and hardcoded tokens."""
        return ConsulAnalyzer(str(path), **kwargs)

    def nomad(self, path: str | Path = ".", **kwargs: Any) -> NomadAnalyzer:
        """Audit HashiCorp Nomad configs for disabled ACLs/TLS, dev mode, privileged plugins, and hardcoded tokens."""
        return NomadAnalyzer(str(path), **kwargs)

    def packer(self, path: str | Path = ".", **kwargs: Any) -> PackerAnalyzer:
        """Audit HashiCorp Packer configs for hardcoded secrets, :latest tags, and unsafe provisioners."""
        return PackerAnalyzer(str(path), **kwargs)

    def vagrant(self, path: str | Path = ".", **kwargs: Any) -> VagrantAnalyzer:
        """Audit Vagrant configs for plaintext SSH passwords, unbound port forwards, and unsafe provisioners."""
        return VagrantAnalyzer(str(path), **kwargs)

    def terragrunt(self, path: str | Path = ".", **kwargs: Any) -> TerragruntAnalyzer:
        """Audit Terragrunt HCL for hardcoded secrets, insecure remote state, and risky dependencies."""
        return TerragruntAnalyzer(str(path), **kwargs)

    def pulumi(self, path: str | Path = ".", **kwargs: Any) -> PulumiAnalyzer:
        """Audit Pulumi IaC for hardcoded secrets, insecure backends, and risky stack configs."""
        return PulumiAnalyzer(str(path), **kwargs)

    def cloudformation(self, path: str | Path = ".", **kwargs: Any) -> CloudFormationAnalyzer:
        """Audit CloudFormation templates for hardcoded secrets, open SGs, and risky IAM policies."""
        return CloudFormationAnalyzer(str(path), **kwargs)

    def crossplane(self, path: str | Path = ".", **kwargs: Any) -> CrossplaneAnalyzer:
        """Audit Crossplane manifests for hardcoded secrets, unversioned providers, and insecure configs."""
        return CrossplaneAnalyzer(str(path), **kwargs)

    def kustomize(self, path: str | Path = ".", **kwargs: Any) -> KustomizeAnalyzer:
        """Audit Kustomize overlays for hardcoded secrets, insecure remote bases, and risky patches."""
        return KustomizeAnalyzer(str(path), **kwargs)

    def skaffold(self, path: str | Path = ".", **kwargs: Any) -> SkaffoldAnalyzer:
        """Audit Skaffold configs for hardcoded secrets, insecure registries, and risky deploy settings."""
        return SkaffoldAnalyzer(str(path), **kwargs)

    def tilt(self, path: str | Path = ".", **kwargs: Any) -> TiltAnalyzer:
        """Audit Tiltfiles for hardcoded secrets, insecure registries, and risky dev settings."""
        return TiltAnalyzer(str(path), **kwargs)

    def devspace(self, path: str | Path = ".", **kwargs: Any) -> DevSpaceAnalyzer:
        """Audit DevSpace configs for hardcoded secrets, insecure registries, and risky dev settings."""
        return DevSpaceAnalyzer(str(path), **kwargs)

    def garden(self, path: str | Path = ".", **kwargs: Any) -> GardenAnalyzer:
        """Audit Garden.io configs for hardcoded secrets, insecure registries, and risky dev settings."""
        return GardenAnalyzer(str(path), **kwargs)

    def telepresence(self, path: str | Path = ".", **kwargs: Any) -> TelepresenceAnalyzer:
        """Audit Telepresence configs for hardcoded secrets, production intercepts, and risky dev settings."""
        return TelepresenceAnalyzer(str(path), **kwargs)

    def earthly(self, path: str | Path = ".", **kwargs: Any) -> EarthlyAnalyzer:
        """Audit Earthfiles for hardcoded secrets, insecure registries, and risky build settings."""
        return EarthlyAnalyzer(str(path), **kwargs)

    def bazel(self, path: str | Path = ".", **kwargs: Any) -> BazelAnalyzer:
        """Audit Bazel BUILD files and .bazelrc for secrets, unpinned deps, and sandbox issues."""
        return BazelAnalyzer(str(path), **kwargs)

    def pants(self, path: str | Path = ".", **kwargs: Any) -> PantsAnalyzer:
        """Audit Pants BUILD files and pants.toml for secrets, unpinned deps, and registry issues."""
        return PantsAnalyzer(str(path), **kwargs)

    def buck(self, path: str | Path = ".", **kwargs: Any) -> BuckAnalyzer:
        """Audit Buck BUCK files and .buckconfig for secrets, unpinned deps, and download issues."""
        return BuckAnalyzer(str(path), **kwargs)

    def gradle(self, path: str | Path = ".", **kwargs: Any) -> GradleAnalyzer:
        """Audit Gradle build files for secrets, insecure repos, and unpinned dependencies."""
        return GradleAnalyzer(str(path), **kwargs)

    def maven(self, path: str | Path = ".", **kwargs: Any) -> MavenAnalyzer:
        """Audit Maven pom.xml and settings.xml for secrets, insecure repos, and unpinned dependencies."""
        return MavenAnalyzer(str(path), **kwargs)

    def poetry(self, path: str | Path = ".", **kwargs: Any) -> PoetryAnalyzer:
        """Audit Poetry pyproject.toml and poetry.toml for secrets, insecure sources, and unpinned deps."""
        return PoetryAnalyzer(str(path), **kwargs)

    def pip(self, path: str | Path = ".", **kwargs: Any) -> PipAnalyzer:
        """Audit pip requirements.txt, constraints.txt, and pip.conf for secrets and unpinned deps."""
        return PipAnalyzer(str(path), **kwargs)

    def pipfile(self, path: str | Path = ".", **kwargs: Any) -> PipfileAnalyzer:
        """Audit Pipenv Pipfile and Pipfile.lock for secrets, insecure sources, and unpinned deps."""
        return PipfileAnalyzer(str(path), **kwargs)

    def conda(self, path: str | Path = ".", **kwargs: Any) -> CondaAnalyzer:
        """Audit Conda environment.yml and recipe meta.yaml for secrets, insecure channels, and unpinned deps."""
        return CondaAnalyzer(str(path), **kwargs)

    def hatch(self, path: str | Path = ".", **kwargs: Any) -> HatchAnalyzer:
        """Audit Hatch pyproject.toml and hatch.toml for secrets, insecure indexes, and unpinned deps."""
        return HatchAnalyzer(str(path), **kwargs)

    def maturin(self, path: str | Path = ".", **kwargs: Any) -> MaturinAnalyzer:
        """Audit maturin pyproject.toml and Cargo.toml for secrets, insecure registries, and unpinned deps."""
        return MaturinAnalyzer(str(path), **kwargs)

    def cibuildwheel(self, path: str | Path = ".", **kwargs: Any) -> CibuildwheelAnalyzer:
        """Audit cibuildwheel configs for secrets, disabled tests, and insecure build hooks."""
        return CibuildwheelAnalyzer(str(path), **kwargs)

    def flit(self, path: str | Path = ".", **kwargs: Any) -> FlitAnalyzer:
        """Audit Flit pyproject.toml and flit.ini for secrets, insecure indexes, and unpinned deps."""
        return FlitAnalyzer(str(path), **kwargs)

    def pdm(self, path: str | Path = ".", **kwargs: Any) -> PdmAnalyzer:
        """Audit PDM pyproject.toml, .pdm.toml, and pdm.lock for secrets, insecure indexes, and unpinned deps."""
        return PdmAnalyzer(str(path), **kwargs)

    def uv(self, path: str | Path = ".", **kwargs: Any) -> UvAnalyzer:
        """Audit uv pyproject.toml and uv.toml for secrets, insecure indexes, and unpinned deps."""
        return UvAnalyzer(str(path), **kwargs)

    def rye(self, path: str | Path = ".", **kwargs: Any) -> RyeAnalyzer:
        """Audit Rye pyproject.toml, rye.lock, and requirements.lock for secrets and unpinned deps."""
        return RyeAnalyzer(str(path), **kwargs)

    def piptools(self, path: str | Path = ".", **kwargs: Any) -> PipToolsAnalyzer:
        """Audit pip-tools requirements.in, compiled requirements.txt, and pyproject.toml for secrets and unpinned deps."""
        return PipToolsAnalyzer(str(path), **kwargs)

    def setuptools(self, path: str | Path = ".", **kwargs: Any) -> SetuptoolsAnalyzer:
        """Audit setuptools setup.py, setup.cfg, and pyproject.toml for secrets, insecure indexes, and unpinned deps."""
        return SetuptoolsAnalyzer(str(path), **kwargs)

    def npm(self, path: str | Path = ".", **kwargs: Any) -> NpmAnalyzer:
        """Audit package.json and .npmrc for secrets, insecure registries, and unpinned deps."""
        return NpmAnalyzer(str(path), **kwargs)

    def pnpm(self, path: str | Path = ".", **kwargs: Any) -> PnpmAnalyzer:
        """Audit pnpm-workspace.yaml, pnpm-lock.yaml, .pnpmfile hooks, and pnpm .npmrc settings."""
        return PnpmAnalyzer(str(path), **kwargs)

    def bun(self, path: str | Path = ".", **kwargs: Any) -> BunAnalyzer:
        """Audit bunfig.toml, bun.lock, and Bun package.json settings for security risks."""
        return BunAnalyzer(str(path), **kwargs)

    def deno(self, path: str | Path = ".", **kwargs: Any) -> DenoAnalyzer:
        """Audit deno.json, deno.jsonc, import maps, and deno.lock for security risks."""
        return DenoAnalyzer(str(path), **kwargs)

    def vitest(self, path: str | Path = ".", **kwargs: Any) -> VitestAnalyzer:
        """Audit vitest.config.* and Vitest setup for security and CI reliability risks."""
        return VitestAnalyzer(str(path), **kwargs)

    def jest(self, path: str | Path = ".", **kwargs: Any) -> JestAnalyzer:
        """Audit jest.config.* and package.json jest blocks for secrets, dangerous setup, and CI risks."""
        return JestAnalyzer(str(path), **kwargs)

    def playwright(self, path: str | Path = ".", **kwargs: Any) -> PlaywrightAnalyzer:
        """Audit playwright.config.* for TLS bypass, sandbox disable, remote debug, and artifact leaks."""
        return PlaywrightAnalyzer(str(path), **kwargs)

    def cypress(self, path: str | Path = ".", **kwargs: Any) -> CypressAnalyzer:
        """Audit cypress.config.* and cypress.json for chromeWebSecurity, secrets in env, and insecure baseUrl."""
        return CypressAnalyzer(str(path), **kwargs)

    def mocha(self, path: str | Path = ".", **kwargs: Any) -> MochaAnalyzer:
        """Audit .mocharc.* and mocha.opts for allowUncaught, require paths, and CI risks."""
        return MochaAnalyzer(str(path), **kwargs)

    def pytest(self, path: str | Path = ".", **kwargs: Any) -> PytestAnalyzer:
        """Audit pytest.ini, pyproject.toml, and conftest.py for secrets, --pdb, and CI risks."""
        return PytestAnalyzer(str(path), **kwargs)

    def tox(self, path: str | Path = ".", **kwargs: Any) -> ToxAnalyzer:
        """Audit tox.ini for passenv=*, allowlist_externals=*, insecure indexes, and dangerous commands."""
        return ToxAnalyzer(str(path), **kwargs)

    def nox(self, path: str | Path = ".", **kwargs: Any) -> NoxAnalyzer:
        """Audit noxfile.py for reuse_venv, venv_backend='none', insecure indexes, and dangerous commands."""
        return NoxAnalyzer(str(path), **kwargs)

    def ruff(self, path: str | Path = ".", **kwargs: Any) -> RuffAnalyzer:
        """Audit ruff.toml and pyproject.toml [tool.ruff] for unsafe-fixes, disabled S rules, and broad ignores."""
        return RuffAnalyzer(str(path), **kwargs)

    def mypy(self, path: str | Path = ".", **kwargs: Any) -> MypyAnalyzer:
        """Audit mypy.ini and pyproject.toml [tool.mypy] for ignore_missing_imports, follow_imports=skip, and disabled strict mode."""
        return MypyAnalyzer(str(path), **kwargs)

    def coverage(self, path: str | Path = ".", **kwargs: Any) -> CoverageAnalyzer:
        """Audit .coveragerc and pyproject.toml [tool.coverage] for low fail_under, broad omit patterns, and skip_covered."""
        return CoverageAnalyzer(str(path), **kwargs)

    def black(self, path: str | Path = ".", **kwargs: Any) -> BlackAnalyzer:
        """Audit pyproject.toml [tool.black] for skip-string-normalization, preview, and broad exclude patterns."""
        return BlackAnalyzer(str(path), **kwargs)

    def isort(self, path: str | Path = ".", **kwargs: Any) -> IsortAnalyzer:
        """Audit isort configs for skip patterns, honor_noqa=false, and Black profile conflicts."""
        return IsortAnalyzer(str(path), **kwargs)

    def flake8(self, path: str | Path = ".", **kwargs: Any) -> Flake8Analyzer:
        """Audit Flake8 configs for broad ignores, disabled S rules, and source exclusions."""
        return Flake8Analyzer(str(path), **kwargs)

    def pyright(self, path: str | Path = ".", **kwargs: Any) -> PyrightAnalyzer:
        """Audit pyrightconfig.json and pyproject.toml [tool.pyright] for relaxed type checking."""
        return PyrightAnalyzer(str(path), **kwargs)

    def pylint(self, path: str | Path = ".", **kwargs: Any) -> PylintAnalyzer:
        """Audit Pylint configs for broad disables, unsafe init-hook, and security rule suppression."""
        return PylintAnalyzer(str(path), **kwargs)

    def golangci(self, path: str | Path = ".", **kwargs: Any) -> GolangciLintAnalyzer:
        """Audit golangci-lint configs for disabled gosec, broad skip patterns, and gosec excludes."""
        return GolangciLintAnalyzer(str(path), **kwargs)

    def rubocop(self, path: str | Path = ".", **kwargs: Any) -> RuboCopAnalyzer:
        """Audit RuboCop configs for disabled Security/* cops, broad Exclude patterns, and remote inherit_from."""
        return RuboCopAnalyzer(str(path), **kwargs)

    def shellcheck(self, path: str | Path = ".", **kwargs: Any) -> ShellcheckAnalyzer:
        """Audit ShellCheck configs for disabled quoting checks, wildcard disables, and external-sources risks."""
        return ShellcheckAnalyzer(str(path), **kwargs)

    def yamllint(self, path: str | Path = ".", **kwargs: Any) -> YamllintAnalyzer:
        """Audit yamllint configs for disabled truthy/key-duplicates checks, relaxed extends, and broad ignores."""
        return YamllintAnalyzer(str(path), **kwargs)

    def hadolint(self, path: str | Path = ".", **kwargs: Any) -> HadolintAnalyzer:
        """Audit Hadolint configs for ignored security rules, wildcard suppressions, and permissive thresholds."""
        return HadolintAnalyzer(str(path), **kwargs)

    def markdownlint(self, path: str | Path = ".", **kwargs: Any) -> MarkdownlintAnalyzer:
        """Audit markdownlint configs for disabled inline-HTML checks, wildcard suppressions, and broad ignores."""
        return MarkdownlintAnalyzer(str(path), **kwargs)

    def tsconfig(self, path: str | Path = ".", **kwargs: Any) -> TsconfigAnalyzer:
        """Audit tsconfig/jsconfig files for disabled strict mode, secrets, and broad exclude patterns."""
        return TsconfigAnalyzer(str(path), **kwargs)

    def vite(self, path: str | Path = ".", **kwargs: Any) -> ViteAnalyzer:
        """Audit vite.config.* for exposed dev servers, secrets, permissive fs.allow, and production sourcemaps."""
        return ViteAnalyzer(str(path), **kwargs)

    def next(self, path: str | Path = ".", **kwargs: Any) -> NextAnalyzer:
        """Audit next.config.* for production sourcemaps, disabled checks, permissive image origins, and SSRF rewrites."""
        return NextAnalyzer(str(path), **kwargs)

    def astro(self, path: str | Path = ".", **kwargs: Any) -> AstroAnalyzer:
        """Audit astro.config.* for exposed dev servers, disabled origin checks, permissive image domains, and SSRF redirects."""
        return AstroAnalyzer(str(path), **kwargs)

    def nuxt(self, path: str | Path = ".", **kwargs: Any) -> NuxtAnalyzer:
        """Audit nuxt.config.* for runtimeConfig leaks, exposed dev servers, internal proxies, and production devtools."""
        return NuxtAnalyzer(str(path), **kwargs)

    def qwik(self, path: str | Path = ".", **kwargs: Any) -> QwikAnalyzer:
        """Audit Qwik City vite.config.* for exposed dev servers, internal proxies, and adapter credential leaks."""
        return QwikAnalyzer(str(path), **kwargs)

    def gatsby(self, path: str | Path = ".", **kwargs: Any) -> GatsbyAnalyzer:
        """Audit gatsby-config.* for HTTP site URLs, GraphQL playground exposure, and plugin credential leaks."""
        return GatsbyAnalyzer(str(path), **kwargs)

    def hono(self, path: str | Path = ".", **kwargs: Any) -> HonoAnalyzer:
        """Audit Hono apps for hardcoded auth, open CORS, insecure cookies, and wrangler secret leaks."""
        return HonoAnalyzer(str(path), **kwargs)

    def fastify(self, path: str | Path = ".", **kwargs: Any) -> FastifyAnalyzer:
        """Audit Fastify apps for hardcoded JWT secrets, open CORS, disabled body limits, and SSRF risks."""
        return FastifyAnalyzer(str(path), **kwargs)

    def express(self, path: str | Path = ".", **kwargs: Any) -> ExpressAnalyzer:
        """Audit Express apps for hardcoded session secrets, open CORS, insecure cookies, and SSRF risks."""
        return ExpressAnalyzer(str(path), **kwargs)

    def nestjs(self, path: str | Path = ".", **kwargs: Any) -> NestJSAnalyzer:
        """Audit NestJS apps for hardcoded JWT secrets, open CORS, disabled validation, and SSRF risks."""
        return NestJSAnalyzer(str(path), **kwargs)

    def fastapi(self, path: str | Path = ".", **kwargs: Any) -> FastAPIAnalyzer:
        """Audit FastAPI apps for hardcoded secrets, open CORS, exposed docs, debug mode, and SSRF risks."""
        return FastAPIAnalyzer(str(path), **kwargs)

    def flask(self, path: str | Path = ".", **kwargs: Any) -> FlaskAnalyzer:
        """Audit Flask apps for hardcoded secrets, open CORS, debug mode, SSTI, shell commands, and SSRF risks."""
        return FlaskAnalyzer(str(path), **kwargs)

    def django(self, path: str | Path = ".", **kwargs: Any) -> DjangoAnalyzer:
        """Audit Django apps for hardcoded secrets, DEBUG mode, wildcard ALLOWED_HOSTS, CSRF bypass, and SSRF risks."""
        return DjangoAnalyzer(str(path), **kwargs)

    def starlette(self, path: str | Path = ".", **kwargs: Any) -> StarletteAnalyzer:
        """Audit Starlette apps for hardcoded secrets, open CORS, unsafe StaticFiles mounts, and SSRF risks."""
        return StarletteAnalyzer(str(path), **kwargs)

    def litestar(self, path: str | Path = ".", **kwargs: Any) -> LitestarAnalyzer:
        """Audit Litestar apps for hardcoded secrets, open CORS, disabled CSRF, exposed OpenAPI, and SSRF risks."""
        return LitestarAnalyzer(str(path), **kwargs)

    def aiohttp(self, path: str | Path = ".", **kwargs: Any) -> AiohttpAnalyzer:
        """Audit aiohttp apps for hardcoded secrets, open CORS, debug mode, disabled TLS verification, and SSRF risks."""
        return AiohttpAnalyzer(str(path), **kwargs)

    def quart(self, path: str | Path = ".", **kwargs: Any) -> QuartAnalyzer:
        """Audit Quart apps for hardcoded secrets, open CORS, debug mode, SSTI, shell commands, and SSRF risks."""
        return QuartAnalyzer(str(path), **kwargs)

    def sanic(self, path: str | Path = ".", **kwargs: Any) -> SanicAnalyzer:
        """Audit Sanic apps for hardcoded secrets, open CORS, debug mode, SSTI, shell commands, and SSRF risks."""
        return SanicAnalyzer(str(path), **kwargs)

    def falcon(self, path: str | Path = ".", **kwargs: Any) -> FalconAnalyzer:
        """Audit Falcon apps for hardcoded secrets, open CORS, debug mode, shell commands, and SSRF risks."""
        return FalconAnalyzer(str(path), **kwargs)

    def tornado(self, path: str | Path = ".", **kwargs: Any) -> TornadoAnalyzer:
        """Audit Tornado apps for hardcoded secrets, disabled XSRF, debug mode, shell commands, and SSRF risks."""
        return TornadoAnalyzer(str(path), **kwargs)

    def cherrypy(self, path: str | Path = ".", **kwargs: Any) -> CherryPyAnalyzer:
        """Audit CherryPy apps for hardcoded secrets, development mode, open CORS, shell commands, and SSRF risks."""
        return CherryPyAnalyzer(str(path), **kwargs)

    def bottle(self, path: str | Path = ".", **kwargs: Any) -> BottleAnalyzer:
        """Audit Bottle apps for hardcoded secrets, debug mode, open CORS, SSTI, shell commands, and SSRF risks."""
        return BottleAnalyzer(str(path), **kwargs)

    def pyramid(self, path: str | Path = ".", **kwargs: Any) -> PyramidAnalyzer:
        """Audit Pyramid apps for hardcoded secrets, debug toolbar, disabled CSRF, shell commands, and SSRF risks."""
        return PyramidAnalyzer(str(path), **kwargs)

    def web2py(self, path: str | Path = ".", **kwargs: Any) -> Web2pyAnalyzer:
        """Audit web2py apps for hardcoded secrets, DAL credentials, disabled CSRF, weak auth, and SSRF risks."""
        return Web2pyAnalyzer(str(path), **kwargs)

    def robyn(self, path: str | Path = ".", **kwargs: Any) -> RobynAnalyzer:
        """Audit Robyn apps for hardcoded secrets, debug mode, open CORS, shell commands, and SSRF risks."""
        return RobynAnalyzer(str(path), **kwargs)

    def blacksheep(self, path: str | Path = ".", **kwargs: Any) -> BlacksheepAnalyzer:
        """Audit BlackSheep apps for hardcoded secrets, reload mode, open CORS, shell commands, and SSRF risks."""
        return BlacksheepAnalyzer(str(path), **kwargs)

    def streamlit(self, path: str | Path = ".", **kwargs: Any) -> StreamlitAnalyzer:
        """Audit Streamlit apps for hardcoded secrets, unsafe HTML, disabled XSRF, and committed secrets files."""
        return StreamlitAnalyzer(str(path), **kwargs)

    def gradio(self, path: str | Path = ".", **kwargs: Any) -> GradioAnalyzer:
        """Audit Gradio apps for hardcoded secrets, public share links, disabled auth, and SSRF risks."""
        return GradioAnalyzer(str(path), **kwargs)

    def chainlit(self, path: str | Path = ".", **kwargs: Any) -> ChainlitAnalyzer:
        """Audit Chainlit apps for hardcoded secrets, missing auth, permissive CORS, and SSRF risks."""
        return ChainlitAnalyzer(str(path), **kwargs)

    def llamaindex(self, path: str | Path = ".", **kwargs: Any) -> LlamaIndexAnalyzer:
        """Audit LlamaIndex RAG pipelines for hardcoded API keys, SQL injection, SSRF, and deserialization risks."""
        return LlamaIndexAnalyzer(str(path), **kwargs)

    def langchain(self, path: str | Path = ".", **kwargs: Any) -> LangChainAnalyzer:
        """Audit LangChain agents and RAG chains for hardcoded API keys, dangerous tools, SQL injection, and SSRF risks."""
        return LangChainAnalyzer(str(path), **kwargs)

    def sveltekit(self, path: str | Path = ".", **kwargs: Any) -> SvelteKitAnalyzer:
        """Audit svelte.config.* for disabled CSRF checks, adapter credential leaks, and SSRF fetch targets."""
        return SvelteKitAnalyzer(str(path), **kwargs)

    def remix(self, path: str | Path = ".", **kwargs: Any) -> RemixAnalyzer:
        """Audit remix.config.* and vite.config.* for session secret leaks, allowedHosts: 'all', and SSRF proxies."""
        return RemixAnalyzer(str(path), **kwargs)

    def solid(self, path: str | Path = ".", **kwargs: Any) -> SolidAnalyzer:
        """Audit app.config.* and vite.config.* for SolidStart session secret leaks, disabled CSP, and SSRF proxies."""
        return SolidAnalyzer(str(path), **kwargs)

    def webpack(self, path: str | Path = ".", **kwargs: Any) -> WebpackAnalyzer:
        """Audit webpack.config.* for exposed dev servers, secrets, allowedHosts: 'all', and production sourcemaps."""
        return WebpackAnalyzer(str(path), **kwargs)

    def webdriverio(self, path: str | Path = ".", **kwargs: Any) -> WebdriverIOAnalyzer:
        """Audit wdio.conf.* for TLS bypass, sandbox disable, remote debug, and artifact leaks."""
        return WebdriverIOAnalyzer(str(path), **kwargs)

    def cargo(self, path: str | Path = ".", **kwargs: Any) -> CargoAnalyzer:
        """Audit Cargo.toml and .cargo/config.toml for secrets, insecure registries, and unpinned deps."""
        return CargoAnalyzer(str(path), **kwargs)

    def go_mod(self, path: str | Path = ".", **kwargs: Any) -> GoModAnalyzer:
        """Audit go.mod, go.sum, and go.env for secrets, insecure proxies, and checksum bypasses."""
        return GoModAnalyzer(str(path), **kwargs)

    def composer(self, path: str | Path = ".", **kwargs: Any) -> ComposerAnalyzer:
        """Audit composer.json and auth.json for secrets, insecure repos, and unpinned deps."""
        return ComposerAnalyzer(str(path), **kwargs)

    def bundler(self, path: str | Path = ".", **kwargs: Any) -> BundlerAnalyzer:
        """Audit Gemfile, gems.rb, and .bundle/config for secrets, insecure sources, and unpinned deps."""
        return BundlerAnalyzer(str(path), **kwargs)

    def mix(self, path: str | Path = ".", **kwargs: Any) -> MixAnalyzer:
        """Audit mix.exs and config/*.exs for secrets, insecure Hex repos, and unpinned deps."""
        return MixAnalyzer(str(path), **kwargs)

    def sbt(self, path: str | Path = ".", **kwargs: Any) -> SbtAnalyzer:
        """Audit build.sbt and project/*.sbt for secrets, insecure resolvers, and unpinned deps."""
        return SbtAnalyzer(str(path), **kwargs)

    def leiningen(self, path: str | Path = ".", **kwargs: Any) -> LeiningenAnalyzer:
        """Audit project.clj and profiles.clj for secrets, insecure repos, and unpinned deps."""
        return LeiningenAnalyzer(str(path), **kwargs)

    def cmake(self, path: str | Path = ".", **kwargs: Any) -> CMakeAnalyzer:
        """Audit CMakeLists.txt and cmake modules for secrets, insecure downloads, and unpinned deps."""
        return CMakeAnalyzer(str(path), **kwargs)

    def meson(self, path: str | Path = ".", **kwargs: Any) -> MesonAnalyzer:
        """Audit meson.build, wrap files, and meson options for secrets, insecure downloads, and unpinned deps."""
        return MesonAnalyzer(str(path), **kwargs)

    def conan(self, path: str | Path = ".", **kwargs: Any) -> ConanAnalyzer:
        """Audit Conan conanfiles, profiles, and remotes for secrets, insecure downloads, and unpinned deps."""
        return ConanAnalyzer(str(path), **kwargs)

    def vcpkg(self, path: str | Path = ".", **kwargs: Any) -> VcpkgAnalyzer:
        """Audit vcpkg.json manifests, portfiles, and registry config for secrets, insecure downloads, and unpinned deps."""
        return VcpkgAnalyzer(str(path), **kwargs)

    def nix(self, path: str | Path = ".", **kwargs: Any) -> NixAnalyzer:
        """Audit flake.nix, shell.nix, and Nix configs for secrets, insecure substituters, and unpinned inputs."""
        return NixAnalyzer(str(path), **kwargs)

    def mise(self, path: str | Path = ".", **kwargs: Any) -> MiseAnalyzer:
        """Audit mise.toml and .tool-versions for secrets, insecure plugin URLs, and dangerous tasks."""
        return MiseAnalyzer(str(path), **kwargs)

    def turbo(self, path: str | Path = ".", **kwargs: Any) -> TurboAnalyzer:
        """Audit turbo.json and turbo.jsonc for secrets, cache signature bypasses, and sensitive env vars."""
        return TurboAnalyzer(str(path), **kwargs)

    def nx(self, path: str | Path = ".", **kwargs: Any) -> NxAnalyzer:
        """Audit nx.json and project.json for secrets, Nx Cloud tokens, and sensitive cache inputs."""
        return NxAnalyzer(str(path), **kwargs)

    def direnv(self, path: str | Path = ".", **kwargs: Any) -> DirenvAnalyzer:
        """Audit .envrc and direnv.toml for secrets, disabled strict_env, and dangerous hooks."""
        return DirenvAnalyzer(str(path), **kwargs)

    def just(self, path: str | Path = ".", **kwargs: Any) -> JustAnalyzer:
        """Audit justfile and Just recipes for secrets, curl|sh, sudo, and dangerous shell commands."""
        return JustAnalyzer(str(path), **kwargs)

    def taskfile(self, path: str | Path = ".", **kwargs: Any) -> TaskfileAnalyzer:
        """Audit Taskfile.yml and taskfile.yaml for secrets, remote includes, and dangerous commands."""
        return TaskfileAnalyzer(str(path), **kwargs)

    def lefthook(self, path: str | Path = ".", **kwargs: Any) -> LefthookAnalyzer:
        """Audit lefthook.yml and .lefthook/*.yml for secrets, remote extends, and dangerous hook commands."""
        return LefthookAnalyzer(str(path), **kwargs)

    def eslint(self, path: str | Path = ".", **kwargs: Any) -> ESLintAnalyzer:
        """Audit .eslintrc.* and eslint.config.js for secrets, disabled security rules, and insecure extends."""
        return ESLintAnalyzer(str(path), **kwargs)

    def husky(self, path: str | Path = ".", **kwargs: Any) -> HuskyAnalyzer:
        """Audit .husky/* hook scripts for secrets, curl|sh, sudo, and unpinned npx commands."""
        return HuskyAnalyzer(str(path), **kwargs)

    def biome(self, path: str | Path = ".", **kwargs: Any) -> BiomeAnalyzer:
        """Audit biome.json for secrets, disabled security rules, and insecure schema URLs."""
        return BiomeAnalyzer(str(path), **kwargs)

    def prettier(self, path: str | Path = ".", **kwargs: Any) -> PrettierAnalyzer:
        """Audit .prettierrc.* and prettier.config.js for secrets and insecure plugin URLs."""
        return PrettierAnalyzer(str(path), **kwargs)

    def stylelint(self, path: str | Path = ".", **kwargs: Any) -> StylelintAnalyzer:
        """Audit .stylelintrc.* and stylelint.config.js for secrets and insecure plugin URLs."""
        return StylelintAnalyzer(str(path), **kwargs)

    def commitlint(self, path: str | Path = ".", **kwargs: Any) -> CommitlintAnalyzer:
        """Audit .commitlintrc.* and commitlint.config.js for secrets and insecure extends URLs."""
        return CommitlintAnalyzer(str(path), **kwargs)

    def editorconfig(self, path: str | Path = ".", **kwargs: Any) -> EditorConfigAnalyzer:
        """Audit .editorconfig files for secrets, insecure URLs, and missing baseline settings."""
        return EditorConfigAnalyzer(str(path), **kwargs)

    def appveyor_ci(self, path: str | Path = ".", **kwargs: Any) -> AppVeyorCIAnalyzer:
        """Audit AppVeyor CI configs for hardcoded secrets, RDP exposure, and variable injection."""
        return AppVeyorCIAnalyzer(str(path), **kwargs)

    def gocd_ci(self, path: str | Path = ".", **kwargs: Any) -> GoCDCIAnalyzer:
        """Audit GoCD pipelines for hardcoded secrets, privileged containers, and GO_* variable injection."""
        return GoCDCIAnalyzer(str(path), **kwargs)

    def cirrus_ci(self, path: str | Path = ".", **kwargs: Any) -> CirrusCIAnalyzer:
        """Audit Cirrus CI pipelines for hardcoded secrets, privileged containers, and CIRRUS_* variable injection."""
        return CirrusCIAnalyzer(str(path), **kwargs)

    def hardcoded_config(self, path: str | Path = ".", **kwargs: Any) -> HardcodedConfigAnalyzer:
        """Detect hardcoded URLs, IPs, DB URLs, and secret env defaults."""
        return HardcodedConfigAnalyzer(str(path), **kwargs)

    def timing_attack(self, path: str | Path = ".", **kwargs: Any) -> TimingAttackAnalyzer:
        """Detect non-constant-time secret comparisons."""
        return TimingAttackAnalyzer(str(path), **kwargs)

    def security_scan(self, path: str | Path = ".", **kwargs: Any) -> SecurityScanner:
        """Run unified static security analysis (secrets, injections, dangerous calls)."""
        return SecurityScanner(str(path), **kwargs)

    @staticmethod
    def prompts() -> PromptRegistry:
        """Return the built-in and registered prompt template registry."""
        return PromptRegistry()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._runtime, name)
