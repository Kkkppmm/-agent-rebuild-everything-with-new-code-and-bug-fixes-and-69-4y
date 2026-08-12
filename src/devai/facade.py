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
