"""Command-line interface for DevAI."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from devai import CodeAssistant, DevAIConfig, CIReporter
from devai.agents import CoderAgent
from devai.batch_review import BatchReviewer
from devai.core import MockLLMClient
from devai.kit import DevKit
from devai.presets import list_presets
from devai.program import DevProgram
from devai.workflow import DevWorkflow
from devai.program_schema import program_schema
from devai.runtime import DevRuntime
from devai.schedule import cron_matches, validate_cron
from devai.library import ProgramLibrary
from devai.export import export_program_to_file
from devai.tools import ToolRegistry, git_diff, list_files, read_file, search_code
from devai.output import extract_code_blocks, extract_first_code_block


def _read_input(path_or_code: str) -> str:
    p = Path(path_or_code)
    if p.exists() and p.is_file():
        return p.read_text(encoding="utf-8", errors="replace")
    return path_or_code


def cmd_review(args: argparse.Namespace) -> None:
    assistant = _get_assistant(args)
    code = _read_input(args.code)
    print(assistant.review(code))


def cmd_batch_review(args: argparse.Namespace) -> None:
    assistant = _get_assistant(args)
    reviewer = BatchReviewer(assistant, max_workers=args.workers)
    if args.directory:
        report = reviewer.review_directory(
            args.directory,
            pattern=args.pattern,
            recursive=not args.no_recursive,
        )
    else:
        report = reviewer.review_files(args.files)
    if args.markdown:
        print(report.to_markdown())
    else:
        for result in report.results:
            print(f"## {result.path}")
            if result.error:
                print(f"ERROR: {result.error}")
            else:
                print(result.review)
            print()


def cmd_extract_blocks(args: argparse.Namespace) -> None:
    text = _read_input(args.text)
    if args.first:
        block = extract_first_code_block(text, language=args.language)
        if block is None:
            print("No code block found.", file=sys.stderr)
            sys.exit(1)
        print(block)
        return
    blocks = extract_code_blocks(text)
    if not blocks:
        print("No code blocks found.", file=sys.stderr)
        sys.exit(1)
    for i, block in enumerate(blocks, 1):
        lang = block.language or "text"
        if args.language and lang != args.language:
            continue
        if args.index and i != args.index:
            continue
        print(f"--- block {i} ({lang}) ---")
        print(block.code)
        if i < len(blocks):
            print()


def cmd_explain(args: argparse.Namespace) -> None:
    assistant = _get_assistant(args)
    code = _read_input(args.code)
    print(assistant.explain(code))


def cmd_debug(args: argparse.Namespace) -> None:
    assistant = _get_assistant(args)
    code = _read_input(args.code)
    print(assistant.debug(code, args.error))


def cmd_commit(args: argparse.Namespace) -> None:
    assistant = _get_assistant(args)
    diff = args.diff or git_diff()
    print(assistant.commit_message(diff))


def cmd_pr(args: argparse.Namespace) -> None:
    assistant = _get_assistant(args)
    diff = args.diff or git_diff()
    print(assistant.pr_description(args.title, diff))


def cmd_changelog(args: argparse.Namespace) -> None:
    assistant = _get_assistant(args)
    print(assistant.changelog(args.version, args.changes))


def cmd_tests(args: argparse.Namespace) -> None:
    assistant = _get_assistant(args)
    code = _read_input(args.code)
    print(assistant.tests(code, framework=args.framework))


def cmd_security(args: argparse.Namespace) -> None:
    assistant = _get_assistant(args)
    code = _read_input(args.code)
    print(assistant.security(code))


def cmd_refactor(args: argparse.Namespace) -> None:
    assistant = _get_assistant(args)
    code = _read_input(args.code)
    print(assistant.refactor(code, goals=args.goals))


def cmd_docstring(args: argparse.Namespace) -> None:
    assistant = _get_assistant(args)
    code = _read_input(args.code)
    print(assistant.docstring(code))


def cmd_api(args: argparse.Namespace) -> None:
    assistant = _get_assistant(args)
    code = _read_input(args.code)
    print(assistant.api_design(code, context=args.context))


def cmd_openapi(args: argparse.Namespace) -> None:
    assistant = _get_assistant(args)
    spec = _read_input(args.spec)
    print(assistant.review_openapi(spec, context=args.context))


def cmd_test_failures(args: argparse.Namespace) -> None:
    assistant = _get_assistant(args)
    output = _read_input(args.output)
    code = _read_input(args.code) if args.code else ""
    print(assistant.analyze_test_failures(output, code=code))


def cmd_stacktrace(args: argparse.Namespace) -> None:
    assistant = _get_assistant(args)
    trace = _read_input(args.trace)
    print(assistant.analyze_stacktrace(trace, context=args.context))


def cmd_config_review(args: argparse.Namespace) -> None:
    assistant = _get_assistant(args)
    config = _read_input(args.config)
    print(assistant.review_config(config, config_type=args.type, context=args.context))


def cmd_notebook(args: argparse.Namespace) -> None:
    assistant = _get_assistant(args)
    if args.cells:
        results = assistant.review_notebook_cells(args.notebook)
        for index, review in sorted(results.items()):
            print(f"## Cell {index}\n{review}\n")
    else:
        print(assistant.review_notebook(args.notebook))


def cmd_symbols(args: argparse.Namespace) -> None:
    from devai.index import CodeSymbolIndex

    index = CodeSymbolIndex(args.directory)
    if args.search:
        symbols = index.search(args.search, kind=args.kind)
        if not symbols:
            print(f"No symbols matching '{args.search}'")
            return
        for symbol in symbols:
            print(f"[{symbol.kind}] {symbol.qualified_name()} @ {symbol.path}:{symbol.lineno}")
        return
    if args.context:
        print(index.to_context(args.context))
        return
    print(index.summary())
    if args.verbose:
        for symbol in index.symbols:
            print(f"[{symbol.kind}] {symbol.qualified_name()} @ {symbol.path}:{symbol.lineno}")


def cmd_imports(args: argparse.Namespace) -> None:
    from devai.import_graph import ImportGraph

    graph = ImportGraph(args.directory)
    if args.module:
        print(graph.to_context(args.module))
        return
    if args.cycles:
        cycles = graph.find_cycles()
        if not cycles:
            print("No circular imports found.")
            return
        for cycle in cycles:
            print(" -> ".join(cycle))
        return
    print(graph.summary())
    if args.verbose:
        for edge in graph.edges:
            print(f"{edge.source} -> {edge.target} @ line {edge.lineno}")


def cmd_secrets(args: argparse.Namespace) -> None:
    from devai.secrets import SecretsScanner

    scanner = SecretsScanner(args.directory)
    if args.context:
        print(scanner.to_context())
        return
    findings = scanner.scan()
    if not findings:
        print(scanner.summary())
        return
    print(scanner.summary())
    for finding in findings:
        print(finding.format())


def cmd_git_changelog(args: argparse.Namespace) -> None:
    assistant = _get_assistant(args)
    print(
        assistant.git_changelog(
            args.version,
            directory=args.directory,
            from_ref=args.from_ref,
            polish=not args.raw,
        )
    )


def cmd_typing(args: argparse.Namespace) -> None:
    from devai.typing_coverage import TypingCoverage

    coverage = TypingCoverage(args.directory)
    if args.context:
        print(coverage.to_context())
        return
    print(coverage.summary())
    if args.verbose:
        for gap in coverage.analyze():
            print(gap.format())


def cmd_parse_deps(args: argparse.Namespace) -> None:
    from devai.deps_parser import DependencyParser

    parser = DependencyParser(args.directory)
    if args.context:
        print(parser.to_context())
        return
    print(parser.summary())
    if args.unpinned:
        for dep in parser.unpinned():
            print(dep.format())
    elif args.verbose:
        for dep in parser.parse():
            print(dep.format())


def cmd_health(args: argparse.Namespace) -> None:
    from devai.project_health import ProjectHealth

    health = ProjectHealth(
        args.directory,
        source_dir=args.source_dir,
        test_dir=args.test_dir,
        scan_secrets=not args.no_secrets,
    )
    report = health.analyze()
    if args.json:
        print(report.to_json())
        return
    if args.markdown:
        print(report.to_markdown())
        return
    if args.context:
        print(health.to_context())
        return
    print(report.summary())


def cmd_smells(args: argparse.Namespace) -> None:
    from devai.code_smells import CodeSmellDetector

    detector = CodeSmellDetector(args.directory)
    if args.context:
        print(detector.to_context())
        return
    print(detector.summary())
    if args.verbose:
        for smell in detector.analyze():
            print(smell.format())


def cmd_tech_debt(args: argparse.Namespace) -> None:
    from devai.tech_debt import TechDebtScanner

    scanner = TechDebtScanner(args.directory)
    if args.context:
        print(scanner.to_context())
        return
    print(scanner.summary())
    if args.verbose:
        for item in scanner.scan():
            print(item.format())


def cmd_env_vars(args: argparse.Namespace) -> None:
    from devai.env_vars import EnvVarAnalyzer

    analyzer = EnvVarAnalyzer(args.directory)
    if args.generate_example:
        print(analyzer.generate_example())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for gap in analyzer.analyze():
            print(gap.format())


def cmd_gitignore(args: argparse.Namespace) -> None:
    from devai.gitignore_analyzer import GitignoreAnalyzer

    analyzer = GitignoreAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for gap in analyzer.analyze():
            print(gap.format())


def cmd_dockerfile_audit(args: argparse.Namespace) -> None:
    from devai.dockerfile_analyzer import DockerfileAnalyzer

    analyzer = DockerfileAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_devcontainer_audit(args: argparse.Namespace) -> None:
    from devai.devcontainer_analyzer import DevContainerAnalyzer

    analyzer = DevContainerAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_workflow_audit(args: argparse.Namespace) -> None:
    from devai.workflow_analyzer import WorkflowAnalyzer

    analyzer = WorkflowAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_compose_audit(args: argparse.Namespace) -> None:
    from devai.compose_analyzer import ComposeAnalyzer

    analyzer = ComposeAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_precommit_audit(args: argparse.Namespace) -> None:
    from devai.precommit_analyzer import PrecommitAnalyzer

    analyzer = PrecommitAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_lefthook_audit(args: argparse.Namespace) -> None:
    from devai.lefthook_analyzer import LefthookAnalyzer

    analyzer = LefthookAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_eslint_audit(args: argparse.Namespace) -> None:
    from devai.eslint_analyzer import ESLintAnalyzer

    analyzer = ESLintAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_husky_audit(args: argparse.Namespace) -> None:
    from devai.husky_analyzer import HuskyAnalyzer

    analyzer = HuskyAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_biome_audit(args: argparse.Namespace) -> None:
    from devai.biome_analyzer import BiomeAnalyzer

    analyzer = BiomeAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_prettier_audit(args: argparse.Namespace) -> None:
    from devai.prettier_analyzer import PrettierAnalyzer

    analyzer = PrettierAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_stylelint_audit(args: argparse.Namespace) -> None:
    from devai.stylelint_analyzer import StylelintAnalyzer

    analyzer = StylelintAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_editorconfig_audit(args: argparse.Namespace) -> None:
    from devai.editorconfig_analyzer import EditorConfigAnalyzer

    analyzer = EditorConfigAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_pnpm_audit(args: argparse.Namespace) -> None:
    from devai.pnpm_analyzer import PnpmAnalyzer

    analyzer = PnpmAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_config())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_bun_audit(args: argparse.Namespace) -> None:
    from devai.bun_analyzer import BunAnalyzer

    analyzer = BunAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_config())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_deno_audit(args: argparse.Namespace) -> None:
    from devai.deno_analyzer import DenoAnalyzer

    analyzer = DenoAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_config())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_jest_audit(args: argparse.Namespace) -> None:
    from devai.jest_analyzer import JestAnalyzer

    analyzer = JestAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_vitest_audit(args: argparse.Namespace) -> None:
    from devai.vitest_analyzer import VitestAnalyzer

    analyzer = VitestAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_config())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_playwright_audit(args: argparse.Namespace) -> None:
    from devai.playwright_analyzer import PlaywrightAnalyzer

    analyzer = PlaywrightAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_cypress_audit(args: argparse.Namespace) -> None:
    from devai.cypress_analyzer import CypressAnalyzer

    analyzer = CypressAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_mocha_audit(args: argparse.Namespace) -> None:
    from devai.mocha_analyzer import MochaAnalyzer

    analyzer = MochaAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_pytest_audit(args: argparse.Namespace) -> None:
    from devai.pytest_analyzer import PytestAnalyzer

    analyzer = PytestAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_tox_audit(args: argparse.Namespace) -> None:
    from devai.tox_analyzer import ToxAnalyzer

    analyzer = ToxAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_nox_audit(args: argparse.Namespace) -> None:
    from devai.nox_analyzer import NoxAnalyzer

    analyzer = NoxAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_ruff_audit(args: argparse.Namespace) -> None:
    from devai.ruff_analyzer import RuffAnalyzer

    analyzer = RuffAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_mypy_audit(args: argparse.Namespace) -> None:
    from devai.mypy_analyzer import MypyAnalyzer

    analyzer = MypyAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_coverage_audit(args: argparse.Namespace) -> None:
    from devai.coverage_analyzer import CoverageAnalyzer

    analyzer = CoverageAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_black_audit(args: argparse.Namespace) -> None:
    from devai.black_analyzer import BlackAnalyzer

    analyzer = BlackAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_yamllint_audit(args: argparse.Namespace) -> None:
    from devai.yamllint_analyzer import YamllintAnalyzer

    analyzer = YamllintAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_shellcheck_audit(args: argparse.Namespace) -> None:
    from devai.shellcheck_analyzer import ShellcheckAnalyzer

    analyzer = ShellcheckAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_webdriverio_audit(args: argparse.Namespace) -> None:
    from devai.webdriverio_analyzer import WebdriverIOAnalyzer

    analyzer = WebdriverIOAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_commitlint_audit(args: argparse.Namespace) -> None:
    from devai.commitlint_analyzer import CommitlintAnalyzer

    analyzer = CommitlintAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_makefile_audit(args: argparse.Namespace) -> None:
    from devai.makefile_analyzer import MakefileAnalyzer

    analyzer = MakefileAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_kubernetes_audit(args: argparse.Namespace) -> None:
    from devai.kubernetes_analyzer import KubernetesAnalyzer

    analyzer = KubernetesAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_terraform_audit(args: argparse.Namespace) -> None:
    from devai.terraform_analyzer import TerraformAnalyzer

    analyzer = TerraformAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_nginx_audit(args: argparse.Namespace) -> None:
    from devai.nginx_analyzer import NginxAnalyzer

    analyzer = NginxAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_helm_audit(args: argparse.Namespace) -> None:
    from devai.helm_analyzer import HelmAnalyzer

    analyzer = HelmAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_values_snippet())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_ansible_audit(args: argparse.Namespace) -> None:
    from devai.ansible_analyzer import AnsibleAnalyzer

    analyzer = AnsibleAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_task_snippet())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_jenkins_audit(args: argparse.Namespace) -> None:
    from devai.jenkinsfile_analyzer import JenkinsfileAnalyzer

    analyzer = JenkinsfileAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_pipeline_snippet())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_gitlab_ci_audit(args: argparse.Namespace) -> None:
    from devai.gitlab_ci_analyzer import GitLabCIAnalyzer

    analyzer = GitLabCIAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_circleci_audit(args: argparse.Namespace) -> None:
    from devai.circleci_analyzer import CircleCIAnalyzer

    analyzer = CircleCIAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_bitbucket_pipelines_audit(args: argparse.Namespace) -> None:
    from devai.bitbucket_pipelines_analyzer import BitbucketPipelinesAnalyzer

    analyzer = BitbucketPipelinesAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_azure_pipelines_audit(args: argparse.Namespace) -> None:
    from devai.azure_pipelines_analyzer import AzurePipelinesAnalyzer

    analyzer = AzurePipelinesAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_travis_ci_audit(args: argparse.Namespace) -> None:
    from devai.travis_ci_analyzer import TravisCIAnalyzer

    analyzer = TravisCIAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_buildkite_audit(args: argparse.Namespace) -> None:
    from devai.buildkite_analyzer import BuildkiteAnalyzer

    analyzer = BuildkiteAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_drone_ci_audit(args: argparse.Namespace) -> None:
    from devai.drone_ci_analyzer import DroneCIAnalyzer

    analyzer = DroneCIAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_woodpecker_ci_audit(args: argparse.Namespace) -> None:
    from devai.woodpecker_ci_analyzer import WoodpeckerCIAnalyzer

    analyzer = WoodpeckerCIAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_codefresh_audit(args: argparse.Namespace) -> None:
    from devai.codefresh_analyzer import CodefreshAnalyzer

    analyzer = CodefreshAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_semaphore_ci_audit(args: argparse.Namespace) -> None:
    from devai.semaphore_ci_analyzer import SemaphoreCIAnalyzer

    analyzer = SemaphoreCIAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_concourse_ci_audit(args: argparse.Namespace) -> None:
    from devai.concourse_ci_analyzer import ConcourseCIAnalyzer

    analyzer = ConcourseCIAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_teamcity_audit(args: argparse.Namespace) -> None:
    from devai.teamcity_analyzer import TeamCityAnalyzer

    analyzer = TeamCityAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_cloud_build_audit(args: argparse.Namespace) -> None:
    from devai.cloud_build_analyzer import CloudBuildAnalyzer

    analyzer = CloudBuildAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_aws_codebuild_audit(args: argparse.Namespace) -> None:
    from devai.aws_codebuild_analyzer import AWSCodeBuildAnalyzer

    analyzer = AWSCodeBuildAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_aws_codepipeline_audit(args: argparse.Namespace) -> None:
    from devai.aws_codepipeline_analyzer import AWSCodePipelineAnalyzer

    analyzer = AWSCodePipelineAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_harness_ci_audit(args: argparse.Namespace) -> None:
    from devai.harness_ci_analyzer import HarnessCIAnalyzer

    analyzer = HarnessCIAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_buddy_ci_audit(args: argparse.Namespace) -> None:
    from devai.buddy_ci_analyzer import BuddyCIAnalyzer

    analyzer = BuddyCIAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_dependabot_audit(args: argparse.Namespace) -> None:
    from devai.dependabot_analyzer import DependabotAnalyzer

    analyzer = DependabotAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_renovate_audit(args: argparse.Namespace) -> None:
    from devai.renovate_analyzer import RenovateAnalyzer

    analyzer = RenovateAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_snyk_audit(args: argparse.Namespace) -> None:
    from devai.snyk_analyzer import SnykAnalyzer

    analyzer = SnykAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_trivy_audit(args: argparse.Namespace) -> None:
    from devai.trivy_analyzer import TrivyAnalyzer

    analyzer = TrivyAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_grype_audit(args: argparse.Namespace) -> None:
    from devai.grype_analyzer import GrypeAnalyzer

    analyzer = GrypeAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_syft_audit(args: argparse.Namespace) -> None:
    from devai.syft_analyzer import SyftAnalyzer

    analyzer = SyftAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_cosign_audit(args: argparse.Namespace) -> None:
    from devai.cosign_analyzer import CosignAnalyzer

    analyzer = CosignAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_semgrep_audit(args: argparse.Namespace) -> None:
    from devai.semgrep_analyzer import SemgrepAnalyzer

    analyzer = SemgrepAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_bandit_audit(args: argparse.Namespace) -> None:
    from devai.bandit_analyzer import BanditAnalyzer

    analyzer = BanditAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_gocd_ci_audit(args: argparse.Namespace) -> None:
    from devai.gocd_ci_analyzer import GoCDCIAnalyzer

    analyzer = GoCDCIAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_cirrus_ci_audit(args: argparse.Namespace) -> None:
    from devai.cirrus_ci_analyzer import CirrusCIAnalyzer

    analyzer = CirrusCIAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_appveyor_ci_audit(args: argparse.Namespace) -> None:
    from devai.appveyor_ci_analyzer import AppVeyorCIAnalyzer

    analyzer = AppVeyorCIAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_tekton_audit(args: argparse.Namespace) -> None:
    from devai.tekton_analyzer import TektonAnalyzer

    analyzer = TektonAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_argo_workflows_audit(args: argparse.Namespace) -> None:
    from devai.argo_workflows_analyzer import ArgoWorkflowsAnalyzer

    analyzer = ArgoWorkflowsAnalyzer(args.directory)
    if args.generate_template:
        print(analyzer.generate_hardened_template())
        return
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_duplicates(args: argparse.Namespace) -> None:
    from devai.duplicate_code import DuplicateCodeDetector

    detector = DuplicateCodeDetector(args.directory, min_lines=args.min_lines)
    if args.context:
        print(detector.to_context())
        return
    print(detector.summary())
    if args.verbose:
        for cluster in detector.analyze():
            print(cluster.format())


def cmd_dead_code(args: argparse.Namespace) -> None:
    from devai.dead_code import DeadCodeAnalyzer

    analyzer = DeadCodeAnalyzer(args.directory)
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for symbol in analyzer.analyze():
            print(symbol.format())


def cmd_api_surface(args: argparse.Namespace) -> None:
    from devai.api_surface import APISurfaceAnalyzer

    analyzer = APISurfaceAnalyzer(args.directory, source_dir=args.source_dir)
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for sym in analyzer.undocumented():
            print(sym.format())


def cmd_hotspots(args: argparse.Namespace) -> None:
    from devai.complexity_hotspots import ComplexityHotspotAnalyzer

    analyzer = ComplexityHotspotAnalyzer(
        args.directory,
        complexity_threshold=args.threshold,
        limit=args.limit,
    )
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())


def cmd_exceptions(args: argparse.Namespace) -> None:
    from devai.exception_analyzer import ExceptionHierarchyAnalyzer

    analyzer = ExceptionHierarchyAnalyzer(args.directory)
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for exc in analyzer.exceptions:
            print(exc.format())
        for handler in analyzer.broad_handlers:
            print(handler.format())


def cmd_coupling(args: argparse.Namespace) -> None:
    from devai.module_coupling import ModuleCouplingAnalyzer

    analyzer = ModuleCouplingAnalyzer(
        args.directory,
        instability_threshold=args.threshold,
        limit=args.limit,
    )
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())


def cmd_naming(args: argparse.Namespace) -> None:
    from devai.naming_conventions import NamingConventionAnalyzer

    analyzer = NamingConventionAnalyzer(args.directory)
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for violation in analyzer.analyze():
            print(violation.format())


def cmd_magic_numbers(args: argparse.Namespace) -> None:
    from devai.magic_numbers import MagicNumberDetector

    detector = MagicNumberDetector(args.directory)
    if args.context:
        print(detector.to_context())
        return
    print(detector.summary())
    if args.verbose:
        for finding in detector.analyze():
            print(finding.format())


def cmd_dangerous_calls(args: argparse.Namespace) -> None:
    from devai.dangerous_calls import DangerousCallsAnalyzer

    analyzer = DangerousCallsAnalyzer(args.directory)
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_sql_injection(args: argparse.Namespace) -> None:
    from devai.sql_injection import SQLInjectionAnalyzer

    analyzer = SQLInjectionAnalyzer(args.directory)
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_debug_artifacts(args: argparse.Namespace) -> None:
    from devai.debug_artifacts import DebugArtifactDetector

    detector = DebugArtifactDetector(args.directory)
    if args.context:
        print(detector.to_context())
        return
    print(detector.summary())
    if args.verbose:
        for finding in detector.analyze():
            print(finding.format())


def cmd_async_blocking(args: argparse.Namespace) -> None:
    from devai.async_blocking import AsyncBlockingDetector

    detector = AsyncBlockingDetector(args.directory)
    if args.context:
        print(detector.to_context())
        return
    print(detector.summary())
    if args.verbose:
        for finding in detector.analyze():
            print(finding.format())


def cmd_resource_leaks(args: argparse.Namespace) -> None:
    from devai.resource_leaks import ResourceLeakAnalyzer

    analyzer = ResourceLeakAnalyzer(args.directory)
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_insecure_random(args: argparse.Namespace) -> None:
    from devai.insecure_random import InsecureRandomAnalyzer

    analyzer = InsecureRandomAnalyzer(args.directory)
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_path_traversal(args: argparse.Namespace) -> None:
    from devai.path_traversal import PathTraversalAnalyzer

    analyzer = PathTraversalAnalyzer(args.directory)
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_weak_crypto(args: argparse.Namespace) -> None:
    from devai.weak_crypto import WeakCryptoAnalyzer

    analyzer = WeakCryptoAnalyzer(args.directory)
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_log_injection(args: argparse.Namespace) -> None:
    from devai.log_injection import LogInjectionAnalyzer

    analyzer = LogInjectionAnalyzer(args.directory)
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_command_injection(args: argparse.Namespace) -> None:
    from devai.command_injection import CommandInjectionAnalyzer

    analyzer = CommandInjectionAnalyzer(args.directory)
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_ssrf(args: argparse.Namespace) -> None:
    from devai.ssrf import SSRFAnalyzer

    analyzer = SSRFAnalyzer(args.directory)
    if args.context:
        print(analyzer.to_context())
        return
    print(analyzer.summary())
    if args.verbose:
        for finding in analyzer.analyze():
            print(finding.format())


def cmd_security_scan(args: argparse.Namespace) -> None:
    from devai.security_scan import SecurityScanner

    scanner = SecurityScanner(args.directory)
    if args.json:
        print(scanner.scan().to_json())
        return
    if args.markdown:
        print(scanner.scan().to_markdown())
        return
    if args.context:
        print(scanner.to_context())
        return
    print(scanner.summary())
    if args.verbose:
        report = scanner.scan()
        for cat in report.categories:
            print(f"\n[{cat.name}] {cat.summary}")


def cmd_sql(args: argparse.Namespace) -> None:
    assistant = _get_assistant(args)
    query = _read_input(args.query)
    print(assistant.optimize_sql(query, context=args.context))


def cmd_readme(args: argparse.Namespace) -> None:
    assistant = _get_assistant(args)
    print(assistant.readme(args.project, args.description))


def cmd_types(args: argparse.Namespace) -> None:
    assistant = _get_assistant(args)
    code = _read_input(args.code)
    print(assistant.type_hints(code))


def cmd_regex(args: argparse.Namespace) -> None:
    assistant = _get_assistant(args)
    print(assistant.regex(args.description, test_cases=args.test_cases))


def cmd_logs(args: argparse.Namespace) -> None:
    assistant = _get_assistant(args)
    logs = _read_input(args.logs)
    print(assistant.analyze_logs(logs))


def cmd_project(args: argparse.Namespace) -> None:
    assistant = _get_assistant(args)
    print(assistant.review_project(args.directory, query=args.query))


def cmd_diff(args: argparse.Namespace) -> None:
    assistant = _get_assistant(args)
    diff = args.diff or git_diff()
    print(assistant.review_diff(diff))


def cmd_performance(args: argparse.Namespace) -> None:
    assistant = _get_assistant(args)
    code = _read_input(args.code)
    print(assistant.performance(code, context=args.context))


def cmd_dockerfile(args: argparse.Namespace) -> None:
    assistant = _get_assistant(args)
    content = _read_input(args.dockerfile)
    print(assistant.dockerfile(content))


def cmd_migrate(args: argparse.Namespace) -> None:
    assistant = _get_assistant(args)
    code = _read_input(args.code)
    print(
        assistant.migration_plan(
            code,
            source=args.source,
            target=args.target,
            constraints=args.constraints,
        )
    )


def cmd_generate(args: argparse.Namespace) -> None:
    assistant = _get_assistant(args)
    print(assistant.generate(args.spec, language=args.language))


def cmd_fix_lint(args: argparse.Namespace) -> None:
    assistant = _get_assistant(args)
    code = _read_input(args.code)
    lint_output = _read_input(args.lint_output)
    print(assistant.fix_lint(code, lint_output))


def cmd_deps(args: argparse.Namespace) -> None:
    assistant = _get_assistant(args)
    deps = _read_input(args.dependencies)
    print(assistant.audit_deps(deps, context=args.context))


def cmd_architecture(args: argparse.Namespace) -> None:
    assistant = _get_assistant(args)
    code = _read_input(args.code)
    print(assistant.architecture(code, context=args.context))


def cmd_incident(args: argparse.Namespace) -> None:
    assistant = _get_assistant(args)
    logs = _read_input(args.logs) if args.logs else ""
    print(assistant.incident_triage(args.symptoms, logs=logs))


def cmd_summarize(args: argparse.Namespace) -> None:
    assistant = _get_assistant(args)
    diff = args.diff or git_diff()
    print(assistant.summarize_changes(diff, audience=args.audience))


def cmd_upgrade_deps(args: argparse.Namespace) -> None:
    assistant = _get_assistant(args)
    deps = _read_input(args.dependencies)
    print(assistant.dependency_upgrade(deps, constraints=args.constraints))


def cmd_verify(args: argparse.Namespace) -> None:
    assistant = _get_assistant(args)
    test_code = _read_input(args.tests)
    result = assistant.generate_and_verify(
        args.spec,
        test_code,
        language=args.language,
        max_attempts=args.max_attempts,
    )
    print(result["code"])
    if not result["success"]:
        print("\n--- stderr ---\n", result["stderr"], file=sys.stderr)
        sys.exit(1)


def cmd_agent(args: argparse.Namespace) -> None:
    client = MockLLMClient() if args.mock else _get_assistant(args).client
    registry = ToolRegistry()
    registry.register(read_file)
    registry.register(search_code)
    registry.register(list_files)
    registry.register(git_diff)
    agent = CoderAgent(client=client, tools=registry)
    print(agent.run(args.task))


def cmd_validate(args: argparse.Namespace) -> None:
    assistant = CodeAssistant(client=MockLLMClient())
    program = DevProgram.from_file(args.program, assistant)
    errors = program.validate()
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        sys.exit(1)
    print(f"OK: {program.name} ({len(program.tasks)} tasks)")


def cmd_dry_run(args: argparse.Namespace) -> None:
    assistant = CodeAssistant(client=MockLLMClient())
    program = DevProgram.from_file(args.program, assistant)
    context: dict[str, str] = {}
    if args.code:
        context["code"] = _read_input(args.code)
    if args.diff:
        context["diff"] = _read_input(args.diff)
    if args.context:
        for pair in args.context:
            key, _, value = pair.partition("=")
            context[key] = value
    for step in program.dry_run(context):
        preview = step.input_preview[:60]
        if len(step.input_preview) > 60:
            preview += "..."
        print(f"{step.index}. {step.name} ({step.action})")
        print(f"   input[{step.input_key}]: {preview!r}")
        if step.kwargs:
            print(f"   kwargs: {step.kwargs}")


def cmd_schema(args: argparse.Namespace) -> None:
    import json

    print(json.dumps(program_schema(), indent=2))


def cmd_run(args: argparse.Namespace) -> None:
    assistant = _get_assistant(args)
    program = DevProgram.from_file(args.program, assistant)
    context: dict[str, str] = {}
    if args.code:
        context["code"] = _read_input(args.code)
    if args.diff:
        context["diff"] = _read_input(args.diff)
    if args.context:
        for pair in args.context:
            key, _, value = pair.partition("=")
            context[key] = value
    print(program.run_and_summarize(context))


def cmd_presets(args: argparse.Namespace) -> None:
    for preset in list_presets():
        print(f"{preset['name']}: {preset['description']}")


def cmd_workflow(args: argparse.Namespace) -> None:
    assistant = _get_assistant(args)
    workflow = DevWorkflow(name=args.name, assistant=assistant)
    for step in args.step:
        if ":" in step:
            step_name, preset = step.split(":", 1)
            workflow.add(step_name, preset)
        else:
            workflow.add(step, step)
    if args.parallel:
        parallel_workflow = DevWorkflow(name=args.name, assistant=assistant)
        group = "parallel"
        for step in args.step:
            if ":" in step:
                step_name, preset = step.split(":", 1)
                parallel_workflow.add(step_name, preset, parallel_group=group)
            else:
                parallel_workflow.add(step, step, parallel_group=group)
        workflow = parallel_workflow

    context: dict[str, str] = {}
    if args.code:
        context["code"] = _read_input(args.code)
    if args.diff:
        context["diff"] = _read_input(args.diff)
    if args.query:
        context["query"] = _read_input(args.query)
    if args.context:
        for pair in args.context:
            key, _, value = pair.partition("=")
            context[key] = value

    result = workflow.run(context)
    print(result.summarize())


def cmd_kit(args: argparse.Namespace) -> None:
    kit = DevKit.from_client(
        _get_assistant(args).client,
        project_path=args.project,
    )
    code = _read_input(args.code) if args.code else None
    handlers = {
        "audit": lambda: kit.audit(code),
        "pre-commit": lambda: kit.pre_commit(code),
        "release": lambda: kit.release_check(code),
        "onboard": lambda: kit.onboard(code),
        "pr-review": lambda: kit.review_pr(
            diff=_read_input(args.diff) if args.diff else None,
            code=code,
        ),
        "ci-gate": lambda: kit.ci_gate(code),
    }
    if args.workflow not in handlers:
        print(f"Unknown workflow: {args.workflow}", file=sys.stderr)
        sys.exit(1)
    print(handlers[args.workflow]())


def cmd_cron_validate(args: argparse.Namespace) -> None:
    expr = args.expression
    if validate_cron(expr):
        print(f"Valid cron expression: {expr}")
        if args.check:
            matches = cron_matches(expr)
            print(f"Matches now: {matches}")
    else:
        print(f"Invalid cron expression: {expr}", file=sys.stderr)
        sys.exit(1)


def cmd_schedule(args: argparse.Namespace) -> None:
    runtime = DevRuntime.create(use_mock=args.mock)
    schedule = runtime.schedule()
    schedule.add(args.name, args.cron, args.preset)
    context: dict[str, str] = {}
    if args.code:
        context["code"] = _read_input(args.code)
    if args.diff:
        context["diff"] = _read_input(args.diff)
    if args.context:
        for pair in args.context:
            key, _, value = pair.partition("=")
            context[key] = value

    if args.once:
        result = schedule.run_once(args.name, context)
        if result.success:
            print(runtime.summarize(result.results))  # type: ignore[arg-type]
        else:
            print(f"Error: {result.error}", file=sys.stderr)
            sys.exit(1)
    else:
        results = schedule.run_due()
        if not results:
            if not cron_matches(args.cron):
                print(f"Cron {args.cron!r} does not match current time. Use --once to run immediately.")
            else:
                print("No jobs ran (already executed this minute).")
        for result in results:
            if result.success:
                print(f"## {result.job_name}\n")
                print(runtime.summarize(result.results))  # type: ignore[arg-type]
            else:
                print(f"Error in {result.job_name}: {result.error}", file=sys.stderr)


def cmd_ci(args: argparse.Namespace) -> None:
    assistant = _get_assistant(args)
    reporter = CIReporter(assistant)
    context: dict[str, str] = {}
    if args.code:
        context["code"] = _read_input(args.code)
    if args.diff:
        context["diff"] = _read_input(args.diff)
    if args.context:
        for pair in args.context:
            key, _, value = pair.partition("=")
            context[key] = value

    if args.program:
        program = DevProgram.from_file(args.program, assistant)
        payload = reporter.run_program_for_ci(program, context, gate=not args.no_gate)
    else:
        preset = args.preset or "pre-commit"
        payload = reporter.run_program_for_ci(preset, context, gate=not args.no_gate)

    if args.format == "comment":
        print(payload["pr_comment"])
    elif args.format == "annotations":
        print("\n".join(payload["annotations"]))
    elif args.format == "gate":
        print(payload.get("gate_report", ""))
    else:
        print(payload["pr_comment"])
        if "gate_report" in payload:
            print("\n" + payload["gate_report"])

    if not args.no_gate and payload.get("passed") is False:
        sys.exit(1)


def cmd_health(args: argparse.Namespace) -> None:
    from devai.health import check_health

    result = check_health(
        provider=args.provider,
        model=args.model,
        api_key=args.api_key,
        use_mock=args.mock,
        probe=not args.no_probe,
    )
    print(f"healthy: {result.healthy}")
    print(f"provider: {result.provider}")
    print(f"model: {result.model}")
    print(f"latency_ms: {result.latency_ms:.2f}")
    print(f"message: {result.message}")
    if not result.healthy:
        sys.exit(1)


def cmd_git_review(args: argparse.Namespace) -> None:
    from devai.git_context import GitContext

    assistant = _get_assistant(args)
    ctx = GitContext(staged=args.staged, base=args.base)
    if args.commit:
        print(ctx.commit_message(assistant))
    elif args.pr:
        print(ctx.pr_description(assistant, title=args.title or ""))
    else:
        print(ctx.review_changes(assistant))


def cmd_trace_demo(args: argparse.Namespace) -> None:
    from devai.trace import DevTrace

    runtime = DevRuntime.create(use_mock=True)
    runtime.trace.clear()
    runtime.run("pre-commit", {"code": "def add(a, b): return a + b"}, trace=True)
    if args.json:
        print(runtime.trace.to_json())
    else:
        summary = runtime.trace.summary()
        print(f"trace_id: {summary['trace_id']}")
        print(f"span_count: {summary['span_count']}")
        print(f"total_duration_ms: {summary['total_duration_ms']}")


def cmd_config_init(args: argparse.Namespace) -> None:
    from devai.config_file import config_file_template

    target = Path(args.path)
    if target.exists() and not args.force:
        print(f"Config file already exists: {target}", file=sys.stderr)
        sys.exit(1)
    target.write_text(
        config_file_template(provider=args.provider, model=args.model),
        encoding="utf-8",
    )
    print(f"Created {target}")


def cmd_config_show(args: argparse.Namespace) -> None:
    from devai.config_file import find_config_file, load_config_file

    path = Path(args.path) if args.path else find_config_file()
    if path is None:
        print("No DevAI config file found.", file=sys.stderr)
        sys.exit(1)
    config = load_config_file(path)
    print(f"path: {path}")
    print(f"model: {config.model}")
    print(f"base_url: {config.base_url}")
    print(f"temperature: {config.temperature}")
    print(f"max_tokens: {config.max_tokens}")
    print(f"api_key_set: {bool(config.api_key)}")


def cmd_benchmark(args: argparse.Namespace) -> None:
    from devai.benchmark import BenchmarkRunner

    runtime = DevRuntime.create(use_mock=args.mock, provider=args.provider, model=args.model)
    runner = BenchmarkRunner(runtime.client, prompt=args.prompt)
    result = runner.run(iterations=args.iterations, name=args.name)
    if args.json:
        import json

        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(result.summary())
        if result.failures:
            sys.exit(1)


def cmd_context(args: argparse.Namespace) -> None:
    from devai.context import DevContext

    ctx = DevContext()
    if args.base:
        ctx.with_base(args.base)
    if args.max_tokens:
        ctx.with_max_tokens(args.max_tokens)
    for path in args.file or []:
        ctx.file(path)
    for snippet in args.snippet or []:
        lang, _, code = snippet.partition(":")
        ctx.snippet(code, language=lang or "text")
    if args.git:
        ctx.git_diff(staged=args.staged, base=args.base_ref)
    if args.text:
        ctx.text(args.text)
    for var in args.context or []:
        key, _, value = var.partition("=")
        ctx.vars(**{key: value})
    output = ctx.build()
    if args.tokens:
        print(f"tokens: {ctx.token_count()}")
    print(output)


def cmd_doctor(args: argparse.Namespace) -> None:
    from devai.doctor import DevDoctor

    doctor = DevDoctor(project_path=args.path, probe=not args.no_probe)
    if args.json:
        import json

        print(json.dumps(doctor.to_dict(), indent=2))
    else:
        print(doctor.summary())
    if not doctor.passed():
        sys.exit(1)


def cmd_report(args: argparse.Namespace) -> None:
    from devai.report import ProgramReport

    runtime = DevRuntime.create(use_mock=args.mock, provider=args.provider)
    context = {"code": _read_input(args.code)}
    results = runtime.run(args.preset, context)
    report = ProgramReport.from_program_results(
        results,
        title=f"Report: {args.preset}",
        program_name=args.preset,
    )
    if args.format == "json":
        print(report.to_json())
    else:
        print(report.to_markdown())


def cmd_library(args: argparse.Namespace) -> None:
    assistant = CodeAssistant(client=MockLLMClient())
    library = ProgramLibrary(Path(args.directory), assistant)
    if args.search:
        entries = library.search(args.search)
    else:
        entries = library.discover(recursive=args.recursive)
    if args.json:
        import json

        print(json.dumps([entry.to_dict() for entry in entries], indent=2))
        return
    for entry in entries:
        desc = f" — {entry.description}" if entry.description else ""
        print(f"{entry.name} ({entry.task_count} tasks){desc}")
        if args.verbose:
            print(f"  path: {entry.path}")
            print(f"  actions: {', '.join(entry.actions)}")


def cmd_apply_patch(args: argparse.Namespace) -> None:
    from devai.utils.diff import apply_unified_diff, extract_diff_from_text, read_diff

    if args.input == "-":
        diff_text = sys.stdin.read()
    elif Path(args.input).exists():
        diff_text = read_diff(args.input)
    else:
        diff_text = args.input
    diff_text = extract_diff_from_text(diff_text)
    result = apply_unified_diff(diff_text, root=args.root, dry_run=args.dry_run)
    if args.json:
        print(
            json.dumps(
                {
                    "applied": result.applied,
                    "files_changed": result.files_changed,
                    "errors": result.errors,
                },
                indent=2,
            )
        )
    else:
        if result.files_changed:
            print("Changed files:")
            for path in result.files_changed:
                print(f"  {path}")
        for error in result.errors:
            print(f"Error: {error}", file=sys.stderr)
        if args.dry_run:
            print("(dry run — no files written)")
    if result.errors:
        sys.exit(1)


def cmd_export(args: argparse.Namespace) -> None:
    assistant = CodeAssistant(client=MockLLMClient())
    program = DevProgram.from_file(args.program, assistant)
    output = Path(args.output)
    export_program_to_file(
        program,
        output,
        use_mock=args.mock,
        provider=args.provider,
        model=args.model,
    )
    print(f"Exported {program.name} to {output}")


def cmd_hooks(args: argparse.Namespace) -> None:
    from devai.hooks import DevHooks, SUPPORTED_HOOKS

    hooks = DevHooks(
        args.path or ".",
        preset=args.preset,
        fail_on_issues=not args.warn_only,
    )
    if args.action == "install":
        installed = hooks.install(args.hook or ["pre-commit"])
        if not installed:
            print("No hooks installed.")
            return
        for name in installed:
            print(f"Installed DevAI hook: {name}")
    elif args.action == "uninstall":
        removed = hooks.uninstall(args.hook or list(SUPPORTED_HOOKS))
        if not removed:
            print("No DevAI hooks to remove.")
            return
        for name in removed:
            print(f"Removed DevAI hook: {name}")
    elif args.action == "status":
        status = hooks.status()
        for name, state in status.items():
            print(f"{name}: {state}")
    else:
        raise SystemExit(f"Unknown hooks action: {args.action}")


def cmd_compare(args: argparse.Namespace) -> None:
    from devai.code_compare import CodeComparer

    assistant = _get_assistant(args)
    comparer = CodeComparer(assistant)
    if args.review:
        print(
            comparer.review_changes(
                args.before,
                args.after,
                before_label=args.before_label,
                after_label=args.after_label,
            )
        )
    elif args.summarize:
        print(
            comparer.summarize_changes(
                args.before,
                args.after,
                audience=args.audience,
                before_label=args.before_label,
                after_label=args.after_label,
            )
        )
    else:
        result = comparer.compare(
            args.before,
            args.after,
            before_label=args.before_label,
            after_label=args.after_label,
        )
        if args.stats:
            print(
                f"{result.before_label} -> {result.after_label}: "
                f"+{result.additions} -{result.deletions}"
            )
        print(result.diff)


def cmd_detect(args: argparse.Namespace) -> None:
    from devai.project_detect import ProjectDetector

    profile = ProjectDetector().detect(args.path)
    if args.json:
        import json

        print(
            json.dumps(
                {
                    "root": profile.root,
                    "languages": profile.languages,
                    "frameworks": profile.frameworks,
                    "package_managers": profile.package_managers,
                    "has_git": profile.has_git,
                    "has_tests": profile.has_tests,
                    "has_ci": profile.has_ci,
                    "python_version": profile.python_version,
                    "summary": profile.summary,
                },
                indent=2,
            )
        )
    else:
        print(profile.to_context())


def cmd_prompts(args: argparse.Namespace) -> None:
    from devai.prompt_registry import PromptRegistry

    registry = PromptRegistry()
    names = registry.list()
    if args.search:
        needle = args.search.lower()
        names = [n for n in names if needle in n]
    if args.json:
        import json

        print(json.dumps(names, indent=2))
    else:
        for name in names:
            if args.verbose:
                template = registry.get(name)
                vars_ = ", ".join(template.input_variables) or "none"
                print(f"{name} ({vars_})")
            else:
                print(name)


def _get_assistant(args: argparse.Namespace) -> CodeAssistant:
    if getattr(args, "mock", False):
        return CodeAssistant(client=MockLLMClient())
    config = DevAIConfig(
        api_key=getattr(args, "api_key", None),
        model=getattr(args, "model", "gpt-4o-mini"),
    )
    return CodeAssistant(config=config)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="devai",
        description="DevAI — AI tools for developers",
    )
    parser.add_argument("--mock", action="store_true", help="Use mock LLM (no API key)")
    parser.add_argument("--api-key", help="API key override")
    parser.add_argument("--model", default="gpt-4o-mini", help="Model name")

    sub = parser.add_subparsers(dest="command", help="Available commands")

    p = sub.add_parser("review", help="Review code")
    p.add_argument("code", help="Code or file path")
    p.set_defaults(func=cmd_review)

    p = sub.add_parser("batch-review", help="Review multiple files or a directory")
    p.add_argument("files", nargs="*", help="File paths to review")
    p.add_argument("--directory", "-d", help="Review all files in a directory")
    p.add_argument("--pattern", default="*.py", help="Glob pattern (with --directory)")
    p.add_argument("--no-recursive", action="store_true", help="Do not scan subdirectories")
    p.add_argument("--workers", type=int, default=4, help="Parallel review workers")
    p.add_argument("--markdown", action="store_true", help="Output as Markdown report")
    p.set_defaults(func=cmd_batch_review)

    p = sub.add_parser("extract-blocks", help="Extract fenced code blocks from text")
    p.add_argument("text", help="Text or file path containing code fences")
    p.add_argument("--language", help="Filter by language tag")
    p.add_argument("--first", action="store_true", help="Print only the first matching block")
    p.add_argument("--index", type=int, help="Print only the block at this 1-based index")
    p.set_defaults(func=cmd_extract_blocks)

    p = sub.add_parser("explain", help="Explain code")
    p.add_argument("code", help="Code or file path")
    p.set_defaults(func=cmd_explain)

    p = sub.add_parser("debug", help="Debug code with error")
    p.add_argument("--code", required=True, help="Code or file path")
    p.add_argument("--error", required=True, help="Error message")
    p.set_defaults(func=cmd_debug)

    p = sub.add_parser("commit", help="Generate commit message")
    p.add_argument("--diff", help="Git diff (defaults to git diff)")
    p.set_defaults(func=cmd_commit)

    p = sub.add_parser("pr", help="Generate PR description")
    p.add_argument("--title", required=True, help="PR title")
    p.add_argument("--diff", help="Git diff")
    p.set_defaults(func=cmd_pr)

    p = sub.add_parser("changelog", help="Generate changelog entry")
    p.add_argument("--version", required=True)
    p.add_argument("--changes", required=True)
    p.set_defaults(func=cmd_changelog)

    p = sub.add_parser("tests", help="Generate unit tests")
    p.add_argument("code", help="Code or file path")
    p.add_argument("--framework", default="pytest")
    p.set_defaults(func=cmd_tests)

    p = sub.add_parser("security", help="Security review")
    p.add_argument("code", help="Code or file path")
    p.set_defaults(func=cmd_security)

    p = sub.add_parser("refactor", help="Refactor code")
    p.add_argument("code", help="Code or file path")
    p.add_argument("--goals", default="improve readability")
    p.set_defaults(func=cmd_refactor)

    p = sub.add_parser("docstring", help="Generate docstrings")
    p.add_argument("code", help="Code or file path")
    p.set_defaults(func=cmd_docstring)

    p = sub.add_parser("api", help="Review API design")
    p.add_argument("code", help="Code or file path")
    p.add_argument("--context", default="", help="Additional context")
    p.set_defaults(func=cmd_api)

    p = sub.add_parser("openapi", help="Review an OpenAPI/Swagger specification")
    p.add_argument("spec", help="OpenAPI spec or file path")
    p.add_argument("--context", default="", help="Additional context")
    p.set_defaults(func=cmd_openapi)

    p = sub.add_parser("test-failures", help="Analyze pytest/unittest failure output")
    p.add_argument("output", help="Test failure output file or inline text")
    p.add_argument("--code", help="Source code context file or inline text")
    p.set_defaults(func=cmd_test_failures)

    p = sub.add_parser("stacktrace", help="Analyze a Python stack trace")
    p.add_argument("trace", help="Stack trace file or inline text")
    p.add_argument("--context", default="", help="Additional context")
    p.set_defaults(func=cmd_stacktrace)

    p = sub.add_parser("config-review", help="Review a project configuration file")
    p.add_argument("config", help="Config file path or inline content")
    p.add_argument(
        "--type",
        default="config",
        help="Config type label (e.g. pyproject.toml, docker-compose.yaml)",
    )
    p.add_argument("--context", default="", help="Additional context")
    p.set_defaults(func=cmd_config_review)

    p = sub.add_parser("notebook", help="Review a Jupyter notebook")
    p.add_argument("notebook", help="Path to .ipynb file")
    p.add_argument(
        "--cells",
        action="store_true",
        help="Review each code cell separately",
    )
    p.set_defaults(func=cmd_notebook)

    p = sub.add_parser("symbols", help="Index and search Python symbols in a project")
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--search", help="Search symbols by name")
    p.add_argument("--kind", choices=["function", "class", "method"], help="Filter by symbol kind")
    p.add_argument("--context", help="Build LLM context for matching symbols")
    p.add_argument("--verbose", "-v", action="store_true", help="List all indexed symbols")
    p.set_defaults(func=cmd_symbols)

    p = sub.add_parser("imports", help="Analyze Python import dependencies")
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--module", help="Focus on a specific module")
    p.add_argument("--cycles", action="store_true", help="List circular import chains")
    p.add_argument("--verbose", "-v", action="store_true", help="List all import edges")
    p.set_defaults(func=cmd_imports)

    p = sub.add_parser("secrets", help="Scan for hardcoded secrets")
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.set_defaults(func=cmd_secrets)

    p = sub.add_parser("git-changelog", help="Generate changelog from git history")
    p.add_argument("version", help="Version label for the changelog")
    p.add_argument("--directory", default=".", help="Git repository path")
    p.add_argument("--from-ref", help="Start ref (e.g. v1.0.0) for commit range")
    p.add_argument("--raw", action="store_true", help="Skip LLM polishing")
    p.set_defaults(func=cmd_git_changelog)

    p = sub.add_parser("typing", help="Analyze type hint coverage")
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List all typing gaps")
    p.set_defaults(func=cmd_typing)

    p = sub.add_parser("parse-deps", help="Parse and analyze project dependencies")
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--unpinned", action="store_true", help="List unpinned dependencies")
    p.add_argument("--verbose", "-v", action="store_true", help="List all dependencies")
    p.set_defaults(func=cmd_parse_deps)

    p = sub.add_parser("project-health", help="Unified project health dashboard")
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--source-dir", default="src", help="Source directory name")
    p.add_argument("--test-dir", default="tests", help="Test directory name")
    p.add_argument("--no-secrets", action="store_true", help="Skip secrets scanning")
    p.add_argument("--json", action="store_true", help="Output JSON report")
    p.add_argument("--markdown", action="store_true", help="Output Markdown report")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.set_defaults(func=cmd_health)

    p = sub.add_parser("smells", help="Detect code smells (long functions, nesting, etc.)")
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List all smells")
    p.set_defaults(func=cmd_smells)

    p = sub.add_parser("tech-debt", help="Scan for TODO, FIXME, HACK markers")
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List all markers")
    p.set_defaults(func=cmd_tech_debt)

    p = sub.add_parser("env-vars", help="Inventory env vars and detect config drift")
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List all gaps")
    p.add_argument(
        "--generate-example",
        action="store_true",
        help="Print a scaffolded .env.example from code references",
    )
    p.set_defaults(func=cmd_env_vars)

    p = sub.add_parser("gitignore", help="Audit .gitignore coverage and detect exposed files")
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List all gaps")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a scaffolded .gitignore from recommended patterns",
    )
    p.set_defaults(func=cmd_gitignore)

    p = sub.add_parser("dockerfile-audit", help="Audit Dockerfiles for security and best practices")
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List all findings")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened multi-stage Dockerfile template",
    )
    p.set_defaults(func=cmd_dockerfile_audit)

    p = sub.add_parser(
        "devcontainer-audit",
        help="Audit dev container configs for security and best practices",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List all findings")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened devcontainer.json template",
    )
    p.set_defaults(func=cmd_devcontainer_audit)

    p = sub.add_parser(
        "workflow-audit",
        help="Audit GitHub Actions workflows for security and CI best practices",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List all findings")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened GitHub Actions workflow template",
    )
    p.set_defaults(func=cmd_workflow_audit)

    p = sub.add_parser(
        "compose-audit",
        help="Audit Docker Compose files for security and container best practices",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List all findings")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened Docker Compose template",
    )
    p.set_defaults(func=cmd_compose_audit)

    p = sub.add_parser(
        "precommit-audit",
        help="Audit pre-commit config for unpinned hooks and unsafe entries",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List all findings")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened pre-commit configuration template",
    )
    p.set_defaults(func=cmd_precommit_audit)

    p = sub.add_parser(
        "lefthook-audit",
        help="Audit lefthook config for unpinned extends and unsafe hook commands",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List all findings")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened lefthook configuration template",
    )
    p.set_defaults(func=cmd_lefthook_audit)

    p = sub.add_parser(
        "eslint-audit",
        help="Audit ESLint configs for disabled security rules and insecure extends",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List all findings")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened ESLint flat config template",
    )
    p.set_defaults(func=cmd_eslint_audit)

    p = sub.add_parser(
        "jest-audit",
        help="Audit Jest configs and package.json jest blocks for security and CI risks",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List all findings")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened Jest config template",
    )
    p.set_defaults(func=cmd_jest_audit)

    p = sub.add_parser(
        "playwright-audit",
        help="Audit Playwright E2E configs for TLS bypass, sandbox disable, and artifact leaks",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List all findings")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened Playwright config template",
    )
    p.set_defaults(func=cmd_playwright_audit)

    p = sub.add_parser(
        "cypress-audit",
        help="Audit Cypress E2E configs for chromeWebSecurity, secrets in env, and insecure baseUrl",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List all findings")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened Cypress config template",
    )
    p.set_defaults(func=cmd_cypress_audit)

    p = sub.add_parser(
        "mocha-audit",
        help="Audit Mocha .mocharc.* configs for allowUncaught, require paths, and CI risks",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List all findings")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened .mocharc.json template",
    )
    p.set_defaults(func=cmd_mocha_audit)

    p = sub.add_parser(
        "pytest-audit",
        help="Audit pytest.ini, pyproject.toml, and conftest.py for --pdb, secrets, and CI risks",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List all findings")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened pytest.ini template",
    )
    p.set_defaults(func=cmd_pytest_audit)

    p = sub.add_parser(
        "tox-audit",
        help="Audit tox.ini for passenv=*, insecure indexes, and dangerous commands",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List all findings")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened tox.ini template",
    )
    p.set_defaults(func=cmd_tox_audit)

    p = sub.add_parser(
        "nox-audit",
        help="Audit noxfile.py for reuse_venv, venv_backend='none', insecure indexes, and dangerous commands",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List all findings")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened noxfile.py template",
    )
    p.set_defaults(func=cmd_nox_audit)

    p = sub.add_parser(
        "ruff-audit",
        help="Audit ruff.toml and pyproject.toml [tool.ruff] for unsafe-fixes and disabled security rules",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List all findings")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened Ruff configuration template",
    )
    p.set_defaults(func=cmd_ruff_audit)

    p = sub.add_parser(
        "mypy-audit",
        help="Audit mypy.ini and pyproject.toml [tool.mypy] for ignore_missing_imports and disabled strict mode",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List all findings")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened mypy configuration template",
    )
    p.set_defaults(func=cmd_mypy_audit)

    p = sub.add_parser(
        "coverage-audit",
        help="Audit .coveragerc and pyproject.toml [tool.coverage] for low fail_under and broad omit patterns",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List all findings")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened coverage.py configuration template",
    )
    p.set_defaults(func=cmd_coverage_audit)

    p = sub.add_parser(
        "black-audit",
        help="Audit pyproject.toml [tool.black] for skip-string-normalization, preview, and broad exclude patterns",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List all findings")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened Black configuration template",
    )
    p.set_defaults(func=cmd_black_audit)

    p = sub.add_parser(
        "yamllint-audit",
        help="Audit .yamllint configs for disabled truthy/key-duplicates checks and broad ignore patterns",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("-v", "--verbose", action="store_true", help="Print each finding")
    p.add_argument("--context", action="store_true", help="Print LLM-ready context")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened yamllint configuration template",
    )
    p.set_defaults(func=cmd_yamllint_audit)

    p = sub.add_parser(
        "shellcheck-audit",
        help="Audit ShellCheck configs for disabled quoting checks, wildcard disables, and external-sources risks",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("-v", "--verbose", action="store_true", help="Print each finding")
    p.add_argument("--context", action="store_true", help="Print LLM-ready context")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened ShellCheck configuration template",
    )
    p.set_defaults(func=cmd_shellcheck_audit)

    p = sub.add_parser(
        "webdriverio-audit",
        help="Audit WebdriverIO wdio.conf.* for TLS bypass, sandbox disable, and artifact leaks",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List all findings")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened wdio.conf.ts template",
    )
    p.set_defaults(func=cmd_webdriverio_audit)

    p = sub.add_parser(
        "husky-audit",
        help="Audit Husky git hooks for secrets, curl|sh, and dangerous commands",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List all findings")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print hardened Husky hook templates",
    )
    p.set_defaults(func=cmd_husky_audit)

    p = sub.add_parser(
        "biome-audit",
        help="Audit Biome configs for disabled security rules and insecure schema URLs",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List all findings")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened Biome configuration template",
    )
    p.set_defaults(func=cmd_biome_audit)

    p = sub.add_parser(
        "prettier-audit",
        help="Audit Prettier configs for secrets and insecure plugin URLs",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List all findings")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened Prettier configuration template",
    )
    p.set_defaults(func=cmd_prettier_audit)

    p = sub.add_parser(
        "stylelint-audit",
        help="Audit Stylelint configs for secrets and insecure plugin URLs",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List all findings")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened Stylelint configuration template",
    )
    p.set_defaults(func=cmd_stylelint_audit)

    p = sub.add_parser(
        "commitlint-audit",
        help="Audit Commitlint configs for secrets and insecure extends URLs",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List all findings")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened Commitlint configuration template",
    )
    p.set_defaults(func=cmd_commitlint_audit)

    p = sub.add_parser(
        "editorconfig-audit",
        help="Audit .editorconfig files for secrets and baseline editor settings",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List all findings")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened EditorConfig template",
    )
    p.set_defaults(func=cmd_editorconfig_audit)

    p = sub.add_parser(
        "pnpm-audit",
        help="Audit pnpm workspace, lockfile, .pnpmfile hooks, and pnpm .npmrc settings",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List all findings")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened pnpm workspace and .npmrc template",
    )
    p.set_defaults(func=cmd_pnpm_audit)

    p = sub.add_parser(
        "bun-audit",
        help="Audit bunfig.toml, bun.lock, and Bun package.json settings",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List all findings")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened bunfig.toml template",
    )
    p.set_defaults(func=cmd_bun_audit)

    p = sub.add_parser(
        "deno-audit",
        help="Audit deno.json, deno.jsonc, import maps, and deno.lock settings",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List all findings")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened deno.json template",
    )
    p.set_defaults(func=cmd_deno_audit)

    p = sub.add_parser(
        "vitest-audit",
        help="Audit vitest.config.* and Vitest setup for security and CI risks",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List all findings")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened vitest.config.ts template",
    )
    p.set_defaults(func=cmd_vitest_audit)

    p = sub.add_parser("makefile-audit", help="Audit Makefiles for security and build best practices")
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List all findings")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened Makefile template",
    )
    p.set_defaults(func=cmd_makefile_audit)

    p = sub.add_parser(
        "kubernetes-audit",
        help="Audit Kubernetes manifests for security misconfigurations",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List all findings")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened Kubernetes Deployment template",
    )
    p.set_defaults(func=cmd_kubernetes_audit)

    p = sub.add_parser(
        "terraform-audit",
        help="Audit Terraform files for security misconfigurations",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List all findings")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened Terraform S3 bucket template",
    )
    p.set_defaults(func=cmd_terraform_audit)

    p = sub.add_parser(
        "nginx-audit",
        help="Audit Nginx configs for weak TLS and security headers",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List all findings")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened Nginx server block template",
    )
    p.set_defaults(func=cmd_nginx_audit)

    p = sub.add_parser(
        "helm-audit",
        help="Audit Helm charts for privileged pods and hardcoded secrets",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List all findings")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened securityContext snippet for values.yaml",
    )
    p.set_defaults(func=cmd_helm_audit)

    p = sub.add_parser(
        "ansible-audit",
        help="Audit Ansible playbooks for hardcoded secrets and unsafe tasks",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--verbose", "-v", action="store_true", help="Show all findings")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened Ansible task snippet",
    )
    p.set_defaults(func=cmd_ansible_audit)

    p = sub.add_parser(
        "jenkins-audit",
        help="Audit Jenkinsfiles for script injection and hardcoded secrets",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--verbose", "-v", action="store_true", help="Show all findings")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened declarative pipeline skeleton",
    )
    p.set_defaults(func=cmd_jenkins_audit)

    p = sub.add_parser(
        "gitlab-ci-audit",
        help="Audit GitLab CI pipelines for hardcoded secrets and unsafe scripts",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--verbose", "-v", action="store_true", help="Show all findings")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened GitLab CI pipeline skeleton",
    )
    p.set_defaults(func=cmd_gitlab_ci_audit)

    p = sub.add_parser(
        "circleci-audit",
        help="Audit CircleCI configs for hardcoded secrets and unsafe scripts",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--verbose", "-v", action="store_true", help="Show all findings")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened CircleCI config skeleton",
    )
    p.set_defaults(func=cmd_circleci_audit)

    p = sub.add_parser(
        "bitbucket-pipelines-audit",
        help="Audit Bitbucket Pipelines for hardcoded secrets and unsafe scripts",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--verbose", "-v", action="store_true", help="Show all findings")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened Bitbucket Pipelines skeleton",
    )
    p.set_defaults(func=cmd_bitbucket_pipelines_audit)

    p = sub.add_parser(
        "azure-pipelines-audit",
        help="Audit Azure Pipelines for hardcoded secrets and unsafe scripts",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--verbose", "-v", action="store_true", help="Show all findings")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened Azure Pipelines skeleton",
    )
    p.set_defaults(func=cmd_azure_pipelines_audit)

    p = sub.add_parser(
        "travis-ci-audit",
        help="Audit Travis CI configs for hardcoded secrets and unsafe scripts",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--verbose", "-v", action="store_true", help="Show all findings")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened Travis CI skeleton",
    )
    p.set_defaults(func=cmd_travis_ci_audit)

    p = sub.add_parser(
        "buildkite-audit",
        help="Audit Buildkite pipelines for hardcoded secrets and unsafe scripts",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--verbose", "-v", action="store_true", help="Show all findings")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened Buildkite pipeline skeleton",
    )
    p.set_defaults(func=cmd_buildkite_audit)

    p = sub.add_parser(
        "drone-ci-audit",
        help="Audit Drone CI pipelines for hardcoded secrets and unsafe scripts",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--verbose", "-v", action="store_true", help="Show all findings")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened Drone CI pipeline skeleton",
    )
    p.set_defaults(func=cmd_drone_ci_audit)

    p = sub.add_parser(
        "woodpecker-ci-audit",
        help="Audit Woodpecker CI pipelines for hardcoded secrets and unsafe scripts",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--verbose", "-v", action="store_true", help="Show all findings")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened Woodpecker CI pipeline skeleton",
    )
    p.set_defaults(func=cmd_woodpecker_ci_audit)

    p = sub.add_parser(
        "codefresh-audit",
        help="Audit Codefresh pipelines for hardcoded secrets and unsafe scripts",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--verbose", "-v", action="store_true", help="Show all findings")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened Codefresh pipeline skeleton",
    )
    p.set_defaults(func=cmd_codefresh_audit)

    p = sub.add_parser(
        "semaphore-ci-audit",
        help="Audit Semaphore CI pipelines for hardcoded secrets and unsafe scripts",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--verbose", "-v", action="store_true", help="Show all findings")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened Semaphore CI pipeline skeleton",
    )
    p.set_defaults(func=cmd_semaphore_ci_audit)

    p = sub.add_parser(
        "concourse-ci-audit",
        help="Audit Concourse CI pipelines for hardcoded secrets and unsafe scripts",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--verbose", "-v", action="store_true", help="Show all findings")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened Concourse CI pipeline skeleton",
    )
    p.set_defaults(func=cmd_concourse_ci_audit)

    p = sub.add_parser(
        "teamcity-audit",
        help="Audit TeamCity pipelines for hardcoded secrets and unsafe scripts",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--verbose", "-v", action="store_true", help="Show all findings")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened TeamCity Kotlin DSL skeleton",
    )
    p.set_defaults(func=cmd_teamcity_audit)

    p = sub.add_parser(
        "cloud-build-audit",
        help="Audit Google Cloud Build pipelines for hardcoded secrets and unsafe scripts",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--verbose", "-v", action="store_true", help="Show all findings")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened Google Cloud Build pipeline skeleton",
    )
    p.set_defaults(func=cmd_cloud_build_audit)

    p = sub.add_parser(
        "aws-codebuild-audit",
        help="Audit AWS CodeBuild buildspec files for hardcoded secrets and unsafe scripts",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--verbose", "-v", action="store_true", help="Show all findings")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened AWS CodeBuild buildspec skeleton",
    )
    p.set_defaults(func=cmd_aws_codebuild_audit)

    p = sub.add_parser(
        "aws-codepipeline-audit",
        help="Audit AWS CodePipeline configs for hardcoded secrets and weak IAM",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--verbose", "-v", action="store_true", help="Show all findings")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened AWS CodePipeline CloudFormation skeleton",
    )
    p.set_defaults(func=cmd_aws_codepipeline_audit)

    p = sub.add_parser(
        "harness-ci-audit",
        help="Audit Harness CI pipelines for hardcoded secrets and unsafe scripts",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--verbose", "-v", action="store_true", help="Show all findings")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened Harness CI pipeline skeleton",
    )
    p.set_defaults(func=cmd_harness_ci_audit)

    p = sub.add_parser(
        "buddy-ci-audit",
        help="Audit Buddy CI pipelines for hardcoded secrets and unsafe scripts",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--verbose", "-v", action="store_true", help="Show all findings")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened Buddy CI pipeline skeleton",
    )
    p.set_defaults(func=cmd_buddy_ci_audit)

    p = sub.add_parser(
        "dependabot-audit",
        help="Audit Dependabot configs for hardcoded credentials and unsafe settings",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--verbose", "-v", action="store_true", help="Show all findings")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened Dependabot config skeleton",
    )
    p.set_defaults(func=cmd_dependabot_audit)

    p = sub.add_parser(
        "renovate-audit",
        help="Audit Renovate configs for hardcoded credentials and unsafe settings",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--verbose", "-v", action="store_true", help="Show all findings")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened Renovate config skeleton",
    )
    p.set_defaults(func=cmd_renovate_audit)

    p = sub.add_parser(
        "snyk-audit",
        help="Audit Snyk policy and CLI configs for hardcoded tokens and broad ignores",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--verbose", "-v", action="store_true", help="Show all findings")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened Snyk policy skeleton",
    )
    p.set_defaults(func=cmd_snyk_audit)

    p = sub.add_parser(
        "trivy-audit",
        help="Audit Trivy ignore files and CLI configs for hardcoded tokens and fail-open settings",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--verbose", "-v", action="store_true", help="Show all findings")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened Trivy config skeleton",
    )
    p.set_defaults(func=cmd_trivy_audit)

    p = sub.add_parser(
        "grype-audit",
        help="Audit Grype ignore files and CLI configs for hardcoded tokens and fail-open settings",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--verbose", "-v", action="store_true", help="Show all findings")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened Grype config skeleton",
    )
    p.set_defaults(func=cmd_grype_audit)

    p = sub.add_parser(
        "syft-audit",
        help="Audit Syft SBOM configs for hardcoded tokens and broad exclusions",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--verbose", "-v", action="store_true", help="Show all findings")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened Syft config skeleton",
    )
    p.set_defaults(func=cmd_syft_audit)

    p = sub.add_parser(
        "cosign-audit",
        help="Audit Cosign signing configs for hardcoded keys and disabled verification",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--verbose", "-v", action="store_true", help="Show all findings")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened Cosign config skeleton",
    )
    p.set_defaults(func=cmd_cosign_audit)

    p = sub.add_parser(
        "semgrep-audit",
        help="Audit Semgrep rule configs for hardcoded tokens and disabled rules",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--verbose", "-v", action="store_true", help="Show all findings")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened Semgrep config skeleton",
    )
    p.set_defaults(func=cmd_semgrep_audit)

    p = sub.add_parser(
        "bandit-audit",
        help="Audit Bandit configs for hardcoded tokens and broad security test skips",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--verbose", "-v", action="store_true", help="Show all findings")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened Bandit config skeleton",
    )
    p.set_defaults(func=cmd_bandit_audit)

    p = sub.add_parser(
        "appveyor-ci-audit",
        help="Audit AppVeyor CI configs for hardcoded secrets and unsafe scripts",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--verbose", "-v", action="store_true", help="Show all findings")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened AppVeyor CI config skeleton",
    )
    p.set_defaults(func=cmd_appveyor_ci_audit)

    p = sub.add_parser(
        "gocd-ci-audit",
        help="Audit GoCD pipelines for hardcoded secrets and unsafe scripts",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--verbose", "-v", action="store_true", help="Show all findings")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened GoCD pipeline skeleton",
    )
    p.set_defaults(func=cmd_gocd_ci_audit)

    p = sub.add_parser(
        "cirrus-ci-audit",
        help="Audit Cirrus CI pipelines for hardcoded secrets and unsafe scripts",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--verbose", "-v", action="store_true", help="Show all findings")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened Cirrus CI pipeline skeleton",
    )
    p.set_defaults(func=cmd_cirrus_ci_audit)

    p = sub.add_parser(
        "tekton-audit",
        help="Audit Tekton pipelines for hardcoded secrets and unsafe scripts",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--verbose", "-v", action="store_true", help="Show all findings")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened Tekton Pipeline skeleton",
    )
    p.set_defaults(func=cmd_tekton_audit)

    p = sub.add_parser(
        "argo-workflows-audit",
        help="Audit Argo Workflows for hardcoded secrets and unsafe scripts",
    )
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--verbose", "-v", action="store_true", help="Show all findings")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument(
        "--generate-template",
        action="store_true",
        help="Print a hardened Argo Workflow skeleton",
    )
    p.set_defaults(func=cmd_argo_workflows_audit)

    p = sub.add_parser("duplicates", help="Find duplicate code blocks")
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--min-lines", type=int, default=5, help="Minimum block size in lines")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List all clusters")
    p.set_defaults(func=cmd_duplicates)

    p = sub.add_parser("dead-code", help="Find potentially unused Python symbols")
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List all symbols")
    p.set_defaults(func=cmd_dead_code)

    p = sub.add_parser("api-surface", help="Map and analyze public API surface")
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--source-dir", default="src", help="Source directory name")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List undocumented symbols")
    p.set_defaults(func=cmd_api_surface)

    p = sub.add_parser("hotspots", help="Rank files by complexity debt")
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--threshold", type=int, default=10, help="Complexity threshold")
    p.add_argument("--limit", type=int, default=20, help="Max hotspots to show")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.set_defaults(func=cmd_hotspots)

    p = sub.add_parser("exceptions", help="Map custom exceptions and risky handlers")
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List all exceptions and handlers")
    p.set_defaults(func=cmd_exceptions)

    p = sub.add_parser("coupling", help="Analyze module coupling and instability")
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--threshold", type=float, default=0.8, help="Instability threshold")
    p.add_argument("--limit", type=int, default=20, help="Max modules to show")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.set_defaults(func=cmd_coupling)

    p = sub.add_parser("naming", help="Check PEP 8 naming conventions")
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List all violations")
    p.set_defaults(func=cmd_naming)

    p = sub.add_parser("magic-numbers", help="Find unexplained numeric literals")
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List all findings")
    p.set_defaults(func=cmd_magic_numbers)

    p = sub.add_parser("dangerous-calls", help="Detect risky Python calls and anti-patterns")
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List all findings")
    p.set_defaults(func=cmd_dangerous_calls)

    p = sub.add_parser("sql-injection", help="Detect dynamic SQL construction")
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List all findings")
    p.set_defaults(func=cmd_sql_injection)

    p = sub.add_parser("debug-artifacts", help="Find debug code left in sources")
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List all findings")
    p.set_defaults(func=cmd_debug_artifacts)

    p = sub.add_parser("async-blocking", help="Detect blocking calls in async functions")
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List all findings")
    p.set_defaults(func=cmd_async_blocking)

    p = sub.add_parser("resource-leaks", help="Detect unclosed files and connections")
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List all findings")
    p.set_defaults(func=cmd_resource_leaks)

    p = sub.add_parser("insecure-random", help="Detect weak random for security values")
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List all findings")
    p.set_defaults(func=cmd_insecure_random)

    p = sub.add_parser("path-traversal", help="Detect unsafe file path construction")
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List all findings")
    p.set_defaults(func=cmd_path_traversal)

    p = sub.add_parser("weak-crypto", help="Detect weak cryptographic algorithms")
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List all findings")
    p.set_defaults(func=cmd_weak_crypto)

    p = sub.add_parser("log-injection", help="Detect log injection risks")
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List all findings")
    p.set_defaults(func=cmd_log_injection)

    p = sub.add_parser("command-injection", help="Detect dynamic shell command construction")
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List all findings")
    p.set_defaults(func=cmd_command_injection)

    p = sub.add_parser("ssrf", help="Detect server-side request forgery risks")
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--verbose", "-v", action="store_true", help="List all findings")
    p.set_defaults(func=cmd_ssrf)

    p = sub.add_parser("security-scan", help="Run unified static security analysis")
    p.add_argument("directory", nargs="?", default=".", help="Project directory")
    p.add_argument("--context", action="store_true", help="Output LLM-ready context")
    p.add_argument("--json", action="store_true", help="Output JSON report")
    p.add_argument("--markdown", action="store_true", help="Output Markdown report")
    p.add_argument("--verbose", "-v", action="store_true", help="Show per-check summaries")
    p.set_defaults(func=cmd_security_scan)

    p = sub.add_parser("sql", help="Optimize SQL query")
    p.add_argument("query", help="SQL query or file path")
    p.add_argument("--context", default="", help="Schema or context")
    p.set_defaults(func=cmd_sql)

    p = sub.add_parser("readme", help="Generate README")
    p.add_argument("--project", required=True, help="Project name")
    p.add_argument("--description", required=True, help="Project description")
    p.set_defaults(func=cmd_readme)

    p = sub.add_parser("types", help="Add Python type hints")
    p.add_argument("code", help="Code or file path")
    p.set_defaults(func=cmd_types)

    p = sub.add_parser("regex", help="Build a regex")
    p.add_argument("description", help="What the regex should match")
    p.add_argument("--test-cases", default="", help="Test cases")
    p.set_defaults(func=cmd_regex)

    p = sub.add_parser("logs", help="Analyze log output")
    p.add_argument("logs", help="Log text or file path")
    p.set_defaults(func=cmd_logs)

    p = sub.add_parser("project", help="Review an entire project")
    p.add_argument("directory", help="Project directory")
    p.add_argument("--query", help="Focus query for relevant files")
    p.set_defaults(func=cmd_project)

    p = sub.add_parser("diff", help="Review a git diff")
    p.add_argument("--diff", help="Diff text or file path (defaults to git diff)")
    p.set_defaults(func=cmd_diff)

    p = sub.add_parser("performance", help="Analyze code performance")
    p.add_argument("code", help="Code or file path")
    p.add_argument("--context", default="", help="Runtime or workload context")
    p.set_defaults(func=cmd_performance)

    p = sub.add_parser("dockerfile", help="Review a Dockerfile")
    p.add_argument("dockerfile", help="Dockerfile or file path")
    p.set_defaults(func=cmd_dockerfile)

    p = sub.add_parser("migrate", help="Generate a migration plan")
    p.add_argument("code", help="Current code or file path")
    p.add_argument("--source", required=True, help="Source technology or version")
    p.add_argument("--target", required=True, help="Target technology or version")
    p.add_argument("--constraints", default="", help="Migration constraints")
    p.set_defaults(func=cmd_migrate)

    p = sub.add_parser("generate", help="Generate code from a specification")
    p.add_argument("spec", help="Natural-language specification")
    p.add_argument("--language", default="python", help="Target language")
    p.set_defaults(func=cmd_generate)

    p = sub.add_parser("fix-lint", help="Fix linter issues")
    p.add_argument("code", help="Code or file path")
    p.add_argument("lint_output", help="Linter output or file path")
    p.set_defaults(func=cmd_fix_lint)

    p = sub.add_parser("deps", help="Audit project dependencies")
    p.add_argument("dependencies", help="Dependencies text or file path")
    p.add_argument("--context", default="", help="Project context")
    p.set_defaults(func=cmd_deps)

    p = sub.add_parser("architecture", help="Describe codebase architecture")
    p.add_argument("code", help="Code or file path")
    p.add_argument("--context", default="", help="Additional context")
    p.set_defaults(func=cmd_architecture)

    p = sub.add_parser("incident", help="Triage a production incident")
    p.add_argument("symptoms", help="Incident symptoms")
    p.add_argument("--logs", help="Log output or file path")
    p.set_defaults(func=cmd_incident)

    p = sub.add_parser("summarize", help="Summarize a diff for PR or release notes")
    p.add_argument("--diff", help="Diff text or file path (defaults to git diff)")
    p.add_argument("--audience", default="developers", help="Target audience")
    p.set_defaults(func=cmd_summarize)

    p = sub.add_parser("upgrade-deps", help="Recommend dependency upgrades")
    p.add_argument("dependencies", help="Dependencies text or file path")
    p.add_argument("--constraints", default="", help="Upgrade constraints")
    p.set_defaults(func=cmd_upgrade_deps)

    p = sub.add_parser("verify", help="Generate code and verify with tests in sandbox")
    p.add_argument("spec", help="Natural-language specification")
    p.add_argument("tests", help="Test code or file path")
    p.add_argument("--language", default="python")
    p.add_argument("--max-attempts", type=int, default=2)
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("agent", help="Run coding agent")
    p.add_argument("task", help="Task description")
    p.set_defaults(func=cmd_agent)

    p = sub.add_parser("run", help="Run a DevAI program from JSON or YAML")
    p.add_argument("program", help="Program JSON file")
    p.add_argument("--code", help="Code input or file path")
    p.add_argument("--diff", help="Diff input or file path")
    p.add_argument(
        "--context",
        action="append",
        metavar="KEY=VALUE",
        help="Additional context values",
    )
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("validate", help="Validate a program file without running it")
    p.add_argument("program", help="Program JSON or YAML file")
    p.set_defaults(func=cmd_validate)

    p = sub.add_parser("dry-run", help="Preview program steps without calling the LLM")
    p.add_argument("program", help="Program JSON or YAML file")
    p.add_argument("--code", help="Code input or file path")
    p.add_argument("--diff", help="Diff input or file path")
    p.add_argument(
        "--context",
        action="append",
        metavar="KEY=VALUE",
        help="Additional context values",
    )
    p.set_defaults(func=cmd_dry_run)

    p = sub.add_parser("schema", help="Print the JSON Schema for program files")
    p.set_defaults(func=cmd_schema)

    p = sub.add_parser("presets", help="List built-in program presets")
    p.set_defaults(func=cmd_presets)

    p = sub.add_parser("workflow", help="Run a multi-step workflow from presets")
    p.add_argument(
        "step",
        nargs="+",
        help="Workflow steps as name:preset or preset (e.g. review:pre-commit security:security)",
    )
    p.add_argument("--name", default="workflow", help="Workflow name")
    p.add_argument("--code", help="Code input or file path")
    p.add_argument("--diff", help="Diff input or file path")
    p.add_argument("--query", help="SQL query input or file path")
    p.add_argument("--parallel", action="store_true", help="Run all steps in parallel")
    p.add_argument(
        "--context",
        action="append",
        metavar="KEY=VALUE",
        help="Additional context values",
    )
    p.set_defaults(func=cmd_workflow)

    p = sub.add_parser("cron-validate", help="Validate a cron expression")
    p.add_argument("expression", help="5-field cron expression (minute hour day month weekday)")
    p.add_argument("--check", action="store_true", help="Also check if expression matches now")
    p.set_defaults(func=cmd_cron_validate)

    p = sub.add_parser("schedule", help="Schedule or run a preset on a cron expression")
    p.add_argument("preset", help="Built-in preset name to run")
    p.add_argument("--cron", required=True, help="5-field cron expression")
    p.add_argument("--name", default="scheduled-job", help="Job name")
    p.add_argument("--once", action="store_true", help="Run immediately, ignoring cron match")
    p.add_argument("--code", help="Code input or file path")
    p.add_argument("--diff", help="Diff input or file path")
    p.add_argument(
        "--context",
        action="append",
        metavar="KEY=VALUE",
        help="Additional context values",
    )
    p.set_defaults(func=cmd_schedule)

    p = sub.add_parser("kit", help="Run a DevKit workflow")
    p.add_argument(
        "workflow",
        choices=["audit", "pre-commit", "release", "onboard", "pr-review", "ci-gate"],
        help="Workflow to run",
    )
    p.add_argument("code", nargs="?", help="Code or file path")
    p.add_argument("--project", help="Project directory for context")
    p.add_argument("--diff", help="Diff for pr-review workflow")
    p.set_defaults(func=cmd_kit)

    p = sub.add_parser("ci", help="Run CI workflow and output GitHub-ready reports")
    p.add_argument("--program", help="Program JSON/YAML file")
    p.add_argument("--preset", help="Built-in preset name (default: pre-commit)")
    p.add_argument("--code", help="Code input or file path")
    p.add_argument("--diff", help="Diff input or file path")
    p.add_argument(
        "--context",
        action="append",
        metavar="KEY=VALUE",
        help="Additional context values",
    )
    p.add_argument(
        "--format",
        choices=["comment", "annotations", "gate", "all"],
        default="all",
        help="Output format",
    )
    p.add_argument("--no-gate", action="store_true", help="Skip CI gate evaluation")
    p.set_defaults(func=cmd_ci)

    p = sub.add_parser("health", help="Check LLM provider connectivity")
    p.add_argument(
        "--provider",
        default="openai",
        help="Provider name (openai, ollama, mock)",
    )
    p.add_argument("--no-probe", action="store_true", help="Only check endpoint, skip completion")
    p.set_defaults(func=cmd_health)

    p = sub.add_parser("git-review", help="Review git changes with AI")
    p.add_argument("--staged", action="store_true", help="Review staged changes only")
    p.add_argument("--base", help="Base ref for diff (e.g. main)")
    p.add_argument("--commit", action="store_true", help="Generate commit message instead of review")
    p.add_argument("--pr", action="store_true", help="Generate PR description instead of review")
    p.add_argument("--title", help="PR title when using --pr")
    p.set_defaults(func=cmd_git_review)

    p = sub.add_parser("trace-demo", help="Run a preset with tracing enabled (demo)")
    p.add_argument("--json", action="store_true", help="Output full trace JSON")
    p.set_defaults(func=cmd_trace_demo)

    p = sub.add_parser("config-init", help="Create a starter .devai.yaml config file")
    p.add_argument(
        "--path",
        default=".devai.yaml",
        help="Config file path to create (default: .devai.yaml)",
    )
    p.add_argument("--provider", default="openai", help="Provider name for the template")
    p.add_argument("--model", default="gpt-4o-mini", help="Model name for the template")
    p.add_argument("--force", action="store_true", help="Overwrite an existing config file")
    p.set_defaults(func=cmd_config_init)

    p = sub.add_parser("config-show", help="Show resolved DevAI config from a project file")
    p.add_argument("--path", help="Explicit config file path")
    p.set_defaults(func=cmd_config_show)

    p = sub.add_parser("benchmark", help="Benchmark LLM latency and throughput")
    p.add_argument("--iterations", type=int, default=5, help="Number of requests to run")
    p.add_argument("--name", default="llm-benchmark", help="Benchmark name")
    p.add_argument("--prompt", default="Reply with exactly: benchmark-ok", help="Prompt text")
    p.add_argument(
        "--provider",
        default="mock",
        help="Provider name (openai, ollama, mock)",
    )
    p.add_argument("--json", action="store_true", help="Output full benchmark JSON")
    p.set_defaults(func=cmd_benchmark)

    p = sub.add_parser("context", help="Build and preview DevContext from files/snippets")
    p.add_argument("--file", action="append", help="Source file to include")
    p.add_argument(
        "--snippet",
        action="append",
        metavar="LANG:CODE",
        help="Code snippet as lang:code (e.g. python:def f(): pass)",
    )
    p.add_argument("--text", help="Free-text section to include")
    p.add_argument("--git", action="store_true", help="Include git diff")
    p.add_argument("--staged", action="store_true", help="Use staged git diff")
    p.add_argument("--base-ref", help="Git base ref for diff")
    p.add_argument("--base", help="Base directory for relative file paths")
    p.add_argument("--max-tokens", type=int, help="Truncate context to token limit")
    p.add_argument("--tokens", action="store_true", help="Print token count before output")
    p.add_argument(
        "--context",
        action="append",
        metavar="KEY=VALUE",
        help="Template variables",
    )
    p.set_defaults(func=cmd_context)

    p = sub.add_parser("doctor", help="Run environment diagnostics")
    p.add_argument("--path", help="Project directory to diagnose")
    p.add_argument("--no-probe", action="store_true", help="Skip LLM probe request")
    p.add_argument("--json", action="store_true", help="Output JSON report")
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("report", help="Run a preset and export results as JSON or Markdown")
    p.add_argument("preset", help="Preset name (e.g. pre-commit)")
    p.add_argument("code", help="Code or file path")
    p.add_argument("--format", choices=["markdown", "json"], default="markdown")
    p.add_argument("--provider", default="mock", help="Provider name")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("library", help="List or search programs in a directory")
    p.add_argument(
        "directory",
        nargs="?",
        default="examples/programs",
        help="Directory containing program JSON/YAML files",
    )
    p.add_argument("--search", help="Search programs by name, description, or action")
    p.add_argument("--recursive", action="store_true", help="Scan subdirectories")
    p.add_argument("--json", action="store_true", help="Output JSON")
    p.add_argument("--verbose", "-v", action="store_true", help="Show file paths and actions")
    p.set_defaults(func=cmd_library)

    p = sub.add_parser("apply-patch", help="Apply a unified diff from file or stdin")
    p.add_argument(
        "input",
        nargs="?",
        default="-",
        help="Diff file path, raw diff text, or '-' for stdin",
    )
    p.add_argument("--root", default=".", help="Project root for relative paths in the diff")
    p.add_argument("--dry-run", action="store_true", help="Validate without writing files")
    p.add_argument("--json", action="store_true", help="Output JSON result")
    p.set_defaults(func=cmd_apply_patch)

    p = sub.add_parser("export", help="Export a program file to a standalone Python script")
    p.add_argument("program", help="Program JSON or YAML file")
    p.add_argument(
        "-o",
        "--output",
        required=True,
        help="Output Python script path",
    )
    p.add_argument("--mock", action="store_true", help="Default to mock LLM in exported script")
    p.add_argument("--provider", default="openai", help="Default provider in exported script")
    p.add_argument("--model", help="Default model in exported script")
    p.set_defaults(func=cmd_export)

    p = sub.add_parser("hooks", help="Install or manage DevAI git hooks")
    p.add_argument(
        "action",
        choices=["install", "uninstall", "status"],
        help="Hook management action",
    )
    p.add_argument(
        "--hook",
        nargs="+",
        choices=["pre-commit", "pre-push", "commit-msg", "post-commit"],
        help="Hook name(s) to install or uninstall",
    )
    p.add_argument("--preset", default="pre-commit", help="Preset for hook actions")
    p.add_argument("--path", help="Project directory (default: current)")
    p.add_argument(
        "--warn-only",
        action="store_true",
        help="Do not fail commits/pushes when checks fail",
    )
    p.set_defaults(func=cmd_hooks)

    p = sub.add_parser("compare", help="Compare two files or code strings")
    p.add_argument("before", help="Before file path or code string")
    p.add_argument("after", help="After file path or code string")
    p.add_argument("--review", action="store_true", help="AI-review the changes")
    p.add_argument("--summarize", action="store_true", help="Summarize changes for PR/release notes")
    p.add_argument("--stats", action="store_true", help="Print addition/deletion stats")
    p.add_argument("--audience", default="developers", help="Audience for --summarize")
    p.add_argument("--before-label", help="Label for before version in diff")
    p.add_argument("--after-label", help="Label for after version in diff")
    p.set_defaults(func=cmd_compare)

    p = sub.add_parser("detect", help="Detect project language, framework, and tooling")
    p.add_argument("path", nargs="?", default=".", help="Project directory")
    p.add_argument("--json", action="store_true", help="Output JSON")
    p.set_defaults(func=cmd_detect)

    p = sub.add_parser("prompts", help="List built-in and registered prompt templates")
    p.add_argument("--search", help="Filter prompts by name")
    p.add_argument("--verbose", "-v", action="store_true", help="Show input variables")
    p.add_argument("--json", action="store_true", help="Output JSON")
    p.set_defaults(func=cmd_prompts)

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        sys.exit(1)
    args.func(args)


if __name__ == "__main__":
    main()
