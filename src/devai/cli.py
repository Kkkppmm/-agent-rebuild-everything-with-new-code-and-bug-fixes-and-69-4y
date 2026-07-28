"""Command-line interface for DevAI."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from devai import CodeAssistant, DevAIConfig, CIReporter
from devai.agents import CoderAgent
from devai.core import MockLLMClient
from devai.kit import DevKit
from devai.presets import list_presets
from devai.program import DevProgram
from devai.program_schema import program_schema
from devai.tools import ToolRegistry, git_diff, list_files, read_file, search_code


def _read_input(path_or_code: str) -> str:
    p = Path(path_or_code)
    if p.exists() and p.is_file():
        return p.read_text(encoding="utf-8", errors="replace")
    return path_or_code


def cmd_review(args: argparse.Namespace) -> None:
    assistant = _get_assistant(args)
    code = _read_input(args.code)
    print(assistant.review(code))


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
