"""Build and ship an AI-powered developer tool with DevApp."""

from devai import DevApp

if __name__ == "__main__":
    # Create an app with mock LLM (swap use_mock=False for real API calls)
    app = (
        DevApp.create(name="code-auditor", use_mock=True)
        .use_preset("pre-commit")
        .with_context(code="def divide(a, b):\n    return a / b")
    )

    # Run and print results
    app.run_and_print()

    # Or run as a CLI: python app_example.py --dry-run
    # app.cli()
