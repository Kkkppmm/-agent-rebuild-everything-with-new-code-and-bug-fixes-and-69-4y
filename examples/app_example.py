"""Example: build a custom AI-powered developer tool with DevApp."""

from devai import DevApp


def main() -> None:
    app = DevApp.create(
        name="codebuddy",
        description="A lightweight code review CLI built with DevAI",
        use_mock=True,
    )

    @app.command("review", help="Review code from stdin or a file", requires_input=True)
    def review_code(code: str) -> str:
        return app.assistant.review(code)

    @app.command("explain", help="Explain code", requires_input=True)
    def explain_code(code: str) -> str:
        return app.assistant.explain(code)

    app.register_preset("pre-commit")

    app.cli()


if __name__ == "__main__":
    main()
