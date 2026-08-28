"""Tests for code sandbox."""

from devai.sandbox import CodeSandbox, SandboxResult


class TestCodeSandbox:
    def test_run_python_success(self):
        sandbox = CodeSandbox()
        result = sandbox.run_python("print('hello')")
        assert result.success
        assert "hello" in result.stdout

    def test_run_python_error(self):
        sandbox = CodeSandbox()
        result = sandbox.run_python("raise ValueError('fail')")
        assert not result.success
        assert result.exit_code != 0

    def test_run_tests(self):
        sandbox = CodeSandbox()
        code = "def add(a, b):\n    return a + b"
        tests = "assert add(1, 2) == 3"
        result = sandbox.run_tests(code, tests)
        assert result.success

    def test_verify_output(self):
        sandbox = CodeSandbox()
        assert sandbox.verify_output("print('ok')", "ok")

    def test_timeout(self):
        sandbox = CodeSandbox(timeout=0.1)
        result = sandbox.run_python("import time\nwhile True: time.sleep(1)")
        assert result.timed_out
        assert not result.success

    def test_sandbox_result_output(self):
        result = SandboxResult(stdout="a", stderr="b", exit_code=0)
        assert "a" in result.output
        assert result.success
