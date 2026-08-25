"""Tests for DevAI CodeProject."""

from devai.project import CodeProject, ProjectFile


class TestCodeProject:
    def test_scan_python_files(self, tmp_path):
        (tmp_path / "main.py").write_text("def main():\n    pass\n")
        (tmp_path / "utils.py").write_text("x = 1\n")
        (tmp_path / "readme.txt").write_text("ignored")

        project = CodeProject(str(tmp_path))
        files = project.scan()
        paths = {f.path for f in files}
        assert "main.py" in paths
        assert "utils.py" in paths
        assert "readme.txt" not in paths

    def test_scan_ignores_hidden_dirs(self, tmp_path):
        hidden = tmp_path / ".git" / "hooks"
        hidden.mkdir(parents=True)
        (hidden / "pre-commit.py").write_text("pass")

        project = CodeProject(str(tmp_path))
        assert project.scan() == []

    def test_summary(self, tmp_path):
        (tmp_path / "a.py").write_text("x = 1\ny = 2\n")
        (tmp_path / "b.js").write_text("const x = 1;")

        project = CodeProject(str(tmp_path))
        summary = project.summary()
        assert "Files: 2" in summary
        assert "python" in summary
        assert "javascript" in summary

    def test_read_file(self, tmp_path):
        (tmp_path / "app.py").write_text("hello\nworld")
        project = CodeProject(str(tmp_path))
        assert project.read_file("app.py") == "hello\nworld"

    def test_read_file_not_found(self, tmp_path):
        project = CodeProject(str(tmp_path))
        assert "not found" in project.read_file("missing.py").lower()

    def test_to_vector_store(self, tmp_path):
        (tmp_path / "module.py").write_text("def foo():\n    return 42\n")
        project = CodeProject(str(tmp_path))
        store = project.to_vector_store()
        assert len(store) > 0

    def test_build_context(self, tmp_path):
        (tmp_path / "calc.py").write_text("def add(a, b):\n    return a + b\n")
        project = CodeProject(str(tmp_path))
        context = project.build_context()
        assert "calc.py" in context

    def test_build_context_with_query(self, tmp_path):
        (tmp_path / "auth.py").write_text("def login(user, password):\n    pass\n")
        (tmp_path / "math.py").write_text("def add(a, b):\n    return a + b\n")
        project = CodeProject(str(tmp_path))
        context = project.build_context(query="authentication login")
        assert "auth.py" in context or "login" in context.lower()

    def test_token_estimate(self, tmp_path):
        (tmp_path / "small.py").write_text("x = 1\n")
        project = CodeProject(str(tmp_path))
        assert project.token_estimate() > 0

    def test_project_file_dataclass(self):
        pf = ProjectFile(path="a.py", language="python", size=100, line_count=10)
        assert pf.path == "a.py"
        assert pf.language == "python"

    def test_empty_directory(self, tmp_path):
        project = CodeProject(str(tmp_path))
        assert project.scan() == []
        assert "No source files" in project.summary()
