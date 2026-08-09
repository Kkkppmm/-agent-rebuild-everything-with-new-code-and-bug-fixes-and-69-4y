"""Config file loading and LLM benchmarking example."""

from pathlib import Path

from devai import BenchmarkRunner, DevRuntime, MockLLMClient, config_file_template, load_config_file

# Create a starter config file
config_path = Path(".devai.example.yaml")
config_path.write_text(config_file_template(provider="mock", model="demo-model"), encoding="utf-8")

# Load config from file
config = load_config_file(config_path)
print(f"Loaded model: {config.model}")

# Bootstrap runtime from project directory
runtime = DevRuntime.from_project(Path.cwd(), config_path=config_path)
print(runtime.review("def add(a, b): return a + b")[:80], "...")

# Benchmark the client
runner = BenchmarkRunner(runtime.client or MockLLMClient())
result = runner.run(iterations=3, name="demo-benchmark")
print(result.summary())

config_path.unlink(missing_ok=True)
