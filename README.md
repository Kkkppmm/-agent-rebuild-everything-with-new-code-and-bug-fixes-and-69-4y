# DevAI

A Python AI library built for developers and programmers. DevAI provides a clean, composable toolkit for LLM-powered code review, debugging, refactoring, agents, RAG, and more.

## Features

- **LLM Client** — OpenAI-compatible API with sync/async, streaming, JSON mode, retries, and caching
- **Code Assistant** — High-level facade for review, explain, debug, refactor, security audit, tests, docstrings, API design, SQL optimization, type hints, regex, log analysis, code generation, lint fixes, dependency audits, diff review, performance analysis, Dockerfile review, architecture analysis, and migration planning
- **Structured Output** — Pydantic schemas for code reviews, security audits, and performance analysis
- **CodeProject** — Scan, index, and build context from an entire codebase
- **Observability** — Callback hooks for logging and tracing LLM calls
- **Agents** — Tool-calling agents with a built-in coder agent
- **Chains** — Simple, sequential, and structured (Pydantic) output chains
- **RAG** — Text chunking, TF-IDF vector store, embedding-based semantic search, and retrieval-augmented generation
- **Code Sandbox** — Run generated Python code in an isolated subprocess with timeout and test verification
- **Plugins** — Register custom actions for DevProgram workflows
- **Tools** — Code utilities: lint, search, git diff, complexity analysis
- **CLI** — Command-line interface for common developer workflows
- **Pipeline** — Composable review/debug/test workflows
- **DevProgram** — Declarative JSON/YAML programs for scripted multi-step AI workflows
- **DevKit** — Unified developer workspace with built-in presets (pre-commit, release, onboarding, PR review)
- **CI Integration** — GitHub Actions annotations, PR comments, and CI gate helpers
- **Cost Estimation** — Token counting and per-model cost estimates
- **DevWorkflow** — Orchestrate multiple programs with sequential and parallel execution
- **Program Presets** — Ready-made workflows (pre-commit, release, CI gate, incident response, dependency update, docs-gen, test-gen, hotfix, api-review, sql-review)
- **DevRuntime** — One-line bootstrap for programs, presets, and quick dev workflows
- **Local LLM Support** — Ollama and any OpenAI-compatible endpoint via config presets
- **Program Validation** — Validate JSON/YAML program files before execution
- **DevApp** — Build and ship AI-powered CLI tools from programs
- **Program Dry-Run** — Preview execution steps without calling the LLM
- **Program Schema** — JSON Schema for IDE validation of program files
- **Rate Limiting** — Token-bucket rate limiter and `RateLimitedLLMClient` for batch jobs and agents
- **Circuit Breaker** — Prevent cascading failures when LLM providers are down
- **Metrics** — Collect latency, throughput, and error metrics for LLM calls
- **DevSchedule** — Cron-like scheduling for programs and workflows
- **Resilient Client** — One-line wrapper combining rate limiting, circuit breaker, and metrics
- **Health Checks** — Verify LLM provider connectivity before running jobs
- **Quickstart** — `quickstart()` and `assistant()` helpers for minimal setup
- **GitContext** — One-line git-aware reviews, commit messages, and PR descriptions
- **DevTrace** — Lightweight tracing spans for program steps and workflows
- **Program Templates** — `${var:}`, `${env:}`, and `${file:}` interpolation in program context
- **Project Config Files** — Load `.devai.yaml` / `devai.json` for per-project LLM settings
- **Benchmarking** — Measure LLM latency, p95, and throughput with `BenchmarkRunner`
- **DevDoctor** — Environment diagnostics for Python version, dependencies, API keys, and provider health
- **ProgramReport** — Export program and workflow results to JSON or Markdown
- **Disk Cache** — `DiskCachedLLMClient` persists LLM responses to disk for faster dev iteration
- **Token Budget** — `TokenBudget` and `BudgetedLLMClient` track and enforce token/cost limits
- **DevWatcher** — Poll directories and auto-run presets when code files change
- **DevContext** — Fluent builder for assembling LLM context from files, snippets, git diffs, and variables
- **PromptBuilder** — Structured prompt assembly with system/user messages, context, and few-shot examples
- **ProgramLibrary** — Discover, search, and run JSON/YAML programs from a directory
- **Program Export** — Export DevProgram files to standalone runnable Python scripts
- **BatchReviewer** — Review multiple files or entire directories in parallel
- **Code Block Extraction** — Pull fenced code blocks from LLM responses with `extract_code_blocks()`
- **Fallback Client** — `FallbackLLMClient` tries multiple providers/models in order on failure
- **Patch Application** — Apply unified diffs from LLM output with `apply_unified_diff()`
- **CodeSymbolIndex** — AST-based symbol indexer for Python projects with search and LLM context export
- **Conversation Persistence** — Save and load `ConversationMemory` to JSON files
- **OpenAPI Review** — Review OpenAPI/Swagger specs for design, security, and consistency issues
- **Jupyter Notebooks** — Read, extract, and review `.ipynb` notebooks with `NotebookReader` and `review_notebook()`
- **Test Failure Analysis** — Analyze pytest/unittest output with `analyze_test_failures()`
- **Stack Trace Analysis** — Debug crashes with `analyze_stacktrace()`
- **ProgramComposer** — Fluent Python API for building DevProgram workflows without JSON/YAML
- **Schedule Config** — Load cron job definitions from JSON/YAML files for DevSchedule and ProgramLibrary
- **ImportGraph** — Analyze Python import dependencies, find circular imports, and export LLM context
- **SecretsScanner** — Heuristic scan for hardcoded API keys, tokens, and credentials
- **GitChangelog** — Generate Keep a Changelog-style release notes from git commit history
- **TypingCoverage** — Analyze type hint coverage across Python projects and export LLM context
- **EnvVarAnalyzer** — Inventory environment variables, detect drift between code and `.env.example`, and scaffold env templates
- **GitignoreAnalyzer** — Audit `.gitignore` coverage, recommend patterns by language, and detect exposed sensitive files
- **DockerfileAnalyzer** — Audit Dockerfiles for security risks (root user, :latest tags, secrets in ENV) and container best practices
- **WorkflowAnalyzer** — Audit GitHub Actions workflows for unpinned actions, pull_request_target misuse, broad permissions, and script injection
- **AzurePipelinesAnalyzer** — Audit Azure Pipelines for hardcoded secrets, unpinned tasks, privileged containers, and unsafe PR checkout patterns
- **TravisCIAnalyzer** — Audit Travis CI configs for hardcoded secrets, curl-pipe-to-shell, cleartext deploy keys, and unpinned language versions
- **BuildkiteAnalyzer** — Audit Buildkite pipelines for hardcoded secrets, unpinned plugins, privileged Docker, and environment propagation
- **CodefreshAnalyzer** — Audit Codefresh pipelines for hardcoded secrets, CF_* injection, privileged containers, and unencrypted exports
- **SemaphoreCIAnalyzer** — Audit Semaphore CI pipelines for hardcoded secrets, auto-promote rules, SEMAPHORE_* injection, and privileged containers
- **ConcourseCIAnalyzer** — Audit Concourse CI pipelines for hardcoded secrets, privileged tasks, insecure_skip_verify, and variable injection in run scripts
- **TektonAnalyzer** — Audit Tekton Pipeline/Task YAML for hardcoded secrets, hostPath mounts, privileged securityContext, and parameter injection in scripts
- **ArgoWorkflowsAnalyzer** — Audit Argo Workflows YAML for hardcoded secrets, hostNetwork/hostPID, privileged securityContext, and expression injection in scripts
- **FluxCDAnalyzer** — Audit Flux CD GitOps manifests for insecure HTTP sources, disabled TLS verification, force apply, cluster-admin RBAC, and hardcoded secrets
- **ArgoCDAnalyzer** — Audit Argo CD Application/ApplicationSet manifests for insecure sources, wildcard destinations, weak sync policies, and hardcoded credentials
- **AWSCodeBuildAnalyzer** — Audit AWS CodeBuild buildspec files for hardcoded secrets, unencrypted artifacts, privileged Docker, and CODEBUILD_* injection
- **DevContainerAnalyzer** — Audit dev container configs for hardcoded secrets, privileged mode, docker.sock mounts, and unsafe lifecycle commands
- **AWSCodePipelineAnalyzer** — Audit AWS CodePipeline configs for hardcoded secrets, disabled encryption, wildcard IAM, and missing production approvals
- **HarnessCIAnalyzer** — Audit Harness CI pipeline YAML for hardcoded secrets, privileged containers, automountServiceAccountToken, and Harness expression injection
- **BuddyCIAnalyzer** — Audit Buddy CI pipeline YAML for hardcoded secrets, docker_privileged_mode, unpinned image tags, and Buddy variable injection
- **DependabotAnalyzer** — Audit `.github/dependabot.yml` for hardcoded registry credentials, insecure external code execution, daily update floods, and missing security groups
- **RenovateAnalyzer** — Audit `renovate.json` for hardcoded host rule tokens, disabled vulnerability alerts, unsafe automerge, and post-upgrade shell tasks
- **SnykAnalyzer** — Audit `.snyk` and `snyk.yaml` for hardcoded tokens, wildcard vulnerability ignores, missing expiry dates, and lowered severity thresholds
- **TrivyAnalyzer** — Audit `.trivyignore` and `trivy.yaml` for hardcoded registry credentials, wildcard suppressions, fail-open exit codes, and insecure DB/registry URLs
- **GrypeAnalyzer** — Audit `.grypeignore` and `.grype.yaml` for hardcoded registry credentials, wildcard suppressions, fail-open severity thresholds, and insecure DB/registry URLs
- **SyftAnalyzer** — Audit `.syft.yaml` and Syft configs for hardcoded registry credentials, wildcard SBOM exclusions, disabled attestation, and insecure registry URLs
- **CosignAnalyzer** — Audit `.cosign.yaml` and Cosign policy configs for hardcoded private keys, disabled Rekor/tlog verification, permissive signing policies, and insecure registry URLs
- **SemgrepAnalyzer** — Audit `.semgrep.yml` and Semgrep rule configs for hardcoded App tokens, disabled rules, wildcard path exclusions, catch-all patterns, and dangerous CLI flags
- **BanditAnalyzer** — Audit `.bandit`, `bandit.yaml`, and `[tool.bandit]` configs for hardcoded tokens, wildcard skips/excludes, disabled shell injection tests, and nosec bypasses
- **CheckovAnalyzer** — Audit `.checkov.yml` and Checkov configs for hardcoded Bridgecrew tokens, soft-fail, wildcard skip-check/path patterns, and empty framework lists
- **KyvernoAnalyzer** — Audit Kyverno policy manifests for audit-only enforcement, failurePolicy: Ignore, wildcard excludes, privileged mutations, and PolicyExceptions
- **FalcoAnalyzer** — Audit Falco runtime security rules for disabled rules, wildcard conditions, broad suppressions, low priorities, and hardcoded secrets
- **OPAAnalyzer** — Audit OPA Rego policies for permissive defaults, unconditional allow rules, TLS bypass, http.send SSRF risks, and wildcard glob patterns
- **VaultAnalyzer** — Audit HashiCorp Vault configs for disabled TLS, dev mode, hardcoded tokens, missing auto-unseal seal, and cleartext api_addr
- **ConsulAnalyzer** — Audit HashiCorp Consul configs for disabled ACLs/TLS, dev mode, missing gossip encrypt, hardcoded tokens, and cleartext cluster addresses
- **NomadAnalyzer** — Audit HashiCorp Nomad configs for disabled ACLs/TLS, dev mode, privileged docker plugins, raw_exec drivers, and hardcoded tokens
- **PackerAnalyzer** — Audit HashiCorp Packer configs for hardcoded AWS keys, plaintext SSH/WinRM passwords, :latest tags, curl-pipe-to-shell provisioners, and unencrypted EBS volumes
- **VagrantAnalyzer** — Audit Vagrantfiles for plaintext SSH passwords, unbound port forwards, missing box version pins, SSH agent forwarding, and curl-pipe-to-shell provisioners
- **TerragruntAnalyzer** — Audit Terragrunt HCL for hardcoded secrets, HTTP remote state, missing DynamoDB locking, disabled S3 encryption, wildcard IAM roles, and unrestricted mock outputs
- **PulumiAnalyzer** — Audit Pulumi IaC projects for hardcoded secrets, plaintext stack config, insecure backends, public database access, open security groups, and unpinned plugins
- **CrossplaneAnalyzer** — Audit Crossplane Kubernetes manifests for hardcoded secrets, unversioned providers, disabled TLS verification, wildcard IAM, open security groups, and privileged compositions
- **KustomizeAnalyzer** — Audit Kustomize overlays for hardcoded secrets in generators, insecure HTTP remote bases, disabled load restrictors, exec plugins, unpinned git sources, and privileged patches
- **SkaffoldAnalyzer** — Audit Skaffold configs for hardcoded build secrets, insecure registries, docker.sock mounts, kubectl force apply, production kubeContext, and disabled status checks
- **TiltAnalyzer** — Audit Tiltfiles for hardcoded secrets, insecure registries, docker.sock mounts, production kube contexts, disabled secret scrubbing, and risky live_update sync paths
- **DevSpaceAnalyzer** — Audit DevSpace configs for hardcoded vars/secrets, insecure registries, SSH into pods, force deploy, and sensitive sync paths
- **GardenAnalyzer** — Audit Garden.io project configs for hardcoded environment variables, insecure registries, inline kubeconfig, docker.sock mounts, and sensitive sync paths
- **TelepresenceAnalyzer** — Audit Telepresence configs for hardcoded env vars, production namespace intercepts, docker.sock mounts, privileged traffic-agent settings, and sensitive envFile paths
- **EarthlyAnalyzer** — Audit Earthfiles for hardcoded ARG/ENV secrets, :latest tags, curl-pipe-to-shell, docker.sock mounts, privileged WITH DOCKER, and sensitive host path copies
- **BazelAnalyzer** — Audit Bazel BUILD files, WORKSPACE/MODULE.bazel, and .bazelrc for hardcoded secrets, unpinned http_archive/git_repository, sandbox disabling, privileged containers, and deprecated bind() usage
- **PantsAnalyzer** — Audit Pants BUILD files and pants.toml for hardcoded secrets, unpinned pants_version, insecure PyPI/Docker registries, privileged docker_image targets, curl-pipe-to-shell in shell_command, and secrets in environment dicts
- **BuckAnalyzer** — Audit Buck BUCK files and .buckconfig for hardcoded secrets, unpinned remote_file/http_archive, insecure Maven/download settings, curl-pipe-to-shell in genrules, and disabled build caches
- **GradleAnalyzer** — Audit Gradle build.gradle(.kts), settings.gradle, gradle.properties, and libs.versions.toml for hardcoded secrets, allowInsecureProtocol, dynamic dependency versions, insecure Maven repos, signing keys in plain text, and curl-pipe-to-shell in exec tasks
- **MavenAnalyzer** — Audit Maven pom.xml, settings.xml, and .mvn config for hardcoded secrets, insecure HTTP repositories, unpinned LATEST/RELEASE versions, allowInsecureProtocol, SCM credentials in URLs, wildcard mirrorOf, and curl-pipe-to-shell in exec-maven-plugin
- **PoetryAnalyzer** — Audit Poetry pyproject.toml and poetry.toml for hardcoded PyPI tokens, insecure HTTP sources, credentials in git/source URLs, unpinned git dependencies, loose version constraints, missing poetry.lock, and curl-pipe-to-shell in scripts
- **PipAnalyzer** — Audit pip requirements.txt, constraints.txt, and pip.conf for hardcoded PyPI tokens, insecure HTTP index URLs, credentials in VCS URLs, unpinned git dependencies, loose version constraints, trusted-host bypasses, missing constraints.txt, and curl-pipe-to-shell patterns
- **UvAnalyzer** — Audit uv pyproject.toml and uv.toml for hardcoded PyPI tokens, insecure HTTP index URLs, credentials in git/source URLs, unpinned git dependencies, loose version constraints, trusted-host bypasses, missing uv.lock, system Python installs, and curl-pipe-to-shell in scripts
- **NpmAnalyzer** — Audit package.json and .npmrc for hardcoded npm tokens, insecure HTTP registry URLs, credentials in git/source URLs, unpinned git dependencies, loose version constraints, strict-ssl bypasses, dangerous lifecycle scripts, missing lockfiles, and curl-pipe-to-shell in install hooks
- **CargoAnalyzer** — Audit Cargo.toml and .cargo/config.toml for hardcoded registry tokens, insecure HTTP index URLs, credentials in git/source URLs, unpinned git dependencies, loose version constraints, git-fetch-with-cli risks, disabled TLS revocation checks, and missing Cargo.lock for binaries
- **GoModAnalyzer** — Audit go.mod, go.sum, go.work, and go.env for hardcoded secrets, insecure GOPROXY settings, disabled GOSUMDB, broad GOINSECURE/GONOSUMDB, credentials in module URLs, local replace directives, unpinned replacements, dangerous //go:generate commands, and missing go.sum lockfiles
- **GolangciLintAnalyzer** — Audit `.golangci.yml` and `.golangci.toml` for disabled gosec/bodyclose linters, broad skip-dirs/skip-files patterns, gosec rule excludes, disable-all, and hardcoded secrets
- **RuboCopAnalyzer** — Audit `.rubocop.yml` and `.rubocop_todo.yml` for disabled Security/* cops, broad Exclude patterns, remote inherit_from URLs, DisabledByDefault, NewCops: disable, and hardcoded secrets
- **ShellcheckAnalyzer** — Audit `.shellcheckrc` for disabled quoting/source checks, wildcard disables, external-sources without source-path, enable=none, and hardcoded secrets
- **ComposerAnalyzer** — Audit composer.json and auth.json for hardcoded tokens, insecure HTTP repositories, credentials in VCS URLs, dev/unpinned dependencies, disabled TLS verification, wildcard allow-plugins, committed auth.json, dangerous scripts, and missing composer.lock lockfiles
- **BundlerAnalyzer** — Audit Gemfile, gems.rb, and .bundle/config for hardcoded tokens, insecure HTTP gem sources, credentials in git sources, unpinned git dependencies, loose version constraints, committed bundle credentials, dangerous install hooks, and missing Gemfile.lock lockfiles
- **MixAnalyzer** — Audit mix.exs and config/*.exs for hardcoded tokens, insecure HTTP Hex repos, credentials in git sources, unpinned git dependencies, loose version constraints, config secrets, dangerous mix aliases, and missing mix.lock lockfiles
- **SbtAnalyzer** — Audit build.sbt, project/*.sbt, and credentials files for hardcoded publish credentials, insecure HTTP resolvers, credentials in git sources, unpinned git dependencies, loose version constraints, dangerous shell tasks, and sensitive path references
- **LeiningenAnalyzer** — Audit project.clj and profiles.clj for hardcoded deploy credentials, insecure HTTP repositories, credentials in git sources, unpinned git dependencies, loose version constraints, dangerous shell aliases, and sensitive path references
- **CMakeAnalyzer** — Audit CMakeLists.txt, cmake modules, and toolchain files for hardcoded secrets, insecure HTTP downloads, credentials in git URLs, unpinned FetchContent/ExternalProject refs, disabled TLS verification, dangerous execute_process calls, insecure compile flags, and downloads without EXPECTED_HASH
- **MesonAnalyzer** — Audit meson.build, meson_options.txt, subprojects/*.wrap, and cross/native files for hardcoded secrets, insecure HTTP downloads, credentials in git URLs, unpinned wrap revisions, dangerous run_command calls, and wrap-file downloads without source_hash
- **ConanAnalyzer** — Audit conanfile.py, conanfile.txt, conandata.yml, profiles, remotes.json, and global.conf for hardcoded secrets, insecure HTTP remotes, credentials in git URLs, unpinned git refs, disabled TLS verification, unverified downloads, and dangerous self.run calls
- **VcpkgAnalyzer** — Audit vcpkg.json, vcpkg-configuration.json, and portfile.cmake for hardcoded secrets, insecure HTTP URLs, credentials in git URLs, unpinned git refs, disabled TLS verification, unverified downloads, and dangerous vcpkg_execute_required_process calls
- **NixAnalyzer** — Audit flake.nix, shell.nix, default.nix, and nix.conf for hardcoded secrets, insecure HTTP substituters, credentials in git URLs, unpinned flake inputs, disabled TLS verification, unverified fetchTarball calls, and dangerous runCommand/writeShellScript invocations
- **MiseAnalyzer** — Audit mise.toml, .mise.toml, and .tool-versions for hardcoded secrets in env blocks, insecure HTTP plugin URLs, credentials in git URLs, unpinned plugin refs, disabled TLS verification, dangerous task run scripts, and unpinned tool versions
- **TurboAnalyzer** — Audit turbo.json and turbo.jsonc for hardcoded secrets, disabled remote cache signatures, sensitive env vars in globalPassThroughEnv, credential files in inputs/globalDependencies, insecure HTTP remote cache URLs, and cache-disabled tasks
- **NxAnalyzer** — Audit nx.json and project.json for hardcoded secrets, nxCloudAccessToken and accessToken values, sensitive env vars in target options, credential files in namedInputs/inputs, insecure HTTP Nx Cloud URLs, and cache-disabled targets
- **DirenvAnalyzer** — Audit .envrc and direnv.toml for hardcoded secrets, disabled strict_env, dotenv loading of credential files, watch_file on secrets, insecure source_env URLs, dangerous eval hooks, writable PATH_add paths, and unpinned use nix/flake refs
- **JustAnalyzer** — Audit justfile, Justfile, and just/*.just for hardcoded secrets, curl|sh in recipes, sudo and chmod 777, git push --force, eval usage, insecure HTTP imports, [script] shebang recipes, and sensitive path references
- **TaskfileAnalyzer** — Audit Taskfile.yml and taskfile.yaml for hardcoded secrets, remote includes, method: none checksum bypass, dotenv loading, curl|sh in cmds, sudo and chmod 777, git push --force, eval usage, and sensitive path references
- **LefthookAnalyzer** — Audit lefthook.yml and .lefthook/*.yml for hardcoded secrets, unpinned remote extends, skip: true disabling hooks, curl|sh in run commands, sudo and chmod 777, git push --force, eval usage, TLS verification disabled, and sensitive path references
- **ESLintAnalyzer** — Audit .eslintrc.*, eslint.config.js, and package.json eslintConfig for hardcoded secrets, insecure HTTP extends URLs, disabled security rules (no-eval, security/*), eval globals, curl|sh in overrides, and process.env secret references
- **HuskyAnalyzer** — Audit .husky/* hook scripts and package.json husky config for hardcoded secrets, curl|sh in hooks, sudo and chmod 777, git push --force, eval usage, TLS verification disabled, unpinned npx commands, disabled hooks, and legacy husky install
- **BiomeAnalyzer** — Audit biome.json and biome.jsonc for hardcoded secrets, insecure HTTP schema URLs, disabled security rules (noDangerouslySetInnerHtml, noGlobalEval, noDebugger), disabled VCS ignore integration, curl|sh patterns, and dangerous shell commands
- **PrettierAnalyzer** — Audit .prettierrc.*, prettier.config.js, and package.json prettier config for hardcoded secrets, insecure HTTP plugin URLs, curl|sh patterns, dangerous shell commands, and process.env secret references
- **StylelintAnalyzer** — Audit .stylelintrc.*, stylelint.config.js, and package.json stylelint config for hardcoded secrets, insecure HTTP plugin/extends URLs, disabled security rules, curl|sh patterns, and process.env secret references
- **CommitlintAnalyzer** — Audit .commitlintrc.*, commitlint.config.js, and package.json commitlint config for hardcoded secrets, insecure HTTP extends URLs, eval in custom parsers, curl|sh patterns, and process.env secret references
- **EditorConfigAnalyzer** — Audit .editorconfig files for hardcoded secrets, insecure URLs, missing root/baseline settings, nested root declarations, and charset/line-ending consistency
- **PnpmAnalyzer** — Audit pnpm-workspace.yaml, pnpm-lock.yaml, .pnpmfile hooks, and pnpm .npmrc settings for hardcoded tokens, disabled integrity checks, shamefully-hoist, wildcard overrides, and dangerous hook scripts
- **BunAnalyzer** — Audit bunfig.toml, bun.lock, and Bun package.json settings for hardcoded tokens, disabled lockfile enforcement, trusted-all dependencies, insecure registries, and dangerous lifecycle scripts
- **DenoAnalyzer** — Audit deno.json, deno.jsonc, import maps, and deno.lock for hardcoded secrets, allow-all permissions, disabled lockfiles, unpinned JSR/npm imports, insecure remote URLs, and dangerous task scripts
- **JestAnalyzer** — Audit jest.config.* and package.json jest blocks for hardcoded secrets, dangerous globalSetup/setupFiles, testPathIgnorePatterns skipping security tests, disabled mock resets, and moduleNameMapper redirects outside the project
- **VitestAnalyzer** — Audit vitest.config.* and Vitest setup for hardcoded secrets, dangerous setup files, test exclusions, disabled mock resets, and insecure server/proxy settings
- **PlaywrightAnalyzer** — Audit playwright.config.* for TLS bypass, sandbox disable, remote debug ports, insecure baseURL, and artifact leaks in outputDir
- **CypressAnalyzer** — Audit cypress.config.* and cypress.json for chromeWebSecurity disabled, secrets in env, insecure baseUrl, modifyObstructiveCode, and artifact folder leaks
- **MochaAnalyzer** — Audit .mocharc.* and mocha.opts for hardcoded secrets, require paths outside the project, allowUncaught, disabled forbidOnly, zero timeouts, and Node inspect flags
- **PytestAnalyzer** — Audit pytest.ini, pyproject.toml, and conftest.py for hardcoded secrets, eval/exec, --pdb in CI, security test exclusions, disabled coverage, and TLS bypass
- **ToxAnalyzer** — Audit tox.ini for passenv=*, allowlist_externals=*, insecure pip indexes, indexserver credentials, changedir outside project, and dangerous commands
- **NoxAnalyzer** — Audit noxfile.py for reuse_venv, venv_backend='none', os.environ forwarding, insecure pip indexes, HTTP git deps, chdir outside project, and dangerous commands
- **WebdriverIOAnalyzer** — Audit wdio.conf.* for acceptInsecureCerts, --no-sandbox, remote debugging, insecure baseUrl/protocol, specs outside the project, and excessive maxInstances
- **AppVeyorCIAnalyzer** — Audit AppVeyor CI configs for hardcoded secrets, enable_rdp, cleartext deploy api_key, and APPVEYOR_* variable injection
- **GoCDCIAnalyzer** — Audit GoCD pipeline YAML for hardcoded secrets, privileged containers, insecure_skip_verify, and GO_* variable injection
- **CirrusCIAnalyzer** — Audit Cirrus CI `.cirrus.yml` for hardcoded secrets, privileged containers, skip_tls_verify, and CIRRUS_* variable injection
- **ComposeAnalyzer** — Audit Docker Compose files for privileged mode, host mounts, :latest tags, secrets in environment, and missing resource limits
- **PrecommitAnalyzer** — Audit `.pre-commit-config.yaml` for unpinned hook revisions, local hooks with unsafe entries, and secrets in config
- **DependencyParser** — Parse requirements.txt and pyproject.toml, detect unpinned and duplicate deps
- **StreamCollector** — Collect streaming LLM output with callbacks, timing, and chunk storage
- **DevHooks** — Install git pre-commit, pre-push, commit-msg, and post-commit hooks powered by DevAI presets
- **Async Batch Review** — `areview_files()` and `areview_directory()` for async parallel file reviews
- **CodeComparer** — Compare two files or code strings, generate unified diffs, and AI-review changes
- **PromptRegistry** — Discover and register custom prompt templates alongside built-in DevAI prompts
- **ProjectDetector** — Detect project language, framework, package manager, and tooling from a directory
- **CodeMetrics** — Static analysis for LOC, cyclomatic complexity, and function counts without LLM calls
- **DocstringCoverage** — Analyze docstring coverage for functions, methods, and classes
- **TestMapper** — Map source modules to test files and find untested modules
- **Async Facade** — `areview()` and `aexplain()` async methods on the `DevAI` entry point
- **ProjectHealth** — Unified project health dashboard combining metrics, typing, docstrings, tests, dependencies, secrets, env vars, gitignore, dockerfile, code smells, tech-debt, exceptions, and coupling analysis with scored recommendations
- **CodeSmellDetector** — AST-based detection of long functions, deep nesting, bare except, god classes, and excessive parameters
- **TechDebtScanner** — Scan for TODO, FIXME, HACK, XXX, and other tech-debt comment markers across multiple languages
- **DuplicateCodeDetector** — Find duplicate and near-duplicate code blocks using normalized line hashing
- **DeadCodeAnalyzer** — Detect potentially unused top-level Python functions and classes
- **APISurfaceAnalyzer** — Map public API symbols, check `__all__` declarations, and flag undocumented exports
- **ComplexityHotspotAnalyzer** — Rank files by complexity debt to prioritize refactoring
- **ExceptionHierarchyAnalyzer** — Map custom exception classes, inheritance chains, and risky bare/broad except handlers
- **ModuleCouplingAnalyzer** — Measure afferent/efferent coupling and instability from import graphs
- **NamingConventionAnalyzer** — Check PEP 8 naming for functions, methods, classes, variables, and constants
- **MagicNumberDetector** — Find unexplained numeric literals that should be named constants
- **DangerousCallsAnalyzer** — Detect risky calls (`eval`, `exec`, `shell=True`) and mutable default arguments
- **WeakCryptoAnalyzer** — Detect MD5, SHA1, and weak ciphers used for security-sensitive operations
- **LogInjectionAnalyzer** — Detect dynamic log messages that enable log injection attacks
- **SQLInjectionAnalyzer** — Detect dynamic SQL construction in database execute calls
- **DebugArtifactDetector** — Find print, breakpoint, and pdb debug code left in sources
- **AsyncBlockingDetector** — Detect blocking calls inside async functions
- **ResourceLeakAnalyzer** — Detect files, sockets, and connections opened without context managers
- **InsecureRandomAnalyzer** — Detect use of `random` for tokens, passwords, and other security-sensitive values
- **PathTraversalAnalyzer** — Detect unsafe file path construction from user-controlled input
- **CommandInjectionAnalyzer** — Detect dynamic shell command construction in os/subprocess calls
- **SSRFAnalyzer** — Detect server-side request forgery risks in outbound HTTP client calls
- **SecurityScanner** — Unified static security scan combining secrets, injections, dangerous calls, insecure random, weak crypto, log injection, SSRF, path traversal, and 77 security checks
- **ProxyTrustAnalyzer** — Detect unvalidated trust of X-Forwarded-For and proxy headers for client IP and access control
- **InsecureWebSocketAnalyzer** — Detect hardcoded ws:// URLs and disabled WebSocket TLS in real-time applications
- **InsecureMiddlewareSettingsAnalyzer** — Detect missing SecurityMiddleware, CSRF, and clickjacking middleware in Django production settings
- **InsecureRestFrameworkSettingsAnalyzer** — Detect AllowAny defaults, missing auth/throttle classes, and BrowsableAPIRenderer in Django REST Framework settings
- **InsecureCelerySettingsAnalyzer** — Detect pickle serializers, task_always_eager, and unauthenticated Redis/AMQP broker URLs in Celery settings
- **InsecureGraphqlSettingsAnalyzer** — Detect enabled introspection, playground/GraphiQL, and debug mode in GraphQL settings
- **InsecureWebhookSettingsAnalyzer** — Detect disabled signature verification and weak/empty webhook secrets
- **InsecureJwtSettingsAnalyzer** — Detect disabled JWT verification, 'none' algorithm, and weak signing keys in settings

## Installation

```bash
pip install devai

# With OpenAI SDK support
pip install "devai[openai]"

# With YAML program support
pip install "devai[yaml]"
```

## Quick Start

```python
from devai import DevAI

# Fastest path — mock mode, no API key required
ai = DevAI.mock()
print(ai.review("def add(a, b): return a + b"))
```

```python
from devai import quickstart

# Full runtime with programs, presets, and workflows
runtime = quickstart(use_mock=True)
print(runtime.review("def add(a, b): return a + b"))
```

```python
from devai import quickstart

# Review local git changes
runtime = quickstart(use_mock=True)
print(runtime.review_git(staged=True))

# Trace program execution
runtime.trace.clear()
runtime.run("pre-commit", {"code": "x = 1"}, trace=True)
print(runtime.trace.summary())
```

```python
from devai import CodeAssistant, CodeProject, CoderAgent, DevAIConfig, MockLLMClient

# Use with any OpenAI-compatible API
config = DevAIConfig(
    api_key="your-api-key",
    base_url="https://api.openai.com/v1",
    model="gpt-4o-mini",
)
assistant = CodeAssistant(config)

# Review code
result = assistant.review("""
def add(a, b):
    return a + b
""")
print(result)

# Explain code
explanation = assistant.explain("async def fetch(): ...")

# Debug an error
fix = assistant.debug(code="...", error="NameError: name 'x' is not defined")

# Generate code from a spec
code = assistant.generate("REST endpoint that returns user profile by ID")

# Structured review with Pydantic output
from devai import CodeReviewResult
result = assistant.structured_review("def foo(): pass")
print(result.score, result.issues)

# Review a git diff
review = assistant.review_diff("diff --git a/app.py ...")

# Batch review multiple files
results = assistant.batch_review({"a.py": "...", "b.py": "..."})
```

## Mock Client (No API Key Required)

```python
from devai import CodeAssistant, MockLLMClient

client = MockLLMClient(default_response="This code looks good.")
assistant = CodeAssistant(client=client)
print(assistant.review("def foo(): pass"))
```

## DevRuntime (Fastest Start)

```python
from devai import DevRuntime

# Bootstrap everything in one line (mock mode — no API key)
runtime = DevRuntime.create(use_mock=True)

print(runtime.review("def add(a, b): return a + b"))
print(runtime.generate("a context manager for temp files"))

# Run a built-in preset program
results = runtime.run("pre-commit", {"code": "def foo(): pass"})
print(runtime.summarize(results))

# Local Ollama (requires running Ollama server)
# runtime = DevRuntime.create(provider="ollama", model="llama3.2")
```

## Project Config Files

```bash
devai config-init              # creates .devai.yaml
devai config-show              # show resolved settings
```

```python
from devai import DevRuntime, load_config_file

# Load from .devai.yaml / devai.json in the project root
runtime = DevRuntime.from_project("./my-app")
config = load_config_file()    # raises if no config file is found
```

Example `.devai.yaml`:

```yaml
provider: openai
model: gpt-4o-mini
temperature: 0.2
max_tokens: 4096
# api_key: sk-...  # or set DEVAI_API_KEY
```

## Benchmarking

```python
from devai import BenchmarkRunner, DevRuntime

runtime = DevRuntime.create(use_mock=True)
result = BenchmarkRunner(runtime.client).run(iterations=10)
print(result.summary())   # mean/p95 latency and throughput
```

```bash
devai benchmark --mock --iterations 10
devai benchmark --provider openai --iterations 5 --json
```

## Health Checks

```python
from devai import check_health

result = check_health(use_mock=True)
print(result.healthy, result.latency_ms)

# CLI: devai health --mock
# devai health --provider ollama --no-probe
```

## DevApp (Ship Your Own Tool)

```python
from devai import DevApp

# Build a code auditor app in a few lines
app = (
    DevApp.create(name="code-auditor", use_mock=True)
    .use_preset("pre-commit")
    .with_context(code=open("app.py").read())
)

results = app.run()
print(app.summarize(results))

# Or expose as a CLI
# app.cli(["--dry-run", "--code", "app.py"])
```

## Agents

```python
from devai import CoderAgent, MockLLMClient
from devai.tools import ToolRegistry, read_file, search_code

registry = ToolRegistry()
registry.register(read_file)
registry.register(search_code)

agent = CoderAgent(client=MockLLMClient(), tools=registry)
response = agent.run("Find all TODO comments in the codebase")
```

## RAG

```python
from devai.rag import chunk_text, VectorStore, RAGChain
from devai.core import MockLLMClient

docs = ["Python uses indentation.", "List comprehensions are concise."]
chunks = chunk_text("\n".join(docs))
store = VectorStore()
store.add_documents(chunks)
chain = RAGChain(client=MockLLMClient(), store=store)
answer = chain.query("How does Python handle blocks?")
```

## Semantic RAG (Embeddings)

```python
from devai import MockEmbeddingClient, MockLLMClient
from devai.rag import SemanticVectorStore, SemanticRAGChain

store = SemanticVectorStore(MockEmbeddingClient())
store.add_texts(["DevAI helps developers with code review and agents."])
chain = SemanticRAGChain(MockLLMClient(), store)
answer = chain.query("What does DevAI do?")
```

## Code Sandbox

```python
from devai import CodeAssistant, MockLLMClient
from devai.sandbox import CodeSandbox

sandbox = CodeSandbox()
result = sandbox.run_python("print('hello')")

assistant = CodeAssistant(client=MockLLMClient(default_response="def add(a,b): return a+b"))
verified = assistant.generate_and_verify("add two numbers", "assert add(1,2)==3")
```

## CodeProject

```python
from devai import CodeProject, CodeAssistant
from devai.core import MockLLMClient

project = CodeProject("./my-app")
print(project.summary())

# Index for RAG
store = project.to_vector_store()

# Review with project context
assistant = CodeAssistant(client=MockLLMClient())
review = assistant.review_project("./my-app", query="authentication")
```

## DevKit (Unified Workspace)

```python
from devai import DevKit, MockLLMClient

kit = DevKit.from_client(MockLLMClient(default_response="Looks good."))

# Built-in workflows
print(kit.pre_commit("def divide(a, b): return a / b"))
print(kit.audit("class UserService: ..."))
print(kit.onboard("def main(): ..."))

# List and load presets
for preset in kit.presets():
    print(preset["name"], preset["description"])

program = kit.preset("release")
results = kit.run_program(program, {"code": open("app.py").read()})
print(kit.summarize(results))

# Project-aware workflows
kit = DevKit.from_client(MockLLMClient(), project_path="./my-app")
print(kit.review_project(query="authentication"))
```

## DevWorkflow (Multi-Program Orchestration)

```python
from devai import DevRuntime, DevWorkflow

runtime = DevRuntime.create(use_mock=True)

# Chain multiple presets sequentially
workflow = (
    runtime.workflow("ship-it")
    .add("quality", "pre-commit")
    .add("docs", "docs-gen")
)
result = workflow.run({
    "code": "def add(a, b): return a + b",
    "project": "mylib",
    "description": "A tiny math library",
})
print(result.summarize())

# Run independent checks in parallel
parallel = (
    DevWorkflow("gate", runtime.assistant)
    .add_parallel("checks", ("review", "pre-commit"), ("hotfix", "hotfix"))
)
parallel.run({"code": "def foo(): pass"})
```

```bash
# CLI: run a workflow from presets
devai workflow quality:pre-commit docs:docs-gen --code app.py --mock
devai workflow review:pre-commit security:security-deep-dive --parallel --mock
```

## DevSchedule (Cron Automation)

```python
from devai import DevRuntime

runtime = DevRuntime.create(use_mock=True)
schedule = runtime.schedule()
schedule.add("nightly", "0 2 * * *", "nightly-audit")
schedule.add("hourly", "0 * * * *", "code-health")

# Run immediately
result = schedule.run_once("hourly", {"code": "def foo(): pass"})

# Resilient client with rate limiting + circuit breaker + metrics
client = runtime.resilient_client(requests_per_minute=120)
```

```bash
# Validate and run scheduled presets
devai cron-validate "0 * * * *" --check
devai schedule pre-commit --cron "0 * * * *" --once --code app.py --mock
```

## DevProgram (Scripted Workflows)

```python
from devai import CodeAssistant, DevProgram
from devai.core import MockLLMClient

assistant = CodeAssistant(client=MockLLMClient(default_response="Looks good."))

# Build a program in code
program = (
    DevProgram("pre-commit-audit", assistant)
    .add("review", "review")
    .add("security", "security")
)
results = program.run({"code": open("app.py").read()})

# Or load from JSON
program = DevProgram.from_file("audit.json", assistant)
print(program.run_and_summarize({"code": "..."}))

# Or load from YAML (requires pip install 'devai[yaml]')
program = DevProgram.from_file("audit.yaml", assistant)
```

Example `audit.json`:

```json
{
  "name": "pre-commit-audit",
  "tasks": [
    {"name": "review", "action": "review"},
    {"name": "security", "action": "security"}
  ]
}
```

## CI Integration

```python
from devai import CIReporter, CodeAssistant, MockLLMClient

reporter = CIReporter(CodeAssistant(client=MockLLMClient()))
payload = reporter.run_program_for_ci("pre-commit", {"code": open("app.py").read()})

print(payload["pr_comment"])       # GitHub PR comment markdown
print(payload["annotations"])      # GitHub Actions ::warning:: lines
print(payload["passed"])           # CI gate result
```

```bash
devai ci --preset pre-commit --code app.py
devai ci --program audit.yaml --code app.py --format comment
```

## Cost Estimation

```python
from devai.core.models import Message
from devai.utils import estimate_message_cost, format_cost

cost = estimate_message_cost(
    [Message.user("Review this code")],
    response="Looks good.",
    model="gpt-4o-mini",
)
print(format_cost(cost))
```

## Doctor & Reports

```python
from devai import DevDoctor, ProgramReport, quickstart

# Diagnose your environment
doctor = DevDoctor()
print(doctor.summary())

# Run a program and export results
runtime = quickstart(use_mock=True)
results = runtime.run("pre-commit", {"code": "def foo(): pass"})
print(runtime.report(results, format="markdown"))
print(runtime.report(results, format="json"))

report = ProgramReport.from_program_results(results, program_name="pre-commit")
print(report.to_markdown())
```

```bash
devai doctor
devai doctor --json
devai report pre-commit app.py --format json
```

## OpenAI SDK Adapter

```python
from devai.core.config import DevAIConfig
from devai.core.openai_adapter import OpenAIAdapter

adapter = OpenAIAdapter(DevAIConfig(api_key="...", model="gpt-4o-mini"))
response = adapter.complete([Message.user("Hello")])
```

## Observability

```python
from devai.core import MockLLMClient, LoggingCallback, ObservedLLMClient

callback = LoggingCallback()
client = ObservedLLMClient(MockLLMClient(), callbacks=[callback])
client.complete([...])
print(callback.events)  # [{"event": "start", ...}, {"event": "end", ...}]
```

## CLI

```bash
devai review path/to/file.py
devai explain "def factorial(n): ..."
devai debug --code file.py --error "TypeError: ..."
devai commit --diff "$(git diff)"
devai security path/to/module.py
devai api path/to/routes.py --context "REST API v2"
devai sql "SELECT * FROM users" --context "users table has 1M rows"
devai types path/to/module.py
devai logs error.log
devai project ./my-app --query "error handling"
devai diff --diff "$(git diff)"
devai performance path/to/hot_path.py --context "10k RPS"
devai dockerfile Dockerfile
devai workflow-audit .
devai compose-audit .
devai precommit-audit .
devai migrate path/to/app.py --source "Django 3" --target "Django 5"
devai generate "REST endpoint for user profiles" --language python
devai fix-lint path/to/module.py "E501 line too long"
devai deps requirements.txt --context "production web app"
devai architecture path/to/main.py --context "microservice"
devai agent "Refactor the auth module"
devai run audit.json --code path/to/app.py
devai validate audit.json
devai dry-run audit.json --code path/to/app.py
devai schema
devai presets
devai kit audit path/to/app.py
devai kit pre-commit path/to/app.py
devai kit pr-review --project ./my-app --diff "$(git diff)"
devai ci --preset pre-commit --code app.py
devai config-init
devai config-show
devai benchmark --mock --iterations 5
devai health --mock
```

## Configuration

Set environment variables, create a project config file (`.devai.yaml`), or pass a `DevAIConfig`:

| Variable | Description |
|----------|-------------|
| `DEVAI_API_KEY` | API key for the LLM provider |
| `DEVAI_BASE_URL` | Base URL (default: OpenAI) |
| `DEVAI_MODEL` | Model name (default: `gpt-4o-mini`) |
| `DEVAI_MAX_TOKENS` | Max tokens per request |
| `DEVAI_TEMPERATURE` | Sampling temperature |

## License

MIT
