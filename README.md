# Skills Scanner

**AI-first security scanner for AI agent plugins and skills.**

Scans plugin manifests, skills, hooks, MCP/LSP servers, scripts, agents, commands, and resources using LLM-powered analysis by default. Every component is scanned in parallel, findings are classified as **Malicious** or **Code Security**, false positives are filtered through evidence-based AI triage, and a clear **safety verdict** is produced. Optional static analysis (235 YAML rules, 41 categories) can be layered on with `--static`.

![Skill Scanner](media/image.png)

---

## Features

- **AI-first scanning** — per-component LLM analysis with 17 security categories, runs by default
- **Evidence-based triage** — skeptical second-pass LLM validation removes false positives
- **CI/PR scanning** (`--ci-pr`) — differential scanning on PRs with LLM-powered impact analysis
- **Multi-target discovery** (`--discover`) — recursively find and scan all plugins/skills in a repo
- **Optional static analysis** (`--static`) — 235 YAML rules, 41 categories, 11 specialized analyzers
- **6 AI providers** — OpenAI, Azure OpenAI, Gemini, Bedrock, Anthropic, xAI Grok
- **Multiple outputs** — JSON, SARIF, CSV, graph visualization
- **Interactive graph UI** — React Flow visualization with filtering and multi-scan support
- **Configurable modes** — `strict`, `balanced`, `permissive` profiles

---

## Quick Start

```bash
git clone https://github.com/your-org/skills-scanner.git && cd skills-scanner
pip install -r requirements.txt

# Install your AI provider
pip install langchain-openai       # or langchain-google-genai, langchain-anthropic, langchain-xai, langchain-aws

export OPENAI_API_KEY=sk-...

python -m scanner /path/to/plugin --ai-provider openai
```

### Common Usage

```bash
# Scan with static analysis alongside AI
python -m scanner /path/to/plugin --static --ai-provider gemini

# Discover and scan all plugins/skills in a repo
python -m scanner /path/to/repo --discover --ai-provider openai

# SARIF output for CI/CD
python -m scanner /path/to/plugin --output sarif --output-file results.sarif --fail-on high

# Graph output for visualization UI
python -m scanner /path/to/plugin --output graph --output-file scan.json

# Marketplace scan
python -m scanner --marketplace https://github.com/org/plugins --ai-provider openai
```

---

## Architecture

![Architecture](media/architecture.png)

### Finding Classification

Based on the Snyk threat taxonomy (*"Exploring the Emerging Threats of the Agent Skill Ecosystem"*, Feb 2026):

| **Malicious** (intentional attacks) | **Code Security** (bugs/misconfigs) |
|--------------------------------------|--------------------------------------|
| prompt_injection, social_engineering, unicode_steganography, tool_poisoning, data_exfiltration, obfuscation, autonomy_abuse, malicious_code, suspicious_downloads, system_modification | command_injection, path_traversal, credential_exposure, privilege_escalation, supply_chain, third_party_exposure, financial_access |

---

## AI Providers

| Provider | `--ai-provider` | Environment Variable | Package |
|----------|----------------|---------------------|---------|
| OpenAI | `openai` | `OPENAI_API_KEY` | `langchain-openai` |
| Azure OpenAI | `azure` | `AZURE_OPENAI_API_KEY` + `AZURE_OPENAI_ENDPOINT` | `langchain-openai` |
| Google Gemini | `gemini` | `GOOGLE_API_KEY` | `langchain-google-genai` |
| AWS Bedrock | `bedrock` | `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` | `langchain-aws` |
| Anthropic | `anthropic` | `ANTHROPIC_API_KEY` | `langchain-anthropic` |
| xAI Grok | `xai` | `XAI_API_KEY` | `langchain-xai` |

---

## CI/CD Integration

### PR Security Scan (`--ci-pr`)

Differential scanning on PRs — detects only vulnerabilities introduced or worsened by the change:

1. **Fetch changed files** via GitHub REST API
2. **LLM target resolution** — identifies affected skills/plugins and classifies change scenario
3. **Differential scan** — scans both base and HEAD versions
4. **LLM impact analysis** — semantically correlates findings against code diffs to classify each as new, worsened, resolved, or unchanged
5. **Report** — PR comment (markdown) + SARIF + JSON

#### GitHub Actions Workflow

```yaml
name: Skill Security Scan
on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
      security-events: write
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - run: pip install -r requirements.txt

      - name: Run PR security scan
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          python -m scanner . \
            --ci-pr \
            --pr-number ${{ github.event.pull_request.number }} \
            --base-ref origin/${{ github.base_ref }} \
            --head-ref ${{ github.sha }} \
            --ai-provider openai \
            --output sarif \
            --output-file results.sarif \
            --pr-comment-file pr-comment.md \
            --fail-on high

      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif

      - uses: marocchino/sticky-pull-request-comment@v2
        if: always()
        with:
          path: pr-comment.md
```

#### Reusable Action

```yaml
- uses: your-org/skills-scanner@main
  with:
    ai-provider: openai
    fail-on: high
  env:
    OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

#### Running Locally

```bash
# Local repo
python -m scanner . --ci-pr --base-ref main --head-ref feature-branch --ai-provider openai

# With GitHub API for file detection
python -m scanner . --ci-pr --pr-number 42 --base-ref origin/main --github-token ghp_xxx --ai-provider openai

# GitHub URL (auto-clones)
python -m scanner https://github.com/org/repo --ci-pr --pr-number 42 --github-token ghp_xxx --ai-provider openai
```

---

## CLI Reference

| Flag | Default | Description |
|------|---------|-------------|
| `plugin_path` | — | Path to plugin directory (or GitHub URL with `--ci-pr`) |
| `--marketplace`, `-m` | — | Git URL of marketplace to scan |
| `--discover` | off | Recursively discover and scan all plugins/skills |
| `--ci-pr` | off | CI mode: differential scan on PR changes |
| `--static` | off | Also run static rule-based analysis |
| `--ai-provider` | `openai` | `openai`, `azure`, `gemini`, `bedrock`, `anthropic`, `xai` |
| `--ai-model` | provider default | Specific model to use |
| `--ai-triage-threshold` | `0.5` | Min confidence to keep a triaged finding (0.0–1.0) |
| `--workers`, `-w` | `4` | Max parallel LLM calls |
| `--rpm` | `0` (unlimited) | Max LLM requests per minute |
| `--output`, `-o` | `json` | `json`, `sarif`, `graph` |
| `--output-file`, `-f` | stdout | Output file path |
| `--mode` | `balanced` | `strict`, `balanced`, `permissive` |
| `--fail-on` | — | Exit non-zero at this severity or higher |
| `--pr-number` | auto-detect | PR number (CI mode) |
| `--base-ref` / `--head-ref` | auto-detect | Git refs for comparison (CI mode) |
| `--github-token` | `GITHUB_TOKEN` env | GitHub token (CI mode) |
| `--pr-comment-file` | — | Write PR comment to file (CI mode) |
| `--verbose` / `--quiet` | off | Control output verbosity |

```bash
python -m scanner rules --list       # List all rules
python -m scanner rules --stats      # Rule statistics
```

---

## Configuration

Three scan modes: `strict` (max coverage), `balanced` (default), `permissive` (less noise). All settings configurable via `config.yaml` — see the file in the project root for all options.

---

## Visualization

```bash
cd viz && npm install && npm run dev    # http://localhost:5173
```

Generate data: `python -m scanner /path/to/plugin --output graph --output-file scan.json`

Supports single and multi-scan (`--discover`) reports with interactive filtering, component inspection, and safety verdict badges.

---

## Custom Rules

YAML rules in `scanner/rules/yaml/` (used with `--static`):

```yaml
- id: my-custom-rule
  name: Custom Security Check
  severity: high
  category: custom-rules
  pattern: "dangerous_function\\s*\\("
  recommendation: Replace with safe_alternative
```

---

## Project Structure

```
skills-scanner/
├── scanner/                    # Main Python package
│   ├── main.py                 # CLI orchestration
│   ├── core/                   # Plugin parser + 11 static analyzers
│   ├── ai/                     # LLM analysis, triage, prompts, prompt guard
│   ├── ci/                     # CI/PR scanning (changed files, target resolver, diff scanner, reporter)
│   ├── rules/                  # YAML security rules (235 rules, 41 categories)
│   ├── config/                 # Scan configuration and mode profiles
│   ├── reporters/              # JSON, SARIF, CSV, graph output
│   └── utils/                  # Discovery, git utilities
├── viz/                        # React visualization UI
├── tests/                      # Test suite
├── .github/workflows/          # GitHub Actions PR scan workflow
├── action.yml                  # Reusable GitHub Action
├── config.yaml                 # Default configuration
├── requirements.txt            # Runtime dependencies
└── requirements-dev.txt        # Dev dependencies
```

---

## Development

```bash
pip install -r requirements-dev.txt
python -m pytest tests/ -v
ruff check scanner/ && black scanner/ tests/
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## Contributors

See [CONTRIBUTORS.md](CONTRIBUTORS.md).

---

## License

Licensed under the [Apache License 2.0](LICENSE).

Copyright 2026 Skills Scanner Contributors.
