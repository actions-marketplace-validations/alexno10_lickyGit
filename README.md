# 🔍 lickyGit

> **Lick every secret out of your Git history.**

A modern, high-performance, cross-platform Git secret scanner that detects leaked credentials, API keys, tokens, and sensitive data across your commit history, staging area, and pull requests.

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔑 **35+ Built-in Rules** | AWS, GitHub, GitLab, Slack, Stripe, Google, Azure, npm, PyPI, Docker, and more |
| 📊 **Shannon Entropy** | Detect high-entropy strings (random API keys, tokens) even without pattern rules |
| 🔤 **Keyword Detection** | Find `password = "..."`, `api_key: "..."` assignments with intelligent false-positive filters |
| ⚡ **Blob SHA Caching** | Instant multi-commit history scans by avoiding redundant object re-scans |
| 🪝 **Staged Changes Scanning** | Scan staged index changes (`--staged`) for zero-leak pre-commit protection |
| 📑 **Baseline Support** | Suppress existing legacy findings with `--baseline` and `--generate-baseline` |
| 🖥️ **Cross-Platform** | Works on Windows, macOS, and Linux (uses native Git object storage) |
| 📝 **5 Output Formats** | Terminal (Rich), JSON, CSV, SARIF 2.1.0, and interactive dark-mode HTML |
| 🚫 **Allowlisting** | Suppress known false positives with `.lickygit-allow` |
| ⚙️ **Configurable** | Per-project `.lickygit.toml` configuration |
| 🧩 **Custom Rules** | Define your own regex rules in TOML or YAML |
| 🐙 **Official GitHub Action** | Plug-and-play CI integration with code scanning SARIF upload |

## 📦 Installation

```bash
pip install lickygit
```

## 🚀 Quick Start

```bash
# Scan entire repository history
lickygit scan

# Scan only currently staged changes (pre-commit)
lickygit scan --staged

# Scan only the HEAD commit
lickygit scan --head-only

# Scan a remote repository and clean up afterwards
lickygit scan --url https://github.com/user/repo.git --delete

# Only report HIGH and CRITICAL findings
lickygit scan --severity high

# Generate an interactive HTML report
lickygit scan -f html -o report.html

# Output as SARIF (for security tools and IDEs)
lickygit scan -f sarif -o results.sarif
```

## 🪝 Pre-commit Hook

Block accidental secret commits right at your machine.

### Built-in Hook

```bash
# Install the pre-commit hook (automatically uses --staged)
lickygit hook install

# Block only CRITICAL secrets
lickygit hook install --severity critical

# Uninstall
lickygit hook uninstall
```

### With Pre-commit Framework

Add this to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/alexno10/lickyGit
    rev: main
    hooks:
      - id: lickygit
```

## 📑 Baseline Management (CI/CD)

Prevent CI pipelines from failing on existing legacy secrets while blocking any **new** leaks in pull requests:

```bash
# 1. Generate a baseline file of existing findings
lickygit scan --generate-baseline .lickygit-baseline.json

# 2. Run future scans against the baseline (ignores known baseline findings)
lickygit scan --baseline .lickygit-baseline.json
```

## 🐙 GitHub Action

Add automated secret scanning to your GitHub repository with two lines:

```yaml
name: Security Audit

on: [push, pull_request]

jobs:
  secret-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write

    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Scan with lickyGit
        uses: alexno10/lickyGit@main
        with:
          severity: 'high'
          upload-sarif: 'true'
```

## ⚙️ Configuration

Create `.lickygit.toml` in your project root:

```toml
[scan]
head_only = false
max_workers = 4
severity = "medium"    # low | medium | high | critical
max_file_size = 5242880 # 5MB limit

[detection]
use_entropy = true
use_keywords = true
use_builtin_rules = true
entropy_threshold = 4.5

[filters]
exclude = ["*.lock", "vendor/*", "*.min.js", "go.sum", "*.schema.json"]
allowlist = ".lickygit-allow"
baseline = ".lickygit-baseline.json"

[output]
format = "terminal"
verbose = false
```

## 🚫 Allowlisting

Create `.lickygit-allow` to suppress specific known false positives:

```
# Exact substring match
EXAMPLE_TOKEN_TO_ALLOW

# Regex match
regex:test_token_[a-z]+

# Scoped to specific files
scope:*.test.py my_test_secret

# With reason
EXAMPLE_TOKEN_TO_ALLOW # Safe development mock token
```

## 🧩 Custom Rules

Define project-specific secret patterns in TOML or YAML:

```toml
[[rules]]
id = "internal-service-token"
name = "Internal Service Token"
pattern = "INT_SVC_[A-Z0-9]{32}"
severity = "HIGH"
description = "Internal service authentication token"
```

```bash
lickygit scan --custom-rules my-rules.toml
```

## 📊 Output Formats

| Format | Flag | Use Case |
|--------|------|----------|
| Terminal | `-f terminal` | Interactive, color-coded table (default) |
| HTML | `-f html` | Standalone interactive dark-mode dashboard |
| SARIF | `-f sarif` | GitHub Code Scanning / Security Tab |
| JSON | `-f json` | CI/CD pipelines and automation scripts |
| CSV | `-f csv` | Spreadsheet audits and compliance reports |

## 🏗️ Architecture

```
lickygit/
├── core/           # Scanner, GitWalker (index/staged & history), Finding model
├── detection/      # Entropy analyzer, Regex pattern matcher, Keywords detector, Rules
├── filters/        # Allowlist, Path filter, Value filter, Baseline manager
└── output/         # Terminal (Rich), JSON, CSV, SARIF 2.1.0, HTML Report
```

## 📄 License

MIT
