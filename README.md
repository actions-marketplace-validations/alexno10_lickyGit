# 🔍 lickyGit

> **Lick every secret out of your Git history.**

A modern, cross-platform Git secret scanner that detects leaked credentials, API keys, tokens, and sensitive data across your entire commit history.

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔑 **35+ Built-in Rules** | AWS, GitHub, GitLab, Slack, Stripe, Google, Azure, npm, PyPI, Docker, and more |
| 📊 **Shannon Entropy** | Detect high-entropy strings (random API keys, tokens) even without pattern rules |
| 🔤 **Keyword Detection** | Find `password = "..."`, `api_key: "..."` assignments in 4+ config formats |
| 🖥️ **Cross-Platform** | Works on Windows, macOS, and Linux (uses GitPython, not shell commands) |
| ⚡ **Parallel Scanning** | Multi-threaded scanning for large repositories |
| 📝 **5 Output Formats** | Terminal (Rich), JSON, CSV, SARIF, HTML Report |
| 🚫 **Allowlisting** | Suppress known false positives with `.lickygit-allow` |
| 🪝 **Pre-commit Hook** | Block secrets before they're committed |
| ⚙️ **Configurable** | Per-project `.lickygit.toml` configuration |
| 🧩 **Custom Rules** | Define your own regex rules in TOML or YAML |

## 📦 Installation

```bash
pip install lickygit
```

## 🚀 Quick Start

```bash
# Scan the current repository
lickygit scan

# Scan only HEAD (faster)
lickygit scan --head-only

# Scan a remote repo
lickygit scan --url https://github.com/user/repo.git --delete

# Output as JSON
lickygit scan -f json -o results.json

# Output as HTML report
lickygit scan -f html -o report.html

# Only show HIGH and CRITICAL findings
lickygit scan --severity high

# Disable entropy detection (fewer false positives)
lickygit scan --no-entropy
```

## 🪝 Pre-commit Hook

### Built-in hook

```bash
# Install the hook
lickygit hook install

# Uninstall
lickygit hook uninstall
```

### With pre-commit framework

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/lickygit/lickygit
    rev: v1.0.0
    hooks:
      - id: lickygit
```

## ⚙️ Configuration

Create `.lickygit.toml` in your project root:

```toml
[scan]
head_only = false
max_workers = 4
severity = "medium"    # low | medium | high | critical

[detection]
use_entropy = true
use_keywords = true
use_builtin_rules = true
entropy_threshold = 4.5

[filters]
exclude = ["*.lock", "vendor/*", "*.min.js"]
allowlist = ".lickygit-allow"

[output]
format = "terminal"
verbose = false
```

## 🚫 Allowlisting

Create `.lickygit-allow` to suppress false positives:

```
# Exact substring match
EXAMPLE_TOKEN_TO_ALLOW

# Regex match
regex:test_token_[a-z]+

# Scoped to specific files
scope:*.test.py my_test_secret

# With reason
EXAMPLE_TOKEN_TO_ALLOW # This is a safe development token
```

## 🧩 Custom Rules

Create a TOML or YAML file with custom detection rules:

```toml
[[rules]]
id = "my-internal-token"
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
| Terminal | `-f terminal` | Interactive, colour-coded (default) |
| JSON | `-f json` | CI/CD pipelines, automation |
| CSV | `-f csv` | Spreadsheet analysis |
| SARIF | `-f sarif` | GitHub Code Scanning |
| HTML | `-f html` | Standalone reports |

## 🏗️ Architecture

```
lickygit/
├── core/           # Scanner, GitWalker, Finding model
├── detection/      # Entropy, patterns, keywords, rules
├── filters/        # Allowlist, path filter, value filter
└── output/         # Terminal, JSON, CSV, SARIF, HTML
```

## 📄 License

MIT
