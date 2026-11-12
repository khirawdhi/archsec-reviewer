# ArchSec Reviewer

A deterministic security architecture analysis tool for cloud-native, distributed and AI-enabled systems.

It analyzes structured YAML architectures to generate evidence-backed findings, prioritized attack paths and developer-friendly security reports.

## Features

- Models components, assets, trust zones and data flows
- Detects flow-specific security risks
- Discovers and prioritizes multi-hop attack paths
- Explains findings using architecture evidence
- Exports Markdown, JSON, Mermaid and SARIF
- Publishes SARIF findings to GitHub Code Scanning

## Installation

```bash
git clone https://github.com/khirawdhi/archsec-reviewer.git
cd archsec-reviewer

python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

For development:

```bash
python -m pip install -e ".[dev]"
```

## Usage

```bash
archsec-review \
  --input examples/rag-system.yaml \
  --output reports/rag-security-review.md
```

Select another output format with:

```bash
archsec-review \
  --input examples/rag-system.yaml \
  --output reports/rag-security-review.sarif \
  --format sarif
```

Supported formats:

| Format | Purpose |
|---|---|
| `markdown` | Human-readable security review |
| `json` | Machine-readable review |
| `mermaid` | Architecture and attack-path diagram |
| `sarif` | GitHub Code Scanning integration |

Use `--attack-path-cutoff` to limit the maximum attack-path depth.

## Analysis

Current rules identify:

- User input reaching an LLM
- Retrieved content influencing an LLM
- Model output reaching executable tools
- Unauthenticated or unencrypted trust-boundary crossings
- Multi-hop paths to privileged or sensitive targets

Findings include severity, confidence, evidence, affected components, recommended controls and validation steps.

## Quality

- 79 automated tests
- Approximately 95% coverage
- Ruff and strict mypy validation
- CI across Python 3.9–3.13
- Package-build and GitHub Code Scanning workflows

## Scope

ArchSec Reviewer analyzes declared architecture relationships. It does not inspect source code, prove exploitability or replace human security judgment.

## License

MIT