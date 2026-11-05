# ArchSec Reviewer

A deterministic security architecture analysis engine for cloud-native, distributed, and AI-enabled systems.

> Model trust transitions, discover attack paths, and generate evidence-backed security findings.

ArchSec Reviewer converts a structured architecture definition into a security review containing:

- Components, assets, trust zones, and data flows
- Flow-specific security findings
- Multi-hop attack paths
- Transparent attack-path prioritization
- Trust-boundary transitions
- Finding severity and confidence
- Supporting architecture evidence
- Recommended security controls
- Validation procedures
- Markdown, JSON, Mermaid, and SARIF outputs

## Why ArchSec Reviewer?

Traditional threat-model reports often depend on manually interpreting diagrams and architecture documents. Generic LLM-generated reviews can also produce plausible threats without showing whether the architecture actually supports those conclusions.

ArchSec Reviewer separates architecture evidence from security reasoning.

A finding is generated from an explicit relationship:

```text
LLM → Refund Tool
```

rather than from the words `LLM` and `tool` merely appearing in the same document.

The goal is not to make an AI model the security authority. The goal is to build a deterministic security-analysis foundation that can later use guarded AI assistance.

## Analysis Pipeline

```mermaid
flowchart TD
    A["YAML architecture"] --> B["Safe parser"]
    B --> C["Validated system model"]
    C --> D["Flow-aware rule engine"]
    C --> E["NetworkX attack-path engine"]
    D --> F["Evidence-backed findings"]
    E --> G["Prioritized attack paths"]
    F --> H["Structured security review"]
    G --> H
    H --> I["Markdown report"]
    H --> J["Versioned JSON"]
    H --> K["Mermaid diagram"]
```

## Current Capabilities

### Structured Architecture Model

ArchSec Reviewer models:

- Components and component types
- Trust zones and trust levels
- Assets and data classifications
- Directed data flows
- Authentication and encryption state
- Privileges and data handled
- Security objectives
- Architecture assumptions

### Flow-Aware Security Analysis

Rules are evaluated against directed relationships, including:

- User input reaching an LLM
- Retrieved content entering an LLM context
- LLM output reaching executable tools
- Unauthenticated cross-zone communication
- Unencrypted cross-zone communication

### Evidence-Backed Findings

Each finding includes:

- Stable finding ID
- Threat category
- Attack scenario
- Severity
- Confidence
- Affected components
- Supporting evidence
- Assumptions
- Recommended controls
- Validation steps
- Optional standards references

### Graph-Based Attack Paths

NetworkX is used to:

- Build a directed architecture graph
- Identify untrusted entry points
- Identify privileged and sensitive targets
- Discover multi-hop paths
- Limit path depth
- Handle graph cycles safely
- Preserve flow IDs as evidence
- Record trust-zone transitions

### Transparent Attack-Path Prioritization

Discovered attack paths receive:

- A priority level
- A numerical priority score
- Human-readable scoring factors
- Sensitive-target consideration
- Trust-boundary consideration
- Related-finding severity consideration

This makes the prioritization explainable rather than presenting an unexplained risk score.

### Safe YAML Processing

Structured input uses:

- `yaml.safe_load()`
- A 1 MB input limit
- UTF-8 validation
- Required-field validation
- Enum validation
- Component-reference validation
- Duplicate-ID detection
- Rejection of unsafe Python object tags

### Multiple Output Formats

ArchSec Reviewer can generate:

- Human-readable Markdown security reviews
- Versioned JSON for integrations and automation
- Mermaid architecture diagrams grouped by trust zone
- SARIF 2.1.0 for code-scanning and security-tool integrations

Mermaid output highlights high- and critical-priority attack paths, including entry points, intermediate components, sensitive targets, and supporting data flows.

## Installation

Clone the repository:

```bash
git clone https://github.com/khirawdhi/archsec-reviewer.git
cd archsec-reviewer
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install ArchSec Reviewer:

```bash
python -m pip install -e .
```

For development:

```bash
python -m pip install -e ".[dev]"
```

## Quick Start

Generate a structured Markdown review:

```bash
archsec-review \
  --input examples/rag-system.yaml \
  --output reports/rag-security-review.md
```

The YAML extension selects the structured analysis pipeline automatically. Markdown is the default output format.

Preview the generated report:

```bash
sed -n '1,120p' reports/rag-security-review.md
```

## Output Formats

### Markdown

Generate a human-readable security review:

```bash
archsec-review \
  --input examples/rag-system.yaml \
  --output reports/rag-security-review.md \
  --format markdown
```

### JSON

Generate a versioned, machine-readable security review:

```bash
archsec-review \
  --input examples/rag-system.yaml \
  --output reports/rag-security-review.json \
  --format json
```

JSON includes:

- Schema version
- Architecture inventory
- Trust zones
- Assets and data flows
- Findings and evidence
- Standards references
- Prioritized attack paths
- Trust transitions
- Summary counts

### Mermaid

Generate a visual architecture diagram:

```bash
archsec-review \
  --input examples/rag-system.yaml \
  --output reports/rag-architecture.mmd \
  --format mermaid
```

The Mermaid diagram includes:

- Components grouped by trust zone
- Directed data flows
- Protocol labels
- Unauthenticated and unencrypted flow indicators
- High- and critical-priority attack paths
- Distinct styling for entry points, intermediate nodes, and targets

JSON and Mermaid output require structured YAML input.

### SARIF

Generate a SARIF 2.1.0 security-analysis report:

```bash
archsec-review \
  --input examples/rag-system.yaml \
  --output reports/rag-security-review.sarif \
  --format sarif
```

SARIF output includes:

- Stable security rule identifiers
- Rule metadata and severity defaults
- Finding-specific results
- Architecture evidence and affected components
- Recommended controls and validation steps
- Standards references
- The input YAML file as the alert location

SARIF output can be consumed by compatible security tools and CI/CD integrations. GitHub code-scanning upload automation is not configured by this command itself.

## Example Architecture

```yaml
name: Tool-Using Assistant

trust_zones:
  - id: internet
    name: Internet
    trust_level: untrusted

  - id: ai
    name: AI Runtime
    trust_level: internal

  - id: privileged
    name: Privileged Operations
    trust_level: privileged

components:
  - id: user
    name: Customer
    type: user
    trust_zone: internet

  - id: llm
    name: Support LLM
    type: llm
    trust_zone: ai

  - id: refund_tool
    name: Refund Tool
    type: tool
    trust_zone: privileged

assets:
  - id: refund_capability
    name: Refund Capability
    classification: restricted
    owner_component: refund_tool

data_flows:
  - id: user_to_llm
    source: user
    destination: llm
    authenticated: true
    encrypted: true

  - id: llm_to_refund
    source: llm
    destination: refund_tool
    authenticated: true
    encrypted: true

security_objectives:
  - Prevent unauthorized refunds.
```

## Example Finding

```text
[HIGH] AI-TOOL-001:llm_to_refund

Title:
Model output reaches an executable tool

Scenario:
Manipulated model output can request a consequential tool
operation without independent authorization.

Affected components:
llm, refund_tool

Evidence:
Data flow 'llm_to_refund' connects Support LLM to Refund Tool.

Controls:
- Authorize every tool action outside the model
- Use scoped tool credentials
- Require approval for high-impact actions

Validation:
- Attempt unauthorized tool use through prompt injection
- Verify the model cannot provide the acting user identity
```

## Example Attack Path

```text
AP-001

Entry point:
customer

Target:
refund_tool

Route:
customer → web_app → backend_api → vector_db → llm → refund_tool

Trust transitions:
internet → edge
edge → application
application → data
data → external_ai
external_ai → privileged
```

## Legacy Markdown Mode

Markdown and text files continue to use the original keyword-based analyzer:

```bash
archsec-review \
  --input examples/rag-system.md \
  --output reports/generated-rag-review.md
```

Structured YAML is recommended for architecture-aware analysis. JSON and Mermaid output are not available for legacy Markdown input.

## CLI Options

```text
-i, --input
    Architecture input file.

-o, --output
    Output report path.

-f, --format
    Structured output format:
    markdown, json, mermaid, or sarif
    Default: markdown.

-t, --title
    Report title for legacy Markdown or text input.

--attack-path-cutoff
    Maximum number of graph edges in an attack path.
    Default: 6.
```

Example:

```bash
archsec-review \
  --input examples/rag-system.yaml \
  --output reports/rag-security-review.json \
  --format json \
  --attack-path-cutoff 5
```

## Repository Structure

```text
archsec_reviewer/
├── application.py
├── analyzer.py
├── cli.py
├── report.py
├── rules.py
├── domain/
│   ├── architecture.py
│   ├── attack_path.py
│   ├── finding.py
│   └── review.py
├── engines/
│   ├── attack_paths.py
│   ├── flow_analysis.py
│   └── prioritization.py
├── parsers/
│   └── yaml_parser.py
└── reporters/
    ├── json_report.py
    ├── markdown.py
    └── mermaid.py
    └── sarif.py

examples/
├── rag-system.md
└── rag-system.yaml

tests/
├── test_application.py
├── test_architecture_model.py
├── test_attack_paths.py
├── test_cli.py
├── test_flow_analysis.py
├── test_json_reporter.py
├── test_mermaid_reporter.py
├── test_prioritization.py
└── test_yaml_parser.py
└── test_sarif_reporter.py

```

## Development

Run the test suite:

```bash
pytest -v
```

Run tests with coverage:

```bash
pytest \
  --cov=archsec_reviewer \
  --cov-report=term-missing \
  --cov-fail-under=85
```

Check formatting:

```bash
ruff format --check .
```

Run linting:

```bash
ruff check .
```

Run strict type checking:

```bash
mypy archsec_reviewer
```

Build the package:

```bash
python -m build
```

## Continuous Integration

GitHub Actions validates:

- Python 3.9–3.13
- Ruff formatting
- Ruff linting
- Strict mypy checks
- Automated tests
- Minimum 85% coverage
- Python package builds

## Security Design

Architecture definitions are treated as untrusted input.

Current protections include:

- Safe YAML loading
- Input-size limits
- Schema-style field validation
- Reference-integrity validation
- Escaping of user-controlled report and diagram content
- Generated Mermaid-safe node identifiers
- No shell or arbitrary code execution
- Deterministic findings based on declared flows

Future LLM integration will remain separate from the deterministic analysis authority. Model-generated suggestions will require schema validation, architecture evidence, and human review.

## Current Limitations

- Flow rules currently cover a focused set of AI and trust-boundary scenarios.
- Attack paths show reachability, not proof of exploitability.
- Severity is rule-defined and is not yet environment-adjusted.
- Mermaid output produces diagram source rather than a rendered image.
- SARIF findings currently point to line 1 of the input YAML file rather than the exact declaring YAML node.
- Automatic upload to GitHub code scanning is not yet configured.
- Comprehensive standards mappings are not yet implemented.
- LLM-assisted architecture extraction is not yet implemented.
- Markdown input uses the legacy keyword analyzer.

## Roadmap

### Analysis

- Identity and authorization rules
- Microservice and Kubernetes rules
- CI/CD and software-supply-chain rules
- Event-driven architecture rules
- OWASP, MITRE ATT&CK, and MITRE ATLAS mappings
- Environment-aware risk adjustment

### Output

- GitHub pull-request annotations
- GitHub code-scanning upload workflow
- Exact YAML source locations for SARIF findings

### Guarded AI Assistance

- Architecture extraction from prose
- Missing-information questions
- Adversarial threat analysis
- Evidence critic
- Local model support
- Policy-gated tools
- Human approval checkpoints

## License

This project is licensed under the MIT License.