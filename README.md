# ArchSec Reviewer

AI-assisted security architecture review for cloud-native, AI, and distributed systems.

> **Turn architecture descriptions into structured security architecture reviews.**

ArchSec Reviewer analyzes architecture descriptions and generates:

- Detected architecture components
- Trust boundaries
- Attack paths
- STRIDE-style threat scenarios
- Recommended security controls
- Validation checklists
- Markdown security reports

---

## Features

- Architecture-aware component detection
- Trust boundary identification
- Attack path generation
- STRIDE-style threat modeling
- Security control recommendations
- Validation checklists
- Markdown report generation

---

## Example

### Input

```text
A customer support RAG assistant accepts user questions, retrieves documents
from a vector database, sends context to an LLM, and can invoke Refund and
Ticket APIs.
```

### Output

```text
Detected Components
- User
- API
- Vector Database
- LLM
- Tool Execution

Trust Boundaries
- User → API
- API → Retrieval Layer
- Vector Database → LLM
- LLM → Tool Execution

Attack Paths
- Prompt Injection → Unauthorized Tool Execution
- Retrieval Data Poisoning → Manipulated LLM Output

Recommended Controls
- Prompt isolation
- Retrieval authorization
- Tool allowlists
- Least-privilege credentials
```

---

## Installation

```bash
git clone https://github.com/khirawdhi/archsec-reviewer.git
cd archsec-reviewer
pip install -e .
```

---

## Usage

```bash
archsec-review \
    --input examples/rag-system.md \
    --output reports/security-review.md
```

Example output:

```
reports/
└── security-review.md
```

---

## Repository Structure

```text
archsec_reviewer/
├── analyzer.py
├── cli.py
├── report.py
├── rules.py
├── __init__.py
└── __main__.py

examples/
└── rag-threat-model.md

reports/
README.md
pyproject.toml
```

---

## Roadmap

- LLM-powered architecture parsing
- Mermaid architecture and attack-path diagrams
- Risk scoring
- OWASP ASVS & OWASP LLM Top 10 mapping
- MITRE ATT&CK / MITRE ATLAS mapping
- GitHub Pull Request reviews
- Local LLM support (Ollama)

---

## License

MIT