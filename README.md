# ArchSec Reviewer

AI-assisted security architecture review for cloud-native, AI, and distributed systems.

> **Turn architecture descriptions into structured security architecture reviews.**

ArchSec Reviewer analyzes system designs and generates:

- Trust boundaries
- Attack paths
- STRIDE-style threat analysis
- Security recommendations
- Validation checklists
- Markdown security reports

---

## Features

- Analyze architecture descriptions
- Detect security-critical components
- Identify trust boundaries
- Generate attack paths
- Perform STRIDE-style threat analysis
- Recommend security controls
- Generate Markdown security reports

---

## Example

### Input

```text
A customer support RAG assistant accepts user questions through a web application.

The backend retrieves relevant documents from a vector database before sending the prompt to an LLM.

For selected requests, the AI agent can invoke backend APIs such as Refund, Ticket Creation, and Customer Profile services.

OAuth is used for service-to-service authentication.
```

↓

### Generated Report

```text
Overall Risk: HIGH

Top Risks
• Prompt Injection
• Retrieval Data Poisoning
• Unauthorized Tool Execution

Trust Boundaries
• User → API
• API → Vector Database
• Vector Database → LLM
• LLM → Tool Execution

Recommended Controls
• Retrieval Authorization
• Prompt Isolation
• Output Filtering
• Tool Allowlists
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

or

```bash
python -m archsec_reviewer \
  --input examples/rag-system.md \
  --output reports/security-review.md
```

---

## Repository Structure

```text
archsec_reviewer/
├── analyzer.py
├── cli.py
├── report.py
├── rules.py
├── __main__.py
└── __init__.py

examples/
reports/

README.md
pyproject.toml
LICENSE
```

---

## Current Status

🚧 **MVP (v0.1)**

Current capabilities:

- Rule-based architecture analysis
- Component detection
- Trust boundary identification
- Attack path generation
- STRIDE-style threat analysis
- Security control recommendations
- Markdown report generation

---

## Roadmap

- LLM-powered architecture parsing
- Risk scoring
- Mermaid attack graphs
- OWASP ASVS & OWASP Top 10 for LLM Applications mapping
- MITRE ATT&CK / ATLAS mapping
- GitHub Pull Request integration
- Local LLM support
- Architecture diagram ingestion (Draw.io, Mermaid, PlantUML)

---

## Who It's For

- Product Security Engineers
- Security Architects
- Application Security Engineers
- Cloud & Platform Engineers
- Developers building AI and distributed systems

---

## Disclaimer

This project is intended for defensive security reviews and authorized security assessment workflows only.

---

## License

MIT
