# ArchSec Reviewer

AI-assisted security architecture review for cloud-native, AI, and distributed systems.

> **Automate security architecture reviews by identifying trust boundaries, attack paths, STRIDE threats, and recommended security controls from system designs.**

---

## Why ArchSec Reviewer?

Security architecture reviews are often manual, inconsistent, and time-consuming.

ArchSec Reviewer analyzes architecture descriptions and generates a structured security review including:

* Assets
* Trust boundaries
* Attack paths
* STRIDE-style threats
* Security controls
* Validation checklist
* Markdown threat model report

The goal is to help security engineers perform faster, more consistent design reviews—not replace human judgment.

---

## Features

* Detects architecture components
* Identifies trust boundaries
* Maps potential attack paths
* Generates STRIDE-style threat scenarios
* Recommends security controls
* Produces a Markdown security review

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
archsec-review --input examples/rag-system.md --output outputs/rag-threat-model.md
```

or

```bash
python -m archsec_reviewer --input examples/rag-system.md --output outputs/rag-threat-model.md
```

---

## Example

**Input**

```text
A RAG assistant accepts user questions, retrieves documents from a vector database, sends context to an LLM, and can call external tools such as a refund API.
```

**Generated Report**

* System summary
* Detected components
* Trust boundaries
* Attack paths
* STRIDE threats
* Recommended controls
* Validation checklist

---

## Repository Structure

```text
archsec_reviewer/
examples/
outputs/
README.md
pyproject.toml
```

---

## Roadmap

* LLM-powered architecture parsing
* Mermaid attack-path diagrams
* Risk scoring
* OWASP ASVS / LLM Top 10 mapping
* GitHub PR integration
* Local LLM support (Ollama)

---

## Disclaimer

This project is intended for defensive security reviews and authorized security assessment workflows only.

## License

MIT
