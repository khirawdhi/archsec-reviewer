# ArchSec Reviewer

AI-assisted security architecture review for cloud-native, AI, and distributed systems.

> **Turn architecture descriptions into structured security architecture reviews.**

ArchSec Reviewer analyzes system designs and generates:

* Trust boundaries
* Attack paths
* STRIDE-style threats
* Recommended security controls
* Validation checklists
* Markdown security reports

---

## Example

### Input

```text id="g9lntc"
A customer support RAG assistant retrieves documents from a vector database,
sends context to an LLM, and can invoke Refund and Ticket APIs.
```

↓

### Output

```text id="s0bdu8"
Overall Risk: HIGH

Top Risks
• Prompt Injection
• Retrieval Data Poisoning
• Unauthorized Tool Execution

Trust Boundaries
• User → API
• API → Vector DB
• Vector DB → LLM
• LLM → Tool Execution
```

---

## Installation

```bash id="kik1dm"
git clone https://github.com/khirawdhi/archsec-reviewer.git
cd archsec-reviewer
pip install -e .
```

---

## Usage

```bash id="i9nlry"
archsec-review \
  --input examples/rag-system.md \
  --output reports/security-review.md
```

---

## Roadmap

* LLM-powered architecture parsing
* Mermaid attack graphs
* Risk scoring
* OWASP & MITRE mapping
* GitHub PR reviews
* Local LLM support

---

## License

MIT
