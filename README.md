# ArchSec Reviewer

AI-assisted security architecture review for cloud-native, AI, and distributed systems.

`archsec-reviewer` reads an architecture description and generates a practical security review covering:

- assets
- trust boundaries
- attack paths
- STRIDE-style threats
- recommended controls
- validation checks
- markdown threat model report

> Security failures happen at trust boundaries, not components.

---

## Install

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

Or:

```bash
python -m archsec_reviewer --input examples/rag-system.md --output outputs/rag-threat-model.md
```

---

## Example Input

```text
A RAG assistant accepts user questions, retrieves documents from a vector database,
sends context to an LLM, and may call tools such as ticket creation or refund APIs.
```

---

## Example Output

The generated report includes:

- system summary
- detected components
- trust boundaries
- attack paths
- threat scenarios
- security recommendations
- validation checklist

---

## Best For

- Security architecture reviews
- Product security design reviews
- Threat modeling workshops
- AI / LLM system reviews
- Cloud-native and distributed system reviews

---

## Repository Structure

```text
archsec_reviewer/
  __main__.py
  cli.py
  analyzer.py
  report.py
  rules.py
examples/
  rag-system.md
outputs/
README.md
pyproject.toml
```

---

## Roadmap

- YAML/JSON architecture input
- Mermaid diagram generation
- Risk scoring
- OWASP LLM mapping
- CI mode for pull requests
- Local LLM support

---

## Disclaimer

This tool is intended for defensive security reviews and authorized security assessment workflows only.

## License

MIT
