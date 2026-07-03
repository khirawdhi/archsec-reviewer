from dataclasses import dataclass, field
from typing import List, Dict

from .rules import COMPONENT_KEYWORDS, CONTROL_LIBRARY, THREAT_LIBRARY


@dataclass
class Review:
    title: str
    summary: str
    components: List[str] = field(default_factory=list)
    trust_boundaries: List[str] = field(default_factory=list)
    attack_paths: List[str] = field(default_factory=list)
    threats: Dict[str, List[str]] = field(default_factory=dict)
    controls: Dict[str, List[str]] = field(default_factory=dict)
    validation_checks: List[str] = field(default_factory=list)


def _detect_components(text: str) -> List[str]:
    lowered = text.lower()
    detected = []

    for component, keywords in COMPONENT_KEYWORDS.items():
        if any(keyword in lowered for keyword in keywords):
            detected.append(component)

    return detected


def _build_trust_boundaries(components: List[str]) -> List[str]:
    boundaries = []

    if "user" in components and "api" in components:
        boundaries.append("User / Client → API or application boundary")

    if "api" in components and "database" in components:
        boundaries.append("Application service → Database boundary")

    if "api" in components and "vector_db" in components:
        boundaries.append("Application service → Retrieval / vector database boundary")

    if "vector_db" in components and "llm" in components:
        boundaries.append("Retrieved context → LLM prompt construction boundary")

    if "llm" in components and "tool" in components:
        boundaries.append("LLM reasoning → Tool / action execution boundary")

    if "api" in components and "third_party" in components:
        boundaries.append("Internal service → External vendor / third-party boundary")

    if "ci_cd" in components:
        boundaries.append("Source code → Build pipeline → Artifact → Deployment boundary")

    if "identity" in components and "api" in components:
        boundaries.append("Identity provider / token issuer → Service authorization boundary")

    return boundaries or ["No explicit trust boundaries detected. Add users, services, data stores, identity, and external integrations."]


def _build_attack_paths(components: List[str]) -> List[str]:
    paths = []

    if {"user", "api", "vector_db", "llm"}.issubset(set(components)):
        paths.append("Malicious user input → retrieval query manipulation → unsafe context → insecure LLM response")

    if {"vector_db", "llm"}.issubset(set(components)):
        paths.append("Poisoned knowledge base document → retrieved as trusted context → manipulated model output")

    if {"llm", "tool"}.issubset(set(components)):
        paths.append("Prompt injection → unauthorized tool selection → sensitive action execution")

    if {"ci_cd", "storage"}.issubset(set(components)):
        paths.append("Compromised build pipeline → malicious artifact → deployment to runtime environment")

    if {"identity", "api"}.issubset(set(components)):
        paths.append("Stolen or over-scoped token → service access → lateral movement across APIs")

    return paths or ["No clear attack path detected. Add more architecture details to improve analysis."]


def _build_threats(components: List[str]) -> Dict[str, List[str]]:
    return {component: THREAT_LIBRARY[component] for component in components if component in THREAT_LIBRARY}


def _build_controls(components: List[str]) -> Dict[str, List[str]]:
    return {component: CONTROL_LIBRARY[component] for component in components if component in CONTROL_LIBRARY}


def _build_validation_checks(components: List[str]) -> List[str]:
    checks = [
        "Confirm every trust boundary has an owner and an enforcement point.",
        "Verify authorization is enforced server-side, not only in the UI.",
        "Confirm logs capture security-relevant decisions and denied actions.",
    ]

    if "vector_db" in components:
        checks.extend([
            "Test whether untrusted documents can be retrieved for sensitive queries.",
            "Verify source metadata is preserved from ingestion to retrieval.",
            "Confirm retrieval results are filtered by user authorization.",
        ])

    if "llm" in components:
        checks.extend([
            "Test prompt injection attempts against system and developer instructions.",
            "Verify sensitive context is not leaked in model output.",
            "Confirm output filtering is applied before returning responses.",
        ])

    if "tool" in components:
        checks.extend([
            "Verify tool calls require explicit authorization.",
            "Test whether the model can trigger high-risk actions without approval.",
            "Confirm tools use scoped credentials with least privilege.",
        ])

    if "ci_cd" in components:
        checks.extend([
            "Verify build artifacts are signed and traceable.",
            "Confirm secrets are not available to untrusted pull requests.",
            "Test dependency confusion and malicious package scenarios.",
        ])

    return checks


def analyze_architecture(text: str, title: str = "Security Architecture Review") -> Review:
    components = _detect_components(text)

    return Review(
        title=title,
        summary=text.strip()[:700],
        components=components,
        trust_boundaries=_build_trust_boundaries(components),
        attack_paths=_build_attack_paths(components),
        threats=_build_threats(components),
        controls=_build_controls(components),
        validation_checks=_build_validation_checks(components),
    )
