"""Flow-aware deterministic security analysis."""

from dataclasses import dataclass

from archsec_reviewer.domain import (
    Architecture,
    Component,
    ComponentType,
    Confidence,
    DataFlow,
    Evidence,
    EvidenceType,
    Finding,
    Severity,
    ThreatCategory,
)


class InvalidArchitectureError(ValueError):
    """Raised when analysis receives a structurally invalid architecture."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = tuple(errors)
        super().__init__("Invalid architecture: " + "; ".join(errors))


@dataclass(frozen=True)
class FlowRule:
    """A security rule applied to a directed component relationship."""

    id: str
    source_type: ComponentType
    destination_type: ComponentType
    title: str
    category: ThreatCategory
    severity: Severity
    scenario: str
    controls: tuple[str, ...]
    validation_steps: tuple[str, ...]

    def matches(
        self,
        source: Component,
        destination: Component,
    ) -> bool:
        return (
            source.type is self.source_type
            and destination.type is self.destination_type
        )


FLOW_RULES: tuple[FlowRule, ...] = (
    FlowRule(
        id="AI-PROMPT-001",
        source_type=ComponentType.USER,
        destination_type=ComponentType.LLM,
        title="Untrusted user input reaches the LLM directly",
        category=ThreatCategory.PROMPT_INJECTION,
        severity=Severity.HIGH,
        scenario=(
            "An untrusted user can send instructions directly to the LLM, "
            "allowing malicious input to influence model behavior."
        ),
        controls=(
            "Treat user prompts as untrusted data.",
            "Separate trusted instructions from user-controlled content.",
            "Apply input and output policy enforcement.",
        ),
        validation_steps=(
            "Test direct prompt-injection attempts.",
            "Verify user input cannot override trusted instructions.",
        ),
    ),
    FlowRule(
        id="AI-RAG-001",
        source_type=ComponentType.VECTOR_DATABASE,
        destination_type=ComponentType.LLM,
        title="Retrieved content influences LLM behavior",
        category=ThreatCategory.DATA_POISONING,
        severity=Severity.HIGH,
        scenario=(
            "Poisoned or unauthorized retrieved content can enter the LLM "
            "context and manipulate generated output."
        ),
        controls=(
            "Preserve document provenance.",
            "Enforce retrieval-time authorization.",
            "Separate retrieved content from trusted instructions.",
        ),
        validation_steps=(
            "Test indirect prompt injection through retrieved documents.",
            "Verify retrieval results are filtered by user authorization.",
        ),
    ),
    FlowRule(
        id="AI-TOOL-001",
        source_type=ComponentType.LLM,
        destination_type=ComponentType.TOOL,
        title="Model output reaches an executable tool",
        category=ThreatCategory.UNSAFE_ACTION,
        severity=Severity.HIGH,
        scenario=(
            "Manipulated model output can request a consequential tool "
            "operation without independent authorization."
        ),
        controls=(
            "Authorize every tool action outside the model.",
            "Use scoped tool credentials.",
            "Require approval for high-impact actions.",
        ),
        validation_steps=(
            "Attempt unauthorized tool use through prompt injection.",
            "Verify the model cannot provide the acting user identity.",
        ),
    ),
)


def analyze_flows(architecture: Architecture) -> list[Finding]:
    """Generate evidence-backed findings from directed data flows."""

    validation_errors = architecture.validate()

    if validation_errors:
        raise InvalidArchitectureError(validation_errors)

    findings: list[Finding] = []

    for flow in architecture.data_flows:
        source = architecture.get_component(flow.source)
        destination = architecture.get_component(flow.destination)

        if source is None or destination is None:
            continue

        for rule in FLOW_RULES:
            if rule.matches(source, destination):
                findings.append(
                    _build_rule_finding(
                        rule,
                        flow,
                        source,
                        destination,
                    )
                )

        if _crosses_trust_zone(source, destination):
            if flow.authenticated is False:
                findings.append(
                    _build_unauthenticated_flow_finding(
                        flow,
                        source,
                        destination,
                    )
                )

            if flow.encrypted is False:
                findings.append(
                    _build_unencrypted_flow_finding(
                        flow,
                        source,
                        destination,
                    )
                )

    return findings


def _build_rule_finding(
    rule: FlowRule,
    flow: DataFlow,
    source: Component,
    destination: Component,
) -> Finding:
    return Finding(
        id=f"{rule.id}:{flow.id}",
        title=rule.title,
        category=rule.category,
        scenario=rule.scenario,
        severity=rule.severity,
        confidence=Confidence.HIGH,
        affected_components=(source.id, destination.id),
        evidence=(
            Evidence(
                type=EvidenceType.DATA_FLOW,
                source_id=flow.id,
                description=(
                    f"Data flow '{flow.id}' connects "
                    f"{source.name} to {destination.name}."
                ),
            ),
        ),
        controls=rule.controls,
        validation_steps=rule.validation_steps,
    )


def _crosses_trust_zone(
    source: Component,
    destination: Component,
) -> bool:
    return (
        source.trust_zone is not None
        and destination.trust_zone is not None
        and source.trust_zone != destination.trust_zone
    )


def _build_unauthenticated_flow_finding(
    flow: DataFlow,
    source: Component,
    destination: Component,
) -> Finding:
    return Finding(
        id=f"TRUST-AUTH-001:{flow.id}",
        title="Unauthenticated flow crosses a trust boundary",
        category=ThreatCategory.SPOOFING,
        scenario=(
            f"{source.name} communicates with {destination.name} across "
            "trust zones without authentication, allowing an attacker to "
            "impersonate the source."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        affected_components=(source.id, destination.id),
        evidence=(
            Evidence(
                type=EvidenceType.DATA_FLOW,
                source_id=flow.id,
                description=(
                    f"Flow '{flow.id}' crosses from "
                    f"'{source.trust_zone}' to "
                    f"'{destination.trust_zone}' and explicitly declares "
                    "authentication as disabled."
                ),
            ),
        ),
        controls=(
            "Authenticate both ends of the communication.",
            "Use workload identity or mutually authenticated transport.",
        ),
        validation_steps=(
            "Attempt to call the destination without valid identity.",
            "Verify identity is bound to authorization decisions.",
        ),
    )


def _build_unencrypted_flow_finding(
    flow: DataFlow,
    source: Component,
    destination: Component,
) -> Finding:
    return Finding(
        id=f"TRUST-ENC-001:{flow.id}",
        title="Unencrypted flow crosses a trust boundary",
        category=ThreatCategory.INFORMATION_DISCLOSURE,
        scenario=(
            f"Data transferred from {source.name} to {destination.name} "
            "can be intercepted or modified while crossing trust zones."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        affected_components=(source.id, destination.id),
        evidence=(
            Evidence(
                type=EvidenceType.DATA_FLOW,
                source_id=flow.id,
                description=(
                    f"Flow '{flow.id}' crosses from "
                    f"'{source.trust_zone}' to "
                    f"'{destination.trust_zone}' and explicitly declares "
                    "encryption as disabled."
                ),
            ),
        ),
        controls=(
            "Encrypt data in transit.",
            "Validate the destination identity before sending data.",
        ),
        validation_steps=(
            "Verify the flow rejects unencrypted connections.",
            "Validate certificate and hostname verification.",
        ),
    )
