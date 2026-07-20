from archsec_reviewer.domain import (
    Architecture,
    Component,
    ComponentType,
    Confidence,
    Evidence,
    EvidenceType,
    Finding,
    Severity,
    StandardReference,
    ThreatCategory,
)


def build_architecture() -> Architecture:
    return Architecture(
        name="Agentic Support System",
        components=[
            Component(
                id="llm",
                name="LLM",
                type=ComponentType.LLM,
            ),
            Component(
                id="refund_tool",
                name="Refund Tool",
                type=ComponentType.TOOL,
            ),
        ],
    )


def build_finding() -> Finding:
    return Finding(
        id="AI-TOOL-001",
        title="Model output may trigger an unauthorized refund",
        category=ThreatCategory.UNSAFE_ACTION,
        scenario=(
            "Prompt injection manipulates the model into requesting "
            "an unauthorized refund."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        affected_components=("llm", "refund_tool"),
        evidence=(
            Evidence(
                type=EvidenceType.DATA_FLOW,
                source_id="llm_to_refund",
                description=("The LLM sends requested actions to the refund tool."),
            ),
        ),
        assumptions=("No independent transaction authorization was described.",),
        controls=(
            "Authorize refund operations outside the model.",
            "Use scoped credentials and transaction limits.",
        ),
        validation_steps=("Attempt an unauthorized refund through prompt injection.",),
        references=(
            StandardReference(
                framework="OWASP Top 10 for LLM Applications",
                identifier="LLM06",
            ),
        ),
    )


def test_valid_finding_has_no_errors() -> None:
    finding = build_finding()

    assert finding.validate(build_architecture()) == []


def test_finding_preserves_risk_information() -> None:
    finding = build_finding()

    assert finding.severity is Severity.HIGH
    assert finding.confidence is Confidence.HIGH
    assert finding.category is ThreatCategory.UNSAFE_ACTION


def test_detects_unknown_affected_component() -> None:
    finding = Finding(
        id="AI-001",
        title="Unknown component",
        category=ThreatCategory.AUTHORIZATION,
        scenario="A missing component is referenced.",
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        affected_components=("missing",),
        evidence=(
            Evidence(
                type=EvidenceType.INFERRED,
                source_id="analysis",
                description="The component was inferred.",
            ),
        ),
    )

    assert (
        "Finding 'AI-001' references unknown component 'missing'."
        in finding.validate(build_architecture())
    )


def test_requires_supporting_evidence() -> None:
    finding = Finding(
        id="AI-002",
        title="Unsupported finding",
        category=ThreatCategory.PROMPT_INJECTION,
        scenario="A scenario without supporting evidence.",
        severity=Severity.HIGH,
        confidence=Confidence.LOW,
        affected_components=("llm",),
        evidence=(),
    )

    assert "Finding 'AI-002' must include supporting evidence." in finding.validate(
        build_architecture()
    )


def test_requires_affected_component() -> None:
    finding = Finding(
        id="AI-003",
        title="Unscoped finding",
        category=ThreatCategory.TAMPERING,
        scenario="A finding that is not attached to a component.",
        severity=Severity.LOW,
        confidence=Confidence.LOW,
        affected_components=(),
        evidence=(
            Evidence(
                type=EvidenceType.INFERRED,
                source_id="analysis",
                description="Potential tampering was inferred.",
            ),
        ),
    )

    assert (
        "Finding 'AI-003' must reference at least one component."
        in finding.validate(build_architecture())
    )


def test_requires_evidence_description() -> None:
    finding = Finding(
        id="AI-004",
        title="Empty evidence",
        category=ThreatCategory.TAMPERING,
        scenario="A finding contains incomplete evidence.",
        severity=Severity.LOW,
        confidence=Confidence.LOW,
        affected_components=("llm",),
        evidence=(
            Evidence(
                type=EvidenceType.INFERRED,
                source_id="analysis",
                description=" ",
            ),
        ),
    )

    assert (
        "Finding 'AI-004' contains evidence without a description."
        in finding.validate(build_architecture())
    )
