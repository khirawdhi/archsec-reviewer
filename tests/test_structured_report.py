from archsec_reviewer.application import review_architecture
from archsec_reviewer.domain import (
    Architecture,
    Asset,
    Component,
    ComponentType,
    DataClassification,
    DataFlow,
    SecurityReview,
    TrustLevel,
    TrustZone,
)
from archsec_reviewer.reporters import render_structured_review


def build_review() -> SecurityReview:
    architecture = Architecture(
        name="Refund Assistant",
        trust_zones=[
            TrustZone(
                id="internet",
                name="Internet",
                trust_level=TrustLevel.UNTRUSTED,
            ),
            TrustZone(
                id="ai",
                name="AI Runtime",
                trust_level=TrustLevel.INTERNAL,
            ),
            TrustZone(
                id="privileged",
                name="Privileged Operations",
                trust_level=TrustLevel.PRIVILEGED,
            ),
        ],
        components=[
            Component(
                id="user",
                name="Customer",
                type=ComponentType.USER,
                trust_zone="internet",
            ),
            Component(
                id="llm",
                name="LLM",
                type=ComponentType.LLM,
                trust_zone="ai",
            ),
            Component(
                id="refund_tool",
                name="Refund Tool",
                type=ComponentType.TOOL,
                trust_zone="privileged",
            ),
        ],
        assets=[
            Asset(
                id="refund",
                name="Refund Capability",
                classification=DataClassification.RESTRICTED,
                owner_component="refund_tool",
            ),
        ],
        data_flows=[
            DataFlow(
                id="user_to_llm",
                source="user",
                destination="llm",
                protocol="HTTPS",
                authenticated=True,
                encrypted=True,
            ),
            DataFlow(
                id="llm_to_refund",
                source="llm",
                destination="refund_tool",
                protocol="HTTPS",
                authenticated=True,
                encrypted=True,
            ),
        ],
        assumptions=[
            "Tool calls are logged.",
        ],
        security_objectives=[
            "Prevent unauthorized refunds.",
        ],
    )

    return review_architecture(architecture)


def test_renders_complete_structured_report() -> None:
    report = render_structured_review(build_review())

    assert report.startswith("# Security Architecture Review: Refund Assistant")
    assert "## Executive Summary" in report
    assert "**2 security findings**" in report
    assert "**1 attack path**" in report
    assert "## Security Objectives" in report
    assert "Prevent unauthorized refunds." in report
    assert "## Declared Assumptions" in report
    assert "Tool calls are logged." in report
    assert "## Architecture Overview" in report
    assert "## Security Findings" in report
    assert "AI-TOOL-001:llm_to_refund" in report
    assert "## Attack Paths" in report
    assert "user → llm → refund_tool" in report
    assert "## Review Limitations" in report


def test_renders_finding_evidence_and_controls() -> None:
    report = render_structured_review(build_review())

    assert "#### Evidence" in report
    assert "Data flow 'llm_to_refund'" in report
    assert "#### Recommended Controls" in report
    assert "Authorize every tool action outside the model." in report
    assert "#### Validation Steps" in report
    assert "- [ ] Attempt unauthorized tool use through prompt injection." in report


def test_renders_attack_path_details() -> None:
    report = render_structured_review(build_review())

    assert "- **Entry point:** user" in report
    assert "- **Target:** refund_tool" in report
    assert "- **Hop count:** 2" in report
    assert "- **Flow evidence:** user_to_llm, llm_to_refund" in report
    assert "user (internet) → llm (ai)" in report
    assert "llm (ai) → refund_tool (privileged)" in report


def test_escapes_table_separator() -> None:
    architecture = Architecture(
        name="Escaping Test",
        components=[
            Component(
                id="api",
                name="API | Gateway",
                type=ComponentType.API,
            ),
        ],
    )

    report = render_structured_review(review_architecture(architecture))

    assert "API \\| Gateway" in report


def test_renders_empty_review_sections() -> None:
    architecture = Architecture(
        name="Empty Architecture",
    )

    report = render_structured_review(review_architecture(architecture))

    assert "**0 security findings**" in report
    assert "**0 attack paths**" in report
    assert "No security objectives declared." in report
    assert "No assumptions declared." in report
    assert "No trust zones declared." in report
    assert "No components declared." in report
    assert "No assets declared." in report
    assert "No data flows declared." in report
    assert "No deterministic findings were generated" in report
    assert "No attack paths were discovered" in report
