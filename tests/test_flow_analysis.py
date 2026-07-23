import pytest

from archsec_reviewer.domain import (
    Architecture,
    Component,
    ComponentType,
    DataFlow,
    TrustLevel,
    TrustZone,
)
from archsec_reviewer.engines import (
    InvalidArchitectureError,
    analyze_flows,
)


def build_architecture(
    flows: list[DataFlow],
) -> Architecture:
    return Architecture(
        name="Customer Support Agent",
        trust_zones=[
            TrustZone(
                id="internet",
                name="Internet",
                trust_level=TrustLevel.UNTRUSTED,
            ),
            TrustZone(
                id="application",
                name="Application",
                trust_level=TrustLevel.INTERNAL,
            ),
            TrustZone(
                id="data",
                name="Data",
                trust_level=TrustLevel.INTERNAL,
            ),
            TrustZone(
                id="privileged",
                name="Privileged",
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
                id="vector_db",
                name="Vector Database",
                type=ComponentType.VECTOR_DATABASE,
                trust_zone="data",
            ),
            Component(
                id="llm",
                name="Support LLM",
                type=ComponentType.LLM,
                trust_zone="application",
            ),
            Component(
                id="refund_tool",
                name="Refund Tool",
                type=ComponentType.TOOL,
                trust_zone="privileged",
            ),
        ],
        data_flows=flows,
    )


def finding_ids(architecture: Architecture) -> set[str]:
    return {finding.id for finding in analyze_flows(architecture)}


def test_detects_direct_prompt_injection_flow() -> None:
    architecture = build_architecture(
        [
            DataFlow(
                id="user_to_llm",
                source="user",
                destination="llm",
                authenticated=True,
                encrypted=True,
            ),
        ]
    )

    assert "AI-PROMPT-001:user_to_llm" in finding_ids(architecture)


def test_detects_retrieval_context_flow() -> None:
    architecture = build_architecture(
        [
            DataFlow(
                id="vector_to_llm",
                source="vector_db",
                destination="llm",
                authenticated=True,
                encrypted=True,
            ),
        ]
    )

    assert "AI-RAG-001:vector_to_llm" in finding_ids(architecture)


def test_detects_llm_to_tool_flow() -> None:
    architecture = build_architecture(
        [
            DataFlow(
                id="llm_to_refund",
                source="llm",
                destination="refund_tool",
                authenticated=True,
                encrypted=True,
            ),
        ]
    )

    findings = analyze_flows(architecture)

    assert "AI-TOOL-001:llm_to_refund" in {finding.id for finding in findings}

    assert all(finding.validate(architecture) == [] for finding in findings)


def test_rule_requires_correct_flow_direction() -> None:
    architecture = build_architecture(
        [
            DataFlow(
                id="refund_to_llm",
                source="refund_tool",
                destination="llm",
                authenticated=True,
                encrypted=True,
            ),
        ]
    )

    assert not any(
        finding_id.startswith("AI-TOOL-001") for finding_id in finding_ids(architecture)
    )


def test_detects_unauthenticated_cross_zone_flow() -> None:
    architecture = build_architecture(
        [
            DataFlow(
                id="user_to_llm",
                source="user",
                destination="llm",
                authenticated=False,
                encrypted=True,
            ),
        ]
    )

    assert "TRUST-AUTH-001:user_to_llm" in finding_ids(architecture)


def test_detects_unencrypted_cross_zone_flow() -> None:
    architecture = build_architecture(
        [
            DataFlow(
                id="llm_to_refund",
                source="llm",
                destination="refund_tool",
                authenticated=True,
                encrypted=False,
            ),
        ]
    )

    assert "TRUST-ENC-001:llm_to_refund" in finding_ids(architecture)


def test_does_not_report_boundary_issue_inside_same_zone() -> None:
    architecture = build_architecture(
        [
            DataFlow(
                id="llm_to_llm",
                source="llm",
                destination="llm",
                authenticated=False,
                encrypted=False,
            ),
        ]
    )

    assert finding_ids(architecture) == set()


def test_rejects_invalid_architecture() -> None:
    architecture = build_architecture(
        [
            DataFlow(
                id="broken_flow",
                source="user",
                destination="missing_component",
            ),
        ]
    )

    with pytest.raises(InvalidArchitectureError) as error:
        analyze_flows(architecture)

    assert "missing_component" in str(error.value)
