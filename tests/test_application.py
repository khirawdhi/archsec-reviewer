from archsec_reviewer.application import review_architecture
from archsec_reviewer.domain import (
    Architecture,
    Component,
    ComponentType,
    DataFlow,
    TrustLevel,
    TrustZone,
)


def build_architecture() -> Architecture:
    return Architecture(
        name="Tool-Using Assistant",
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
        data_flows=[
            DataFlow(
                id="user_to_llm",
                source="user",
                destination="llm",
                authenticated=True,
                encrypted=True,
            ),
            DataFlow(
                id="llm_to_refund",
                source="llm",
                destination="refund_tool",
                authenticated=True,
                encrypted=True,
            ),
        ],
    )


def test_runs_complete_security_review() -> None:
    review = review_architecture(build_architecture())

    assert review.architecture.name == "Tool-Using Assistant"
    assert review.finding_count == 2
    assert review.attack_path_count == 1

    assert {finding.id for finding in review.findings} == {
        "AI-PROMPT-001:user_to_llm",
        "AI-TOOL-001:llm_to_refund",
    }

    assert review.attack_paths[0].nodes == (
        "user",
        "llm",
        "refund_tool",
    )


def test_respects_attack_path_cutoff() -> None:
    review = review_architecture(
        build_architecture(),
        attack_path_cutoff=1,
    )

    assert review.finding_count == 2
    assert review.attack_path_count == 0
