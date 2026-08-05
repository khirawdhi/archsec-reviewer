from archsec_reviewer.domain import (
    Architecture,
    Asset,
    AttackPath,
    Component,
    ComponentType,
    DataClassification,
    DataFlow,
    PathPriority,
    TrustLevel,
    TrustZone,
)
from archsec_reviewer.engines import (
    analyze_flows,
    find_attack_paths,
    prioritize_attack_paths,
)


def build_high_priority_architecture() -> Architecture:
    return Architecture(
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
                id="refund_capability",
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


def test_prioritizes_restricted_privileged_tool_path() -> None:
    architecture = build_high_priority_architecture()
    findings = analyze_flows(architecture)
    paths = find_attack_paths(
        architecture,
        entry_points=["user"],
        targets=["refund_tool"],
    )

    prioritized = prioritize_attack_paths(
        architecture,
        findings,
        paths,
    )

    assert len(prioritized) == 1

    path = prioritized[0]

    assert path.priority is PathPriority.CRITICAL
    assert path.priority_score == 16
    assert "+4 Target owns a restricted asset." in path.priority_factors
    assert "+3 Target is an executable tool." in path.priority_factors
    assert "+3 Target is in a privileged trust zone." in path.priority_factors
    assert "+2 Path crosses 2 trust boundaries." in path.priority_factors
    assert "+4 Path contains high-severity flow findings." in path.priority_factors


def test_does_not_sum_multiple_flow_findings() -> None:
    architecture = build_high_priority_architecture()
    findings = analyze_flows(architecture)
    paths = find_attack_paths(
        architecture,
        entry_points=["user"],
        targets=["refund_tool"],
    )

    assert len(findings) == 2

    prioritized = prioritize_attack_paths(
        architecture,
        findings,
        paths,
    )

    assert prioritized[0].priority_score == 16


def test_assigns_low_priority_without_risk_factors() -> None:
    architecture = Architecture(
        name="Internal Services",
        components=[
            Component(
                id="service_a",
                name="Service A",
                type=ComponentType.SERVICE,
            ),
            Component(
                id="service_b",
                name="Service B",
                type=ComponentType.SERVICE,
            ),
        ],
    )

    path = AttackPath(
        id="AP-001",
        entry_point="service_a",
        target="service_b",
        nodes=("service_a", "service_b"),
        flow_ids=("service_a_to_b",),
        trust_transitions=(),
    )

    prioritized = prioritize_attack_paths(
        architecture,
        findings=[],
        attack_paths=[path],
    )

    assert prioritized[0].priority is PathPriority.LOW
    assert prioritized[0].priority_score == 0
    assert prioritized[0].priority_factors == ()


def test_sorts_paths_by_descending_priority() -> None:
    architecture = build_high_priority_architecture()
    findings = analyze_flows(architecture)

    high_path = find_attack_paths(
        architecture,
        entry_points=["user"],
        targets=["refund_tool"],
    )[0]

    low_path = AttackPath(
        id="AP-999",
        entry_point="user",
        target="llm",
        nodes=("user", "llm"),
        flow_ids=(),
        trust_transitions=(),
    )

    prioritized = prioritize_attack_paths(
        architecture,
        findings,
        [low_path, high_path],
    )

    assert prioritized[0].target == "refund_tool"
    assert prioritized[0].priority is PathPriority.CRITICAL
    assert prioritized[-1].target == "llm"
