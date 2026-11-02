"""Tests for the Mermaid architecture-review renderer."""

from archsec_reviewer.domain import (
    Architecture,
    AttackPath,
    Component,
    ComponentType,
    DataFlow,
    PathPriority,
    SecurityReview,
    TrustLevel,
    TrustTransition,
    TrustZone,
)
from archsec_reviewer.reporters import render_mermaid_review


def test_renders_trust_zones_flows_and_attack_path() -> None:
    architecture = Architecture(
        name="Tool-Using Assistant",
        trust_zones=[
            TrustZone(
                id="internet",
                name="Internet",
                trust_level=TrustLevel.UNTRUSTED,
            ),
            TrustZone(
                id="application",
                name="Application Runtime",
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
                id="customer",
                name="Customer",
                type=ComponentType.USER,
                trust_zone="internet",
            ),
            Component(
                id="api",
                name="Assistant API",
                type=ComponentType.API,
                trust_zone="application",
            ),
            Component(
                id="refund-tool",
                name="Refund Tool",
                type=ComponentType.TOOL,
                trust_zone="privileged",
            ),
        ],
        data_flows=[
            DataFlow(
                id="customer-to-api",
                source="customer",
                destination="api",
                protocol="HTTPS",
                authenticated=False,
                encrypted=False,
            ),
            DataFlow(
                id="api-to-tool",
                source="api",
                destination="refund-tool",
                protocol="HTTPS",
                authenticated=True,
                encrypted=True,
            ),
        ],
    )

    attack_path = AttackPath(
        id="AP-001",
        entry_point="customer",
        target="refund-tool",
        nodes=("customer", "api", "refund-tool"),
        flow_ids=("customer-to-api", "api-to-tool"),
        trust_transitions=(
            TrustTransition(
                source="customer",
                destination="api",
                source_zone="internet",
                destination_zone="application",
                flow_ids=("customer-to-api",),
            ),
            TrustTransition(
                source="api",
                destination="refund-tool",
                source_zone="application",
                destination_zone="privileged",
                flow_ids=("api-to-tool",),
            ),
        ),
        priority=PathPriority.HIGH,
        priority_score=8,
    )

    review = SecurityReview(
        architecture=architecture,
        findings=(),
        attack_paths=(attack_path,),
    )

    diagram = render_mermaid_review(review)

    assert diagram.startswith("flowchart TD\n")
    assert 'subgraph zone_0["Internet — untrusted"]' in diagram
    assert 'component_0["Customer (user)"]' in diagram
    assert 'component_1["Assistant API (api)"]' in diagram
    assert 'component_2["Refund Tool (tool)"]' in diagram
    assert (
        'component_0 -->|"customer-to-api · HTTPS · '
        'unauthenticated · unencrypted"| component_1' in diagram
    )
    assert 'component_1 -->|"api-to-tool · HTTPS"| component_2' in diagram
    assert "class component_0 entry;" in diagram
    assert "class component_1 attack;" in diagram
    assert "class component_2 target;" in diagram
    assert "linkStyle 0 stroke:#dc2626,stroke-width:3px;" in diagram
    assert "linkStyle 1 stroke:#dc2626,stroke-width:3px;" in diagram
    assert diagram.endswith("\n")


def test_does_not_highlight_low_priority_path() -> None:
    architecture = Architecture(
        name="Low-Risk Architecture",
        components=[
            Component(
                id="user",
                name="User",
                type=ComponentType.USER,
            ),
            Component(
                id="service",
                name="Service",
                type=ComponentType.SERVICE,
            ),
        ],
        data_flows=[
            DataFlow(
                id="user-to-service",
                source="user",
                destination="service",
            )
        ],
    )

    attack_path = AttackPath(
        id="AP-LOW",
        entry_point="user",
        target="service",
        nodes=("user", "service"),
        flow_ids=("user-to-service",),
        trust_transitions=(),
        priority=PathPriority.LOW,
        priority_score=1,
    )

    review = SecurityReview(
        architecture=architecture,
        findings=(),
        attack_paths=(attack_path,),
    )

    diagram = render_mermaid_review(review)

    assert "class component_0 entry;" not in diagram
    assert "class component_1 target;" not in diagram
    assert "linkStyle 0" not in diagram


def test_escapes_mermaid_labels() -> None:
    architecture = Architecture(
        name="Escaping Test",
        components=[
            Component(
                id="gateway",
                name='R&D "Gateway" | Edge',
                type=ComponentType.EXTERNAL_SERVICE,
            )
        ],
    )
    review = SecurityReview(
        architecture=architecture,
        findings=(),
        attack_paths=(),
    )

    diagram = render_mermaid_review(review)

    assert (
        'component_0["R&amp;D &quot;Gateway&quot; '
        '&#124; Edge (external_service)"]' in diagram
    )
