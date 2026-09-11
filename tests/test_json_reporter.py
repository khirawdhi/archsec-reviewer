"""Tests for the structured JSON security-review reporter."""

import json

from archsec_reviewer.domain import (
    Architecture,
    Asset,
    AttackPath,
    Component,
    ComponentType,
    Confidence,
    DataClassification,
    DataFlow,
    Evidence,
    EvidenceType,
    Finding,
    PathPriority,
    SecurityReview,
    Severity,
    StandardReference,
    ThreatCategory,
    TrustLevel,
    TrustTransition,
    TrustZone,
)
from archsec_reviewer.reporters import render_json_review


def build_review() -> SecurityReview:
    architecture = Architecture(
        name="Tool-Using Assistant",
        trust_zones=[
            TrustZone(
                id="internet",
                name="Internet",
                trust_level=TrustLevel.UNTRUSTED,
            ),
            TrustZone(
                id="privileged",
                name="Privileged Runtime",
                trust_level=TrustLevel.PRIVILEGED,
                owner="Platform Security",
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
                id="refund-tool",
                name="Refund Tool",
                type=ComponentType.TOOL,
                trust_zone="privileged",
                privileges=("issue_refund",),
                data_handled=("payment-data",),
            ),
        ],
        assets=[
            Asset(
                id="payment-data",
                name="Payment Data",
                classification=DataClassification.RESTRICTED,
                owner_component="refund-tool",
            )
        ],
        data_flows=[
            DataFlow(
                id="customer-to-tool",
                source="customer",
                destination="refund-tool",
                data=("refund-request",),
                protocol="HTTPS",
                authenticated=True,
                encrypted=True,
            )
        ],
        assumptions=["Identity provider remains available."],
        security_objectives=["Prevent unauthorized refunds."],
    )

    finding = Finding(
        id="F-001",
        title="Untrusted input reaches a privileged tool",
        category=ThreatCategory.UNSAFE_ACTION,
        scenario="Customer input may influence refund execution.",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        affected_components=("customer", "refund-tool"),
        evidence=(
            Evidence(
                type=EvidenceType.DATA_FLOW,
                source_id="customer-to-tool",
                description="A direct flow reaches the refund tool.",
            ),
        ),
        controls=("Require explicit authorization.",),
        validation_steps=("Attempt an unauthorized refund.",),
        references=(
            StandardReference(
                framework="OWASP",
                identifier="LLM06",
                url="https://owasp.org/",
            ),
        ),
    )

    attack_path = AttackPath(
        id="AP-001",
        entry_point="customer",
        target="refund-tool",
        nodes=("customer", "refund-tool"),
        flow_ids=("customer-to-tool",),
        trust_transitions=(
            TrustTransition(
                source="customer",
                destination="refund-tool",
                source_zone="internet",
                destination_zone="privileged",
                flow_ids=("customer-to-tool",),
            ),
        ),
        priority=PathPriority.HIGH,
        priority_score=8,
        priority_factors=(
            "+3 Target is an executable tool.",
            "+2 Path crosses a trust boundary.",
        ),
    )

    return SecurityReview(
        architecture=architecture,
        findings=(finding,),
        attack_paths=(attack_path,),
    )


def test_renders_complete_review_as_json() -> None:
    rendered = render_json_review(build_review())
    document = json.loads(rendered)

    assert document["schema_version"] == "1.0"
    assert document["summary"] == {
        "finding_count": 1,
        "attack_path_count": 1,
    }

    architecture = document["architecture"]
    assert architecture["name"] == "Tool-Using Assistant"
    assert architecture["trust_zones"][1]["trust_level"] == "privileged"
    assert architecture["components"][1]["type"] == "tool"
    assert architecture["assets"][0]["classification"] == "restricted"
    assert architecture["data_flows"][0]["authenticated"] is True

    finding = document["findings"][0]
    assert finding["severity"] == "high"
    assert finding["category"] == "unsafe_action"
    assert finding["evidence"][0]["source_id"] == "customer-to-tool"
    assert finding["references"][0]["identifier"] == "LLM06"

    attack_path = document["attack_paths"][0]
    assert attack_path["nodes"] == ["customer", "refund-tool"]
    assert attack_path["hop_count"] == 1
    assert attack_path["priority"] == "high"
    assert attack_path["priority_score"] == 8
    assert attack_path["trust_transitions"][0]["destination_zone"] == "privileged"


def test_renders_empty_review_and_trailing_newline() -> None:
    review = SecurityReview(
        architecture=Architecture(name="Empty Architecture"),
        findings=(),
        attack_paths=(),
    )

    rendered = render_json_review(review)
    document = json.loads(rendered)

    assert rendered.endswith("\n")
    assert document["summary"] == {
        "finding_count": 0,
        "attack_path_count": 0,
    }
    assert document["findings"] == []
    assert document["attack_paths"] == []
