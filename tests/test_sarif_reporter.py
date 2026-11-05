"""Tests for the SARIF 2.1.0 security-review renderer."""

import json
from dataclasses import replace

from archsec_reviewer.domain import (
    Architecture,
    Component,
    ComponentType,
    Confidence,
    Evidence,
    EvidenceType,
    Finding,
    SecurityReview,
    Severity,
    StandardReference,
    ThreatCategory,
)
from archsec_reviewer.reporters import render_sarif_review


def build_finding() -> Finding:
    return Finding(
        id="AI-TOOL-001:llm-to-tool",
        title="Model output reaches an executable tool",
        category=ThreatCategory.UNSAFE_ACTION,
        scenario=("Manipulated model output may request an unauthorized action."),
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        affected_components=("llm", "refund-tool"),
        evidence=(
            Evidence(
                type=EvidenceType.DATA_FLOW,
                source_id="llm-to-tool",
                description=("The LLM sends output directly to the refund tool."),
            ),
        ),
        assumptions=("The tool executes requests received from the model.",),
        controls=(
            "Authorize tool actions outside the model.",
            "Require approval for high-impact actions.",
        ),
        validation_steps=("Attempt an unauthorized refund through model output.",),
        references=(
            StandardReference(
                framework="OWASP",
                identifier="LLM06",
                url="https://owasp.org/",
            ),
        ),
    )


def build_architecture() -> Architecture:
    return Architecture(
        name="Tool-Using Assistant",
        components=[
            Component(
                id="llm",
                name="Support LLM",
                type=ComponentType.LLM,
            ),
            Component(
                id="refund-tool",
                name="Refund Tool",
                type=ComponentType.TOOL,
            ),
        ],
    )


def test_renders_github_compatible_sarif_result() -> None:
    review = SecurityReview(
        architecture=build_architecture(),
        findings=(build_finding(),),
        attack_paths=(),
    )

    rendered = render_sarif_review(
        review,
        artifact_uri="examples/architecture.yaml",
    )
    document = json.loads(rendered)

    assert document["version"] == "2.1.0"
    assert document["$schema"].endswith("sarif-2.1.0.json")

    run = document["runs"][0]
    driver = run["tool"]["driver"]

    assert driver["name"] == "ArchSec Reviewer"
    assert driver["semanticVersion"] == "0.1.0"
    assert run["automationDetails"]["id"] == ("Tool-Using Assistant")

    rule = driver["rules"][0]

    assert rule["id"] == "AI-TOOL-001"
    assert rule["name"] == "AI_TOOL_001"
    assert rule["defaultConfiguration"]["level"] == "error"
    assert rule["helpUri"] == "https://owasp.org/"
    assert "security" in rule["properties"]["tags"]
    assert "unsafe_action" in rule["properties"]["tags"]
    assert "OWASP:LLM06" in rule["properties"]["tags"]

    result = run["results"][0]

    assert result["ruleId"] == "AI-TOOL-001"
    assert result["ruleIndex"] == 0
    assert result["level"] == "error"
    assert result["message"]["text"].startswith(
        "Model output reaches an executable tool."
    )

    location = result["locations"][0]

    assert (
        location["physicalLocation"]["artifactLocation"]["uri"]
        == "examples/architecture.yaml"
    )
    assert location["physicalLocation"]["region"]["startLine"] == 1
    assert location["logicalLocations"] == [
        {
            "name": "llm",
            "kind": "component",
        },
        {
            "name": "refund-tool",
            "kind": "component",
        },
    ]

    properties = result["properties"]

    assert properties["findingId"] == ("AI-TOOL-001:llm-to-tool")
    assert properties["confidence"] == "high"
    assert properties["threatCategory"] == "unsafe_action"
    assert properties["standardReferences"] == ["OWASP:LLM06"]
    assert rendered.endswith("\n")


def test_deduplicates_rules_for_multiple_findings() -> None:
    first = build_finding()
    second = replace(
        first,
        id="AI-TOOL-001:agent-to-tool",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
    )
    review = SecurityReview(
        architecture=build_architecture(),
        findings=(first, second),
        attack_paths=(),
    )

    document = json.loads(render_sarif_review(review))
    run = document["runs"][0]

    assert len(run["tool"]["driver"]["rules"]) == 1
    assert len(run["results"]) == 2
    assert run["results"][0]["ruleIndex"] == 0
    assert run["results"][1]["ruleIndex"] == 0
    assert run["results"][0]["level"] == "error"
    assert run["results"][1]["level"] == "warning"


def test_renders_empty_sarif_log() -> None:
    review = SecurityReview(
        architecture=Architecture(name="Empty Architecture"),
        findings=(),
        attack_paths=(),
    )

    rendered = render_sarif_review(review)
    document = json.loads(rendered)
    run = document["runs"][0]

    assert run["tool"]["driver"]["rules"] == []
    assert run["results"] == []
    assert rendered.endswith("\n")
