"""SARIF 2.1.0 renderer for architecture security findings."""

import json

from archsec_reviewer import __version__
from archsec_reviewer.domain import (
    Finding,
    SecurityReview,
    Severity,
)


SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_NAME = "ArchSec Reviewer"
TOOL_INFORMATION_URI = "https://github.com/khirawdhi/archsec-reviewer"

SEVERITY_LEVELS = {
    Severity.INFORMATIONAL: "note",
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}


def render_sarif_review(
    review: SecurityReview,
    artifact_uri: str = "architecture.yaml",
) -> str:
    """Render security findings as a SARIF 2.1.0 log."""
    rule_findings = _unique_rule_findings(review.findings)
    rules = [_serialize_rule(finding) for finding in rule_findings]
    rule_indices = {
        _rule_id(finding): index for index, finding in enumerate(rule_findings)
    }

    results = [
        _serialize_result(
            finding=finding,
            rule_index=rule_indices[_rule_id(finding)],
            artifact_uri=artifact_uri,
        )
        for finding in review.findings
    ]

    document = {
        "version": SARIF_VERSION,
        "$schema": SARIF_SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "semanticVersion": __version__,
                        "informationUri": TOOL_INFORMATION_URI,
                        "rules": rules,
                    }
                },
                "automationDetails": {
                    "id": review.architecture.name,
                },
                "results": results,
            }
        ],
    }

    return (
        json.dumps(
            document,
            indent=2,
            ensure_ascii=False,
        )
        + "\n"
    )


def _unique_rule_findings(
    findings: tuple[Finding, ...],
) -> list[Finding]:
    unique_findings: list[Finding] = []
    seen_rule_ids: set[str] = set()

    for finding in findings:
        rule_id = _rule_id(finding)

        if rule_id not in seen_rule_ids:
            unique_findings.append(finding)
            seen_rule_ids.add(rule_id)

    return unique_findings


def _serialize_rule(
    finding: Finding,
) -> dict[str, object]:
    rule_id = _rule_id(finding)
    references = [
        f"{reference.framework}:{reference.identifier}"
        for reference in finding.references
    ]
    tags = _unique_strings(
        [
            "security",
            "architecture",
            finding.category.value,
            *references,
        ]
    )

    rule: dict[str, object] = {
        "id": rule_id,
        "name": _rule_name(rule_id),
        "shortDescription": {
            "text": finding.title,
        },
        "fullDescription": {
            "text": (
                f"Detects {finding.category.value.replace('_', ' ')} "
                "risk supported by declared architecture evidence."
            ),
        },
        "defaultConfiguration": {
            "level": SEVERITY_LEVELS[finding.severity],
        },
        "help": {
            "text": _rule_help(finding),
        },
        "properties": {
            "tags": tags,
        },
    }

    help_uri = next(
        (
            reference.url
            for reference in finding.references
            if reference.url is not None
        ),
        None,
    )

    if help_uri is not None:
        rule["helpUri"] = help_uri

    return rule


def _serialize_result(
    finding: Finding,
    rule_index: int,
    artifact_uri: str,
) -> dict[str, object]:
    return {
        "ruleId": _rule_id(finding),
        "ruleIndex": rule_index,
        "level": SEVERITY_LEVELS[finding.severity],
        "message": {
            "text": _result_message(finding),
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": artifact_uri,
                    },
                    "region": {
                        "startLine": 1,
                    },
                },
                "logicalLocations": [
                    {
                        "name": component_id,
                        "kind": "component",
                    }
                    for component_id in finding.affected_components
                ],
            }
        ],
        "properties": {
            "findingId": finding.id,
            "confidence": finding.confidence.value,
            "threatCategory": finding.category.value,
            "affectedComponents": list(finding.affected_components),
            "evidence": [evidence.description for evidence in finding.evidence],
            "assumptions": list(finding.assumptions),
            "controls": list(finding.controls),
            "validationSteps": list(finding.validation_steps),
            "standardReferences": [
                (f"{reference.framework}:{reference.identifier}")
                for reference in finding.references
            ],
        },
    }


def _rule_id(finding: Finding) -> str:
    """Return the stable rule portion of an instance finding ID."""
    return finding.id.partition(":")[0]


def _rule_name(rule_id: str) -> str:
    """Return a SARIF-compatible readable rule name."""
    return "".join(character if character.isalnum() else "_" for character in rule_id)


def _result_message(finding: Finding) -> str:
    title = finding.title.rstrip(".")
    scenario = finding.scenario.strip()

    return f"{title}. {scenario}"


def _rule_help(finding: Finding) -> str:
    sections = [
        f"Threat category: {finding.category.value.replace('_', ' ')}.",
    ]

    if finding.controls:
        sections.append("Recommended controls: " + "; ".join(finding.controls))

    if finding.validation_steps:
        sections.append("Validation: " + "; ".join(finding.validation_steps))

    return "\n\n".join(sections)


def _unique_strings(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))
