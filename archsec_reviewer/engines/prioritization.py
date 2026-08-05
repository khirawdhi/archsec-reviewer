"""Transparent attack-path review prioritization."""

from collections.abc import Sequence
from dataclasses import replace
from typing import Optional

from archsec_reviewer.domain import (
    Architecture,
    AttackPath,
    ComponentType,
    DataClassification,
    EvidenceType,
    Finding,
    PathPriority,
    Severity,
    TrustLevel,
)


SEVERITY_SCORES = {
    Severity.INFORMATIONAL: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 4,
    Severity.CRITICAL: 5,
}

CLASSIFICATION_SCORES = {
    DataClassification.PUBLIC: 0,
    DataClassification.INTERNAL: 1,
    DataClassification.CONFIDENTIAL: 3,
    DataClassification.RESTRICTED: 4,
}


def prioritize_attack_paths(
    architecture: Architecture,
    findings: Sequence[Finding],
    attack_paths: Sequence[AttackPath],
) -> list[AttackPath]:
    """Score and rank paths using explainable architecture factors."""

    prioritized = [
        _prioritize_path(
            architecture,
            findings,
            path,
        )
        for path in attack_paths
    ]

    return sorted(
        prioritized,
        key=lambda path: (
            -path.priority_score,
            path.id,
        ),
    )


def _prioritize_path(
    architecture: Architecture,
    findings: Sequence[Finding],
    path: AttackPath,
) -> AttackPath:
    score = 0
    factors: list[str] = []

    asset_score, asset_factor = _target_asset_factor(
        architecture,
        path.target,
    )
    score += asset_score

    if asset_factor is not None:
        factors.append(asset_factor)

    target = architecture.get_component(path.target)

    if target is not None:
        if target.type is ComponentType.TOOL:
            score += 3
            factors.append(
                "+3 Target is an executable tool."
            )

        zone_levels = {
            zone.id: zone.trust_level
            for zone in architecture.trust_zones
        }

        if (
            target.trust_zone is not None
            and zone_levels.get(target.trust_zone)
            is TrustLevel.PRIVILEGED
        ):
            score += 3
            factors.append(
                "+3 Target is in a privileged trust zone."
            )

    transition_score = min(
        len(path.trust_transitions),
        3,
    )
    score += transition_score

    if transition_score:
        factors.append(
            f"+{transition_score} Path crosses "
            f"{len(path.trust_transitions)} trust "
            f"{_pluralize(len(path.trust_transitions), 'boundary', 'boundaries')}."
        )

    finding_score, finding_factor = _finding_factor(
        findings,
        path,
    )
    score += finding_score

    if finding_factor is not None:
        factors.append(finding_factor)

    return replace(
        path,
        priority=_priority_for_score(score),
        priority_score=score,
        priority_factors=tuple(factors),
    )


def _target_asset_factor(
    architecture: Architecture,
    target_id: str,
) -> tuple[int, Optional[str]]:
    classifications = [
        asset.classification
        for asset in architecture.assets
        if asset.owner_component == target_id
    ]

    if not classifications:
        return 0, None

    classification = max(
        classifications,
        key=lambda value: CLASSIFICATION_SCORES[value],
    )
    score = CLASSIFICATION_SCORES[classification]

    if score == 0:
        return 0, None

    return (
        score,
        (
            f"+{score} Target owns a "
            f"{classification.value} asset."
        ),
    )


def _finding_factor(
    findings: Sequence[Finding],
    path: AttackPath,
) -> tuple[int, Optional[str]]:
    path_flow_ids = set(path.flow_ids)

    related_findings = [
        finding
        for finding in findings
        if any(
            evidence.type is EvidenceType.DATA_FLOW
            and evidence.source_id in path_flow_ids
            for evidence in finding.evidence
        )
    ]

    if not related_findings:
        return 0, None

    highest_severity = max(
        (
            finding.severity
            for finding in related_findings
        ),
        key=lambda severity: SEVERITY_SCORES[severity],
    )
    score = SEVERITY_SCORES[highest_severity]

    if score == 0:
        return 0, None

    return (
        score,
        (
            f"+{score} Path contains "
            f"{highest_severity.value}-severity "
            "flow findings."
        ),
    )


def _priority_for_score(score: int) -> PathPriority:
    if score >= 13:
        return PathPriority.CRITICAL

    if score >= 9:
        return PathPriority.HIGH

    if score >= 5:
        return PathPriority.MEDIUM

    return PathPriority.LOW


def _pluralize(
    count: int,
    singular: str,
    plural: str,
) -> str:
    return singular if count == 1 else plural