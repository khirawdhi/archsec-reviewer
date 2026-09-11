"""Machine-readable JSON renderer for structured security reviews."""

import json

from archsec_reviewer.domain import (
    Architecture,
    AttackPath,
    Finding,
    SecurityReview,
)


SCHEMA_VERSION = "1.0"


def render_json_review(review: SecurityReview) -> str:
    """Render a structured security review as deterministic JSON."""
    document = {
        "schema_version": SCHEMA_VERSION,
        "summary": {
            "finding_count": review.finding_count,
            "attack_path_count": review.attack_path_count,
        },
        "architecture": _serialize_architecture(review.architecture),
        "findings": [_serialize_finding(finding) for finding in review.findings],
        "attack_paths": [_serialize_attack_path(path) for path in review.attack_paths],
    }

    return (
        json.dumps(
            document,
            indent=2,
            ensure_ascii=False,
            sort_keys=True,
        )
        + "\n"
    )


def _serialize_architecture(
    architecture: Architecture,
) -> dict[str, object]:
    return {
        "name": architecture.name,
        "trust_zones": [
            {
                "id": zone.id,
                "name": zone.name,
                "trust_level": zone.trust_level.value,
                "owner": zone.owner,
            }
            for zone in architecture.trust_zones
        ],
        "components": [
            {
                "id": component.id,
                "name": component.name,
                "type": component.type.value,
                "trust_zone": component.trust_zone,
                "privileges": list(component.privileges),
                "data_handled": list(component.data_handled),
            }
            for component in architecture.components
        ],
        "assets": [
            {
                "id": asset.id,
                "name": asset.name,
                "classification": asset.classification.value,
                "owner_component": asset.owner_component,
            }
            for asset in architecture.assets
        ],
        "data_flows": [
            {
                "id": flow.id,
                "source": flow.source,
                "destination": flow.destination,
                "data": list(flow.data),
                "protocol": flow.protocol,
                "authenticated": flow.authenticated,
                "encrypted": flow.encrypted,
            }
            for flow in architecture.data_flows
        ],
        "assumptions": list(architecture.assumptions),
        "security_objectives": list(architecture.security_objectives),
    }


def _serialize_finding(finding: Finding) -> dict[str, object]:
    return {
        "id": finding.id,
        "title": finding.title,
        "category": finding.category.value,
        "scenario": finding.scenario,
        "severity": finding.severity.value,
        "confidence": finding.confidence.value,
        "affected_components": list(finding.affected_components),
        "evidence": [
            {
                "type": evidence.type.value,
                "source_id": evidence.source_id,
                "description": evidence.description,
            }
            for evidence in finding.evidence
        ],
        "assumptions": list(finding.assumptions),
        "controls": list(finding.controls),
        "validation_steps": list(finding.validation_steps),
        "references": [
            {
                "framework": reference.framework,
                "identifier": reference.identifier,
                "url": reference.url,
            }
            for reference in finding.references
        ],
    }


def _serialize_attack_path(
    path: AttackPath,
) -> dict[str, object]:
    return {
        "id": path.id,
        "entry_point": path.entry_point,
        "target": path.target,
        "nodes": list(path.nodes),
        "flow_ids": list(path.flow_ids),
        "hop_count": path.hop_count,
        "trust_transitions": [
            {
                "source": transition.source,
                "destination": transition.destination,
                "source_zone": transition.source_zone,
                "destination_zone": transition.destination_zone,
                "flow_ids": list(transition.flow_ids),
            }
            for transition in path.trust_transitions
        ],
        "priority": path.priority.value,
        "priority_score": path.priority_score,
        "priority_factors": list(path.priority_factors),
    }
