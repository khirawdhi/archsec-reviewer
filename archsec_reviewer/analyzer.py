"""Architecture analysis engine for ArchSec Reviewer."""

from dataclasses import dataclass, field
from typing import Sequence

from .rules import (
    ATTACK_PATH_RULES,
    BASE_VALIDATION_CHECKS,
    COMPONENTS,
    TRUST_BOUNDARY_RULES,
    RuleDefinition,
)


Library = dict[str, list[str]]


@dataclass
class Review:
    title: str
    summary: str
    components: list[str] = field(default_factory=list)
    trust_boundaries: list[str] = field(default_factory=list)
    attack_paths: list[str] = field(default_factory=list)
    threats: Library = field(default_factory=dict)
    controls: Library = field(default_factory=dict)
    validation_checks: list[str] = field(default_factory=list)


def _detect_components(text: str) -> list[str]:
    lowered_text = text.lower()

    return [
        component
        for component, definition in COMPONENTS.items()
        if any(keyword in lowered_text for keyword in definition.keywords)
    ]


def _apply_rules(
    components: Sequence[str],
    rules: Sequence[RuleDefinition],
    fallback: str,
) -> list[str]:
    component_set = set(components)

    matches = [
        rule.message
        for rule in rules
        if rule.required_components.issubset(component_set)
    ]

    return matches or [fallback]


def _build_trust_boundaries(components: Sequence[str]) -> list[str]:
    return _apply_rules(
        components,
        TRUST_BOUNDARY_RULES,
        (
            "No explicit trust boundaries detected. Add users, services, "
            "data stores, identity, and external integrations."
        ),
    )


def _build_attack_paths(components: Sequence[str]) -> list[str]:
    return _apply_rules(
        components,
        ATTACK_PATH_RULES,
        (
            "No clear attack path detected. "
            "Add more architecture details to improve analysis."
        ),
    )


def _build_threats(components: Sequence[str]) -> Library:
    return {
        component: list(COMPONENTS[component].threats)
        for component in components
        if COMPONENTS[component].threats
    }


def _build_controls(components: Sequence[str]) -> Library:
    return {
        component: list(COMPONENTS[component].controls)
        for component in components
        if COMPONENTS[component].controls
    }


def _build_validation_checks(components: Sequence[str]) -> list[str]:
    checks = list(BASE_VALIDATION_CHECKS)

    for component in components:
        checks.extend(COMPONENTS[component].validation_checks)

    return checks


def analyze_architecture(
    text: str,
    title: str = "Security Architecture Review",
) -> Review:
    components = _detect_components(text)

    return Review(
        title=title,
        summary=text.strip()[:700],
        components=components,
        trust_boundaries=_build_trust_boundaries(components),
        attack_paths=_build_attack_paths(components),
        threats=_build_threats(components),
        controls=_build_controls(components),
        validation_checks=_build_validation_checks(components),
    )
