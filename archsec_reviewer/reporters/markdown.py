"""Markdown renderer for structured security reviews."""

from html import escape
from typing import Iterable

from archsec_reviewer.domain import (
    Finding,
    SecurityReview,
    Severity,
)


SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFORMATIONAL: 4,
}


def render_structured_review(
    review: SecurityReview,
) -> str:
    """Render a structured security review as Markdown."""

    architecture = review.architecture

    finding_label = _pluralize(
        review.finding_count,
        "finding",
        "findings",
    )
    attack_path_label = _pluralize(
        review.attack_path_count,
        "path",
        "paths",
    )

    lines = [
        f"# Security Architecture Review: {_text(architecture.name)}",
        "",
        "## Executive Summary",
        "",
        (
            f"ArchSec Reviewer identified **{review.finding_count} "
            f"security {finding_label}** and "
            f"**{review.attack_path_count} attack "
            f"{attack_path_label}** from the declared architecture."
        ),
        "",
    ]

    lines.extend(_render_scope(review))
    lines.extend(_render_architecture(review))
    lines.extend(_render_findings(review))
    lines.extend(_render_attack_paths(review))
    lines.extend(_render_limitations())

    return "\n".join(lines) + "\n"


def _render_scope(review: SecurityReview) -> list[str]:
    architecture = review.architecture

    return [
        "## Security Objectives",
        "",
        _bullets(architecture.security_objectives)
        or "- No security objectives declared.",
        "",
        "## Declared Assumptions",
        "",
        _bullets(architecture.assumptions) or "- No assumptions declared.",
        "",
    ]


def _render_architecture(
    review: SecurityReview,
) -> list[str]:
    architecture = review.architecture

    lines = [
        "## Architecture Overview",
        "",
        "### Trust Zones",
        "",
    ]

    if architecture.trust_zones:
        lines.extend(
            [
                "| ID | Name | Trust level | Owner |",
                "|---|---|---|---|",
            ]
        )

        for zone in architecture.trust_zones:
            lines.append(
                "| "
                + " | ".join(
                    [
                        _cell(zone.id),
                        _cell(zone.name),
                        _cell(zone.trust_level.value),
                        _cell(zone.owner or "Not declared"),
                    ]
                )
                + " |"
            )
    else:
        lines.append("No trust zones declared.")

    lines.extend(
        [
            "",
            "### Components",
            "",
        ]
    )

    if architecture.components:
        lines.extend(
            [
                "| ID | Name | Type | Trust zone |",
                "|---|---|---|---|",
            ]
        )

        for component in architecture.components:
            lines.append(
                "| "
                + " | ".join(
                    [
                        _cell(component.id),
                        _cell(component.name),
                        _cell(component.type.value),
                        _cell(component.trust_zone or "Not declared"),
                    ]
                )
                + " |"
            )
    else:
        lines.append("No components declared.")

    lines.extend(
        [
            "",
            "### Assets",
            "",
        ]
    )

    if architecture.assets:
        lines.extend(
            [
                "| ID | Name | Classification | Owner |",
                "|---|---|---|---|",
            ]
        )

        for asset in architecture.assets:
            lines.append(
                "| "
                + " | ".join(
                    [
                        _cell(asset.id),
                        _cell(asset.name),
                        _cell(asset.classification.value),
                        _cell(asset.owner_component or "Not declared"),
                    ]
                )
                + " |"
            )
    else:
        lines.append("No assets declared.")

    lines.extend(
        [
            "",
            "### Data Flows",
            "",
        ]
    )

    if architecture.data_flows:
        lines.extend(
            [
                (
                    "| ID | Source | Destination | Protocol | "
                    "Authenticated | Encrypted |"
                ),
                "|---|---|---|---|---|---|",
            ]
        )

        for flow in architecture.data_flows:
            lines.append(
                "| "
                + " | ".join(
                    [
                        _cell(flow.id),
                        _cell(flow.source),
                        _cell(flow.destination),
                        _cell(flow.protocol or "Not declared"),
                        _cell(_boolean(flow.authenticated)),
                        _cell(_boolean(flow.encrypted)),
                    ]
                )
                + " |"
            )
    else:
        lines.append("No data flows declared.")

    lines.append("")

    return lines


def _render_findings(
    review: SecurityReview,
) -> list[str]:
    lines = [
        "## Security Findings",
        "",
    ]

    if not review.findings:
        lines.extend(
            [
                (
                    "No deterministic findings were generated from "
                    "the declared architecture."
                ),
                "",
            ]
        )
        return lines

    findings = sorted(
        review.findings,
        key=lambda finding: (
            SEVERITY_ORDER[finding.severity],
            finding.id,
        ),
    )

    for finding in findings:
        lines.extend(_render_finding(finding))

    return lines


def _render_finding(finding: Finding) -> list[str]:
    lines = [
        (
            f"### [{finding.severity.value.upper()}] "
            f"{_text(finding.id)} — {_text(finding.title)}"
        ),
        "",
        f"- **Severity:** {_text(finding.severity.value)}",
        f"- **Confidence:** {_text(finding.confidence.value)}",
        f"- **Category:** {_text(finding.category.value)}",
        (
            "- **Affected components:** "
            + ", ".join(_text(component) for component in finding.affected_components)
        ),
        "",
        "#### Scenario",
        "",
        _text(finding.scenario),
        "",
        "#### Evidence",
        "",
    ]

    for evidence in finding.evidence:
        lines.append(
            f"- **{_text(evidence.type.value)} / "
            f"{_text(evidence.source_id)}:** "
            f"{_text(evidence.description)}"
        )

    lines.extend(
        [
            "",
            "#### Assumptions",
            "",
            _bullets(finding.assumptions) or "- No additional assumptions.",
            "",
            "#### Recommended Controls",
            "",
            _bullets(finding.controls) or "- No controls generated.",
            "",
            "#### Validation Steps",
            "",
            _checklist(finding.validation_steps)
            or "- [ ] No validation steps generated.",
            "",
        ]
    )

    if finding.references:
        lines.extend(
            [
                "#### Standards References",
                "",
            ]
        )

        for reference in finding.references:
            label = f"{_text(reference.framework)} {_text(reference.identifier)}"

            if reference.url:
                lines.append(f"- [{label}]({_text(reference.url)})")
            else:
                lines.append(f"- {label}")

        lines.append("")

    return lines


def _render_attack_paths(
    review: SecurityReview,
) -> list[str]:
    lines = [
        "## Attack Paths",
        "",
    ]

    if not review.attack_paths:
        lines.extend(
            [
                (
                    "No attack paths were discovered between declared "
                    "entry points and sensitive targets."
                ),
                "",
            ]
        )
        return lines

    for path in review.attack_paths:
        lines.extend(
            [
                f"### {_text(path.id)}",
                "",
                f"- **Entry point:** {_text(path.entry_point)}",
                f"- **Target:** {_text(path.target)}",
                f"- **Hop count:** {path.hop_count}",
                ("- **Route:** " + " → ".join(_text(node) for node in path.nodes)),
                (
                    "- **Flow evidence:** "
                    + ", ".join(_text(flow_id) for flow_id in path.flow_ids)
                ),
                "",
                "#### Trust Transitions",
                "",
            ]
        )

        if not path.trust_transitions:
            lines.append("- No explicit trust-zone transition declared.")
        else:
            for transition in path.trust_transitions:
                lines.append(
                    f"- {_text(transition.source)} "
                    f"({_text(transition.source_zone)}) → "
                    f"{_text(transition.destination)} "
                    f"({_text(transition.destination_zone)})"
                )

        lines.append("")

    return lines


def _render_limitations() -> list[str]:
    return [
        "## Review Limitations",
        "",
        (
            "This report is based on the components, data flows, trust "
            "zones, assets, and assumptions declared in the input. "
            "Missing architecture details may produce missing findings "
            "or lower-confidence conclusions."
        ),
        "",
    ]


def _bullets(items: Iterable[str]) -> str:
    return "\n".join(f"- {_text(item)}" for item in items)


def _checklist(items: Iterable[str]) -> str:
    return "\n".join(f"- [ ] {_text(item)}" for item in items)


def _boolean(value: object) -> str:
    if value is True:
        return "Yes"

    if value is False:
        return "No"

    return "Not declared"


def _text(value: str) -> str:
    return escape(
        value,
        quote=False,
    ).replace(
        "\n",
        " ",
    )


def _cell(value: str) -> str:
    return _text(value).replace(
        "|",
        "\\|",
    )


def _pluralize(
    count: int,
    singular: str,
    plural: str,
) -> str:
    return singular if count == 1 else plural
