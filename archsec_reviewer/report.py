"""Markdown report rendering for ArchSec Reviewer."""

from .analyzer import Review


def _bullet_list(items: list[str]) -> str:
    return "\n".join(f"- {item}" for item in items)


def _checklist(items: list[str]) -> str:
    return "\n".join(f"- [ ] {item}" for item in items)


def _section_heading(title: str) -> list[str]:
    return ["", f"## {title}", ""]


def _grouped_section(
    title: str,
    data: dict[str, list[str]],
    empty_message: str,
) -> list[str]:
    lines = _section_heading(title)

    if not data:
        return lines + [empty_message]

    for component, items in data.items():
        lines.extend(
            [
                f"### {component.replace('_', ' ').title()}",
                "",
                _bullet_list(items),
                "",
            ]
        )

    return lines


def render_markdown_report(review: Review) -> str:
    lines = [
        f"# {review.title}",
        "",
        "## System Summary",
        "",
        review.summary or "No summary provided.",
    ]

    lines.extend(
        _section_heading("Detected Components")
        + [
            _bullet_list(
                component.replace("_", " ").title()
                for component in review.components
            )
            if review.components
            else "- No components detected."
        ]
    )

    lines.extend(
        _section_heading("Trust Boundaries")
        + [_bullet_list(review.trust_boundaries)]
    )

    lines.extend(
        _section_heading("Attack Paths")
        + [_bullet_list(review.attack_paths)]
    )

    lines.extend(
        _grouped_section(
            "Threat Scenarios",
            review.threats,
            "- No threat scenarios generated.",
        )
    )

    lines.extend(
        _grouped_section(
            "Recommended Controls",
            review.controls,
            "- No controls generated.",
        )
    )

    lines.extend(
        _section_heading("Validation Checklist")
        + [_checklist(review.validation_checks)]
    )

    lines.extend(
        [
            "",
            "## Final Note",
            "",
            "> Threat model trust transitions, not just components.",
            "",
        ]
    )

    return "\n".join(lines)