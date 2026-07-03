from .analyzer import Review


def _section_list(items):
    return "\n".join(f"- {item}" for item in items)


def render_markdown_report(review: Review) -> str:
    lines = []

    lines.append(f"# {review.title}")
    lines.append("")
    lines.append("## System Summary")
    lines.append("")
    lines.append(review.summary or "No summary provided.")
    lines.append("")

    lines.append("## Detected Components")
    lines.append("")
    if review.components:
        lines.append(_section_list(review.components))
    else:
        lines.append("- No components detected.")
    lines.append("")

    lines.append("## Trust Boundaries")
    lines.append("")
    lines.append(_section_list(review.trust_boundaries))
    lines.append("")

    lines.append("## Attack Paths")
    lines.append("")
    lines.append(_section_list(review.attack_paths))
    lines.append("")

    lines.append("## Threat Scenarios")
    lines.append("")
    if review.threats:
        for component, threats in review.threats.items():
            lines.append(f"### {component}")
            lines.append("")
            lines.append(_section_list(threats))
            lines.append("")
    else:
        lines.append("- No threat scenarios generated.")
        lines.append("")

    lines.append("## Recommended Controls")
    lines.append("")
    if review.controls:
        for component, controls in review.controls.items():
            lines.append(f"### {component}")
            lines.append("")
            lines.append(_section_list(controls))
            lines.append("")
    else:
        lines.append("- No controls generated.")
        lines.append("")

    lines.append("## Validation Checklist")
    lines.append("")
    for item in review.validation_checks:
        lines.append(f"- [ ] {item}")
    lines.append("")

    lines.append("## Final Note")
    lines.append("")
    lines.append("> Threat model trust transitions, not just components.")
    lines.append("")

    return "\n".join(lines)
