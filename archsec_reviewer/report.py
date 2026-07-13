from .analyzer import Review


def _list(items: list[str]) -> str:
    return "\n".join(f"- {item}" for item in items)


def _checklist(items: list[str]) -> str:
    return "\n".join(f"- [ ] {item}" for item in items)


def _heading(title: str) -> list[str]:
    return ["", f"## {title}", ""]


def _component_section(title: str, data: dict[str, list[str]], empty: str) -> list[str]:
    if not data:
        return _heading(title) + [empty, ""]

    lines = _heading(title)

    for component, items in data.items():
        lines.extend([
            f"### {component}",
            "",
            _list(items),
            "",
        ])

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
        _heading("Detected Components")
        + [_list(review.components) if review.components else "- No components detected."]
    )

    lines.extend(
        _heading("Trust Boundaries")
        + [_list(review.trust_boundaries)]
    )

    lines.extend(
        _heading("Attack Paths")
        + [_list(review.attack_paths)]
    )

    lines.extend(
        _component_section(
            "Threat Scenarios",
            review.threats,
            "- No threat scenarios generated.",
        )
    )

    lines.extend(
        _component_section(
            "Recommended Controls",
            review.controls,
            "- No controls generated.",
        )
    )

    lines.extend(
        _heading("Validation Checklist")
        + [_checklist(review.validation_checks)]
    )

    lines.extend([
        "",
        "## Final Note",
        "",
        "> Threat model trust transitions, not just components.",
    ])

    return "\n".join(lines)
