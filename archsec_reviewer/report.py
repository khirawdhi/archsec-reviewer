"""Markdown report renderer for ArchSec Reviewer."""

from collections.abc import Iterable

from .analyzer import Review


def _bullet_list(items: Iterable[str]) -> str:
    return "\n".join(f"- {item}" for item in items)


def _checklist(items: Iterable[str]) -> str:
    return "\n".join(f"- [ ] {item}" for item in items)


def _heading(title: str) -> list[str]:
    return ["", f"## {title}", ""]


def _render_summary(review: Review) -> list[str]:
    return [
        f"# {review.title}",
        "",
        "## System Summary",
        "",
        review.summary or "No summary provided.",
    ]


def _render_components(review: Review) -> list[str]:
    lines = _heading("Detected Components")

    if review.components:
        formatted = (
            component.replace("_", " ").title() for component in review.components
        )
        lines.append(_bullet_list(formatted))
    else:
        lines.append("- No components detected.")

    return lines


def _render_list_section(title: str, items: Iterable[str]) -> list[str]:
    return _heading(title) + [_bullet_list(items)]


def _render_grouped_section(
    title: str,
    groups: dict[str, list[str]],
    empty_message: str,
) -> list[str]:
    lines = _heading(title)

    if not groups:
        lines.append(empty_message)
        return lines

    for component, values in groups.items():
        lines.extend(
            [
                f"### {component.replace('_', ' ').title()}",
                "",
                _bullet_list(values),
                "",
            ]
        )

    return lines


def _render_validation(review: Review) -> list[str]:
    return _heading("Validation Checklist") + [_checklist(review.validation_checks)]


def _render_footer() -> list[str]:
    return [
        "",
        "## Final Note",
        "",
        "> Threat model trust transitions, not just components.",
    ]


def render_markdown_report(review: Review) -> str:
    lines: list[str] = []

    renderers = [
        _render_summary,
        _render_components,
        lambda r: _render_list_section(
            "Trust Boundaries",
            r.trust_boundaries,
        ),
        lambda r: _render_list_section(
            "Attack Paths",
            r.attack_paths,
        ),
        lambda r: _render_grouped_section(
            "Threat Scenarios",
            r.threats,
            "- No threat scenarios generated.",
        ),
        lambda r: _render_grouped_section(
            "Recommended Controls",
            r.controls,
            "- No controls generated.",
        ),
        _render_validation,
    ]

    for renderer in renderers:
        lines.extend(renderer(review))

    lines.extend(_render_footer())

    return "\n".join(lines)
