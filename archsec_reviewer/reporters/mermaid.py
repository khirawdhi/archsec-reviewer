"""Mermaid renderer for structured architecture security reviews."""

from archsec_reviewer.domain import (
    Architecture,
    DataFlow,
    PathPriority,
    SecurityReview,
)


HIGHLIGHTED_PRIORITIES = {
    PathPriority.HIGH,
    PathPriority.CRITICAL,
}


def render_mermaid_review(review: SecurityReview) -> str:
    """Render an architecture and its prioritized attack paths as Mermaid."""
    architecture = review.architecture
    node_ids = {
        component.id: f"component_{index}"
        for index, component in enumerate(architecture.components)
    }

    lines = ["flowchart TD"]
    lines.extend(
        _render_trust_zones(
            architecture,
            node_ids,
        )
    )
    lines.extend(
        _render_unzoned_components(
            architecture,
            node_ids,
        )
    )

    highlighted_paths = [
        path for path in review.attack_paths if path.priority in HIGHLIGHTED_PRIORITIES
    ]
    highlighted_flow_ids = {
        flow_id for path in highlighted_paths for flow_id in path.flow_ids
    }
    highlighted_node_ids = {
        component_id for path in highlighted_paths for component_id in path.nodes
    }
    entry_points = {path.entry_point for path in highlighted_paths}
    targets = {path.target for path in highlighted_paths}

    highlighted_links: list[int] = []

    for link_index, flow in enumerate(architecture.data_flows):
        source = node_ids[flow.source]
        destination = node_ids[flow.destination]
        label = _flow_label(flow)

        lines.append(f'    {source} -->|"{_escape_label(label)}"| {destination}')

        if flow.id in highlighted_flow_ids:
            highlighted_links.append(link_index)

    lines.extend(
        [
            "",
            "    classDef entry fill:#fff3cd,stroke:#b7791f,stroke-width:2px;",
            "    classDef attack fill:#fee2e2,stroke:#dc2626,stroke-width:2px;",
            "    classDef target fill:#fecaca,stroke:#991b1b,stroke-width:3px;",
        ]
    )

    for component_id, node_id in node_ids.items():
        if component_id in targets:
            lines.append(f"    class {node_id} target;")
        elif component_id in entry_points:
            lines.append(f"    class {node_id} entry;")
        elif component_id in highlighted_node_ids:
            lines.append(f"    class {node_id} attack;")

    for link_index in highlighted_links:
        lines.append(f"    linkStyle {link_index} stroke:#dc2626,stroke-width:3px;")

    return "\n".join(lines) + "\n"


def _render_trust_zones(
    architecture: Architecture,
    node_ids: dict[str, str],
) -> list[str]:
    lines: list[str] = []

    for index, zone in enumerate(architecture.trust_zones):
        zone_label = f"{zone.name} — {zone.trust_level.value}"
        lines.append(f'    subgraph zone_{index}["{_escape_label(zone_label)}"]')

        for component in architecture.components:
            if component.trust_zone == zone.id:
                lines.append(
                    _render_component(
                        component_id=node_ids[component.id],
                        name=component.name,
                        component_type=component.type.value,
                        indentation="        ",
                    )
                )

        lines.append("    end")

    return lines


def _render_unzoned_components(
    architecture: Architecture,
    node_ids: dict[str, str],
) -> list[str]:
    return [
        _render_component(
            component_id=node_ids[component.id],
            name=component.name,
            component_type=component.type.value,
            indentation="    ",
        )
        for component in architecture.components
        if component.trust_zone is None
    ]


def _render_component(
    component_id: str,
    name: str,
    component_type: str,
    indentation: str,
) -> str:
    label = _escape_label(f"{name} ({component_type})")
    return f'{indentation}{component_id}["{label}"]'


def _flow_label(flow: DataFlow) -> str:
    flow_id = flow.id
    protocol = flow.protocol
    authenticated = flow.authenticated
    encrypted = flow.encrypted

    parts = [str(flow_id)]

    if protocol:
        parts.append(str(protocol))

    if authenticated is False:
        parts.append("unauthenticated")

    if encrypted is False:
        parts.append("unencrypted")

    return " · ".join(parts)


def _escape_label(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace('"', "&quot;")
        .replace("|", "&#124;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\n", " ")
    )
