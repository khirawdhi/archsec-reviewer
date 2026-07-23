"""Graph-based attack-path discovery."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Optional

import networkx as nx

from archsec_reviewer.domain import (
    Architecture,
    AttackPath,
    Component,
    ComponentType,
    DataClassification,
    TrustLevel,
    TrustTransition,
)

from .flow_analysis import InvalidArchitectureError


def build_attack_graph(
    architecture: Architecture,
) -> nx.DiGraph[str]:
    """Build a directed graph from architecture components and flows."""

    validation_errors = architecture.validate()

    if validation_errors:
        raise InvalidArchitectureError(validation_errors)

    graph: nx.DiGraph[str] = nx.DiGraph()

    for component in architecture.components:
        graph.add_node(
            component.id,
            component=component,
        )

    for flow in architecture.data_flows:
        if graph.has_edge(flow.source, flow.destination):
            graph[flow.source][flow.destination]["flow_ids"].append(flow.id)
        else:
            graph.add_edge(
                flow.source,
                flow.destination,
                flow_ids=[flow.id],
            )

    return graph


def find_attack_paths(
    architecture: Architecture,
    entry_points: Optional[Sequence[str]] = None,
    targets: Optional[Sequence[str]] = None,
    cutoff: int = 6,
) -> list[AttackPath]:
    """Find directed routes from untrusted entries to sensitive targets."""

    if cutoff < 1:
        raise ValueError("Attack-path cutoff must be at least 1.")

    graph = build_attack_graph(architecture)
    known_components = set(graph.nodes)

    resolved_entries = (
        sorted(set(entry_points))
        if entry_points is not None
        else _discover_entry_points(architecture)
    )
    resolved_targets = (
        sorted(set(targets)) if targets is not None else _discover_targets(architecture)
    )

    _validate_requested_components(
        "entry point",
        resolved_entries,
        known_components,
    )
    _validate_requested_components(
        "target",
        resolved_targets,
        known_components,
    )

    discovered: set[tuple[str, ...]] = set()

    for entry_point in resolved_entries:
        for target in resolved_targets:
            if entry_point == target:
                continue

            for path in nx.all_simple_paths(
                graph,
                source=entry_point,
                target=target,
                cutoff=cutoff,
            ):
                discovered.add(tuple(path))

    ordered_paths = sorted(
        discovered,
        key=lambda path: (len(path), path),
    )

    return [
        _build_attack_path(
            architecture=architecture,
            graph=graph,
            path=path,
            identifier=f"AP-{index:03d}",
        )
        for index, path in enumerate(ordered_paths, start=1)
    ]


def _discover_entry_points(
    architecture: Architecture,
) -> list[str]:
    zone_levels = {zone.id: zone.trust_level for zone in architecture.trust_zones}

    entries = {
        component.id
        for component in architecture.components
        if component.type
        in {
            ComponentType.USER,
            ComponentType.EXTERNAL_SERVICE,
        }
        or (
            component.trust_zone is not None
            and zone_levels.get(component.trust_zone)
            in {
                TrustLevel.UNTRUSTED,
                TrustLevel.EXTERNAL,
            }
        )
    }

    return sorted(entries)


def _discover_targets(
    architecture: Architecture,
) -> list[str]:
    privileged_zones = {
        zone.id
        for zone in architecture.trust_zones
        if zone.trust_level is TrustLevel.PRIVILEGED
    }

    asset_owners = {
        asset.owner_component
        for asset in architecture.assets
        if asset.owner_component is not None
        and asset.classification
        in {
            DataClassification.CONFIDENTIAL,
            DataClassification.RESTRICTED,
        }
    }

    targets = {
        component.id
        for component in architecture.components
        if component.type is ComponentType.TOOL
        or (
            component.trust_zone is not None
            and component.trust_zone in privileged_zones
        )
        or component.id in asset_owners
    }

    return sorted(targets)


def _validate_requested_components(
    role: str,
    component_ids: Sequence[str],
    known_components: set[str],
) -> None:
    for component_id in component_ids:
        if component_id not in known_components:
            raise ValueError(f"Unknown attack-path {role}: '{component_id}'.")


def _build_attack_path(
    architecture: Architecture,
    graph: nx.DiGraph[str],
    path: tuple[str, ...],
    identifier: str,
) -> AttackPath:
    flow_ids: list[str] = []
    transitions: list[TrustTransition] = []

    for source_id, destination_id in zip(path, path[1:]):
        edge_flow_ids = tuple(graph[source_id][destination_id]["flow_ids"])
        flow_ids.extend(edge_flow_ids)

        source = architecture.get_component(source_id)
        destination = architecture.get_component(destination_id)

        if source is None or destination is None:
            continue

        transition = _build_trust_transition(
            source,
            destination,
            edge_flow_ids,
        )

        if transition is not None:
            transitions.append(transition)

    return AttackPath(
        id=identifier,
        entry_point=path[0],
        target=path[-1],
        nodes=path,
        flow_ids=tuple(flow_ids),
        trust_transitions=tuple(transitions),
    )


def _build_trust_transition(
    source: Component,
    destination: Component,
    flow_ids: tuple[str, ...],
) -> Optional[TrustTransition]:
    if (
        source.trust_zone is None
        or destination.trust_zone is None
        or source.trust_zone == destination.trust_zone
    ):
        return None

    return TrustTransition(
        source=source.id,
        destination=destination.id,
        source_zone=source.trust_zone,
        destination_zone=destination.trust_zone,
        flow_ids=flow_ids,
    )
