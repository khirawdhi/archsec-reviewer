from typing import Optional

import pytest

from archsec_reviewer.domain import (
    Architecture,
    Asset,
    Component,
    ComponentType,
    DataClassification,
    DataFlow,
    TrustLevel,
    TrustZone,
)
from archsec_reviewer.engines import (
    build_attack_graph,
    find_attack_paths,
)


def build_architecture(
    extra_flows: Optional[list[DataFlow]] = None,
) -> Architecture:
    additional_flows = extra_flows or []

    return Architecture(
        name="Customer Support RAG",
        trust_zones=[
            TrustZone(
                id="internet",
                name="Internet",
                trust_level=TrustLevel.UNTRUSTED,
            ),
            TrustZone(
                id="application",
                name="Application",
                trust_level=TrustLevel.INTERNAL,
            ),
            TrustZone(
                id="data",
                name="Data",
                trust_level=TrustLevel.INTERNAL,
            ),
            TrustZone(
                id="privileged",
                name="Privileged",
                trust_level=TrustLevel.PRIVILEGED,
            ),
        ],
        components=[
            Component(
                id="user",
                name="Customer",
                type=ComponentType.USER,
                trust_zone="internet",
            ),
            Component(
                id="api",
                name="Backend API",
                type=ComponentType.API,
                trust_zone="application",
            ),
            Component(
                id="vector_db",
                name="Vector Database",
                type=ComponentType.VECTOR_DATABASE,
                trust_zone="data",
            ),
            Component(
                id="llm",
                name="Support LLM",
                type=ComponentType.LLM,
                trust_zone="application",
            ),
            Component(
                id="refund_tool",
                name="Refund Tool",
                type=ComponentType.TOOL,
                trust_zone="privileged",
            ),
            Component(
                id="customer_db",
                name="Customer Database",
                type=ComponentType.DATABASE,
                trust_zone="data",
            ),
        ],
        assets=[
            Asset(
                id="customer_records",
                name="Customer Records",
                classification=DataClassification.RESTRICTED,
                owner_component="customer_db",
            ),
        ],
        data_flows=[
            DataFlow(
                id="user_to_api",
                source="user",
                destination="api",
            ),
            DataFlow(
                id="api_to_vector",
                source="api",
                destination="vector_db",
            ),
            DataFlow(
                id="vector_to_llm",
                source="vector_db",
                destination="llm",
            ),
            DataFlow(
                id="llm_to_refund",
                source="llm",
                destination="refund_tool",
            ),
            DataFlow(
                id="api_to_customer_db",
                source="api",
                destination="customer_db",
            ),
            *additional_flows,
        ],
    )


def test_builds_directed_architecture_graph() -> None:
    graph = build_attack_graph(build_architecture())

    assert set(graph.nodes) == {
        "user",
        "api",
        "vector_db",
        "llm",
        "refund_tool",
        "customer_db",
    }
    assert graph.has_edge("user", "api")
    assert not graph.has_edge("api", "user")


def test_preserves_flow_ids_as_edge_evidence() -> None:
    architecture = build_architecture(
        extra_flows=[
            DataFlow(
                id="second_llm_to_refund",
                source="llm",
                destination="refund_tool",
            ),
        ]
    )

    graph = build_attack_graph(architecture)

    assert graph["llm"]["refund_tool"]["flow_ids"] == [
        "llm_to_refund",
        "second_llm_to_refund",
    ]


def test_finds_explicit_attack_path() -> None:
    paths = find_attack_paths(
        build_architecture(),
        entry_points=["user"],
        targets=["refund_tool"],
    )

    assert len(paths) == 1

    path = paths[0]

    assert path.id == "AP-001"
    assert path.nodes == (
        "user",
        "api",
        "vector_db",
        "llm",
        "refund_tool",
    )
    assert path.hop_count == 4
    assert path.flow_ids == (
        "user_to_api",
        "api_to_vector",
        "vector_to_llm",
        "llm_to_refund",
    )


def test_records_trust_transitions() -> None:
    path = find_attack_paths(
        build_architecture(),
        entry_points=["user"],
        targets=["refund_tool"],
    )[0]

    transitions = {
        (
            transition.source_zone,
            transition.destination_zone,
        )
        for transition in path.trust_transitions
    }

    assert ("internet", "application") in transitions
    assert ("application", "data") in transitions
    assert ("data", "application") in transitions
    assert ("application", "privileged") in transitions


def test_discovers_entries_and_targets_automatically() -> None:
    paths = find_attack_paths(build_architecture())

    discovered_routes = {(path.entry_point, path.target) for path in paths}

    assert ("user", "refund_tool") in discovered_routes
    assert ("user", "customer_db") in discovered_routes


def test_cutoff_limits_path_depth() -> None:
    paths = find_attack_paths(
        build_architecture(),
        entry_points=["user"],
        targets=["refund_tool"],
        cutoff=3,
    )

    assert paths == []


def test_cycle_does_not_create_repeated_node_paths() -> None:
    architecture = build_architecture(
        extra_flows=[
            DataFlow(
                id="llm_to_api",
                source="llm",
                destination="api",
            ),
        ]
    )

    paths = find_attack_paths(
        architecture,
        entry_points=["user"],
        targets=["refund_tool"],
    )

    assert len(paths) == 1
    assert len(paths[0].nodes) == len(set(paths[0].nodes))


def test_rejects_unknown_requested_component() -> None:
    with pytest.raises(
        ValueError,
        match="Unknown attack-path entry point",
    ):
        find_attack_paths(
            build_architecture(),
            entry_points=["attacker"],
            targets=["refund_tool"],
        )


def test_rejects_invalid_cutoff() -> None:
    with pytest.raises(
        ValueError,
        match="cutoff must be at least 1",
    ):
        find_attack_paths(
            build_architecture(),
            cutoff=0,
        )
