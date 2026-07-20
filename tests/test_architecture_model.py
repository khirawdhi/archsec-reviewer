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


def build_valid_architecture() -> Architecture:
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
        ],
        assets=[
            Asset(
                id="customer_data",
                name="Customer Data",
                classification=DataClassification.CONFIDENTIAL,
                owner_component="api",
            ),
        ],
        data_flows=[
            DataFlow(
                id="user_to_api",
                source="user",
                destination="api",
                data=("user prompt",),
                protocol="HTTPS",
                authenticated=True,
                encrypted=True,
            ),
        ],
        security_objectives=[
            "Prevent unauthorized customer-data disclosure.",
        ],
    )


def test_valid_architecture_has_no_errors() -> None:
    architecture = build_valid_architecture()

    assert architecture.validate() == []


def test_returns_component_by_id() -> None:
    architecture = build_valid_architecture()

    component = architecture.get_component("api")

    assert component is not None
    assert component.name == "Backend API"


def test_returns_none_for_unknown_component() -> None:
    architecture = build_valid_architecture()

    assert architecture.get_component("missing") is None


def test_detects_duplicate_component_ids() -> None:
    architecture = build_valid_architecture()
    architecture.components.append(
        Component(
            id="api",
            name="Duplicate API",
            type=ComponentType.API,
            trust_zone="application",
        )
    )

    assert "Duplicate component ID 'api'." in architecture.validate()


def test_detects_unknown_trust_zone() -> None:
    architecture = build_valid_architecture()
    architecture.components.append(
        Component(
            id="worker",
            name="Worker",
            type=ComponentType.SERVICE,
            trust_zone="missing-zone",
        )
    )

    assert (
        "Component 'worker' references unknown trust zone 'missing-zone'."
    ) in architecture.validate()


def test_detects_unknown_flow_destination() -> None:
    architecture = build_valid_architecture()
    architecture.data_flows.append(
        DataFlow(
            id="api_to_missing",
            source="api",
            destination="missing-service",
        )
    )

    assert (
        "Data flow 'api_to_missing' references unknown destination 'missing-service'."
    ) in architecture.validate()


def test_detects_unknown_asset_owner() -> None:
    architecture = build_valid_architecture()
    architecture.assets.append(
        Asset(
            id="audit_logs",
            name="Audit Logs",
            classification=DataClassification.RESTRICTED,
            owner_component="missing-storage",
        )
    )

    assert (
        "Asset 'audit_logs' references unknown owner component 'missing-storage'."
    ) in architecture.validate()
