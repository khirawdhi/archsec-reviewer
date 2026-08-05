"""Structured system architecture domain model."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ComponentType(str, Enum):
    """Supported architecture component categories."""

    USER = "user"
    WEB_APPLICATION = "web_application"
    API = "api"
    SERVICE = "service"
    IDENTITY_PROVIDER = "identity_provider"
    DATABASE = "database"
    VECTOR_DATABASE = "vector_database"
    MESSAGE_BROKER = "message_broker"
    LLM = "llm"
    AGENT = "agent"
    TOOL = "tool"
    STORAGE = "storage"
    CI_CD = "ci_cd"
    EXTERNAL_SERVICE = "external_service"


class TrustLevel(str, Enum):
    """Relative trust assigned to an architecture zone."""

    UNTRUSTED = "untrusted"
    EXTERNAL = "external"
    INTERNAL = "internal"
    PRIVILEGED = "privileged"


class DataClassification(str, Enum):
    """Sensitivity classification for information assets."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


@dataclass(frozen=True)
class TrustZone:
    """Administrative or security boundary containing components."""

    id: str
    name: str
    trust_level: TrustLevel
    owner: Optional[str] = None


@dataclass(frozen=True)
class Component:
    """A deployable, logical, human, or external system element."""

    id: str
    name: str
    type: ComponentType
    trust_zone: Optional[str] = None
    privileges: tuple[str, ...] = ()
    data_handled: tuple[str, ...] = ()


@dataclass(frozen=True)
class Asset:
    """Information or capability requiring protection."""

    id: str
    name: str
    classification: DataClassification
    owner_component: Optional[str] = None


@dataclass(frozen=True)
class DataFlow:
    """A directed transfer of data or authority between components."""

    id: str
    source: str
    destination: str
    data: tuple[str, ...] = ()
    protocol: Optional[str] = None
    authenticated: Optional[bool] = None
    encrypted: Optional[bool] = None


@dataclass
class Architecture:
    """Canonical representation consumed by security-analysis engines."""

    name: str
    components: list[Component] = field(default_factory=list)
    trust_zones: list[TrustZone] = field(default_factory=list)
    assets: list[Asset] = field(default_factory=list)
    data_flows: list[DataFlow] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    security_objectives: list[str] = field(default_factory=list)

    def get_component(self, component_id: str) -> Optional[Component]:
        """Return a component by ID, or None when it is not present."""

        return next(
            (
                component
                for component in self.components
                if component.id == component_id
            ),
            None,
        )

    def validate(self) -> list[str]:
        """Return structural validation errors without mutating the model."""

        errors: list[str] = []

        component_ids = [component.id for component in self.components]
        zone_ids = [zone.id for zone in self.trust_zones]
        asset_ids = [asset.id for asset in self.assets]
        flow_ids = [flow.id for flow in self.data_flows]

        errors.extend(_duplicate_errors("component", component_ids))
        errors.extend(_duplicate_errors("trust zone", zone_ids))
        errors.extend(_duplicate_errors("asset", asset_ids))
        errors.extend(_duplicate_errors("data flow", flow_ids))

        known_components = set(component_ids)
        known_zones = set(zone_ids)

        for component in self.components:
            if (
                component.trust_zone is not None
                and component.trust_zone not in known_zones
            ):
                errors.append(
                    f"Component '{component.id}' references unknown "
                    f"trust zone '{component.trust_zone}'."
                )

        for asset in self.assets:
            if (
                asset.owner_component is not None
                and asset.owner_component not in known_components
            ):
                errors.append(
                    f"Asset '{asset.id}' references unknown owner "
                    f"component '{asset.owner_component}'."
                )

        for flow in self.data_flows:
            if flow.source not in known_components:
                errors.append(
                    f"Data flow '{flow.id}' references unknown source '{flow.source}'."
                )

            if flow.destination not in known_components:
                errors.append(
                    f"Data flow '{flow.id}' references unknown "
                    f"destination '{flow.destination}'."
                )

        return errors


def _duplicate_errors(entity: str, identifiers: list[str]) -> list[str]:
    duplicates = sorted(
        identifier
        for identifier in set(identifiers)
        if identifiers.count(identifier) > 1
    )

    return [f"Duplicate {entity} ID '{identifier}'." for identifier in duplicates]
