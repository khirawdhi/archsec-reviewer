"""Safe YAML parser for structured architecture definitions."""

from pathlib import Path
from typing import Mapping, Optional

import yaml

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


MAX_ARCHITECTURE_BYTES = 1_000_000


class ArchitectureParseError(ValueError):
    """Raised when architecture input cannot be parsed safely."""


def parse_yaml_architecture(text: str) -> Architecture:
    """Parse YAML text into a validated Architecture."""

    try:
        loaded: object = yaml.safe_load(text)
    except yaml.YAMLError as error:
        raise ArchitectureParseError(f"Invalid YAML: {error}") from error

    root = _mapping(loaded, "architecture")

    architecture = Architecture(
        name=_required_string(root, "name", "architecture"),
        trust_zones=[
            _parse_trust_zone(item, index)
            for index, item in enumerate(
                _list(root.get("trust_zones", []), "trust_zones")
            )
        ],
        components=[
            _parse_component(item, index)
            for index, item in enumerate(
                _list(root.get("components", []), "components")
            )
        ],
        assets=[
            _parse_asset(item, index)
            for index, item in enumerate(_list(root.get("assets", []), "assets"))
        ],
        data_flows=[
            _parse_data_flow(item, index)
            for index, item in enumerate(
                _list(root.get("data_flows", []), "data_flows")
            )
        ],
        assumptions=_string_list(
            root.get("assumptions", []),
            "assumptions",
        ),
        security_objectives=_string_list(
            root.get("security_objectives", []),
            "security_objectives",
        ),
    )

    validation_errors = architecture.validate()

    if validation_errors:
        raise ArchitectureParseError(
            "Invalid architecture: " + "; ".join(validation_errors)
        )

    return architecture


def load_yaml_architecture(path: Path) -> Architecture:
    """Read and parse a size-limited UTF-8 YAML architecture file."""

    if not path.is_file():
        raise ArchitectureParseError(f"Architecture file not found: {path}")

    if path.stat().st_size > MAX_ARCHITECTURE_BYTES:
        raise ArchitectureParseError("Architecture file exceeds the 1 MB size limit.")

    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as error:
        raise ArchitectureParseError(
            "Architecture file must use UTF-8 encoding."
        ) from error

    return parse_yaml_architecture(text)


def _parse_trust_zone(
    value: object,
    index: int,
) -> TrustZone:
    context = f"trust_zones[{index}]"
    item = _mapping(value, context)

    return TrustZone(
        id=_required_string(item, "id", context),
        name=_required_string(item, "name", context),
        trust_level=_trust_level(
            _required_string(item, "trust_level", context),
            context,
        ),
        owner=_optional_string(item, "owner", context),
    )


def _parse_component(
    value: object,
    index: int,
) -> Component:
    context = f"components[{index}]"
    item = _mapping(value, context)

    return Component(
        id=_required_string(item, "id", context),
        name=_required_string(item, "name", context),
        type=_component_type(
            _required_string(item, "type", context),
            context,
        ),
        trust_zone=_optional_string(
            item,
            "trust_zone",
            context,
        ),
        privileges=tuple(
            _string_list(
                item.get("privileges", []),
                f"{context}.privileges",
            )
        ),
        data_handled=tuple(
            _string_list(
                item.get("data_handled", []),
                f"{context}.data_handled",
            )
        ),
    )


def _parse_asset(
    value: object,
    index: int,
) -> Asset:
    context = f"assets[{index}]"
    item = _mapping(value, context)

    return Asset(
        id=_required_string(item, "id", context),
        name=_required_string(item, "name", context),
        classification=_data_classification(
            _required_string(
                item,
                "classification",
                context,
            ),
            context,
        ),
        owner_component=_optional_string(
            item,
            "owner_component",
            context,
        ),
    )


def _parse_data_flow(
    value: object,
    index: int,
) -> DataFlow:
    context = f"data_flows[{index}]"
    item = _mapping(value, context)

    return DataFlow(
        id=_required_string(item, "id", context),
        source=_required_string(item, "source", context),
        destination=_required_string(
            item,
            "destination",
            context,
        ),
        data=tuple(
            _string_list(
                item.get("data", []),
                f"{context}.data",
            )
        ),
        protocol=_optional_string(
            item,
            "protocol",
            context,
        ),
        authenticated=_optional_boolean(
            item,
            "authenticated",
            context,
        ),
        encrypted=_optional_boolean(
            item,
            "encrypted",
            context,
        ),
    )


def _mapping(
    value: object,
    context: str,
) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise ArchitectureParseError(f"{context} must be a mapping.")

    result: dict[str, object] = {}

    for key, item in value.items():
        if not isinstance(key, str):
            raise ArchitectureParseError(f"{context} contains a non-string key.")

        result[key] = item

    return result


def _list(value: object, context: str) -> list[object]:
    if not isinstance(value, list):
        raise ArchitectureParseError(f"{context} must be a list.")

    return list(value)


def _required_string(
    item: Mapping[str, object],
    key: str,
    context: str,
) -> str:
    value = item.get(key)

    if not isinstance(value, str) or not value.strip():
        raise ArchitectureParseError(f"{context}.{key} must be a non-empty string.")

    return value


def _optional_string(
    item: Mapping[str, object],
    key: str,
    context: str,
) -> Optional[str]:
    value = item.get(key)

    if value is None:
        return None

    if not isinstance(value, str) or not value.strip():
        raise ArchitectureParseError(f"{context}.{key} must be a non-empty string.")

    return value


def _optional_boolean(
    item: Mapping[str, object],
    key: str,
    context: str,
) -> Optional[bool]:
    value = item.get(key)

    if value is None:
        return None

    if not isinstance(value, bool):
        raise ArchitectureParseError(f"{context}.{key} must be a boolean.")

    return value


def _string_list(
    value: object,
    context: str,
) -> list[str]:
    values = _list(value, context)
    result: list[str] = []

    for index, item in enumerate(values):
        if not isinstance(item, str) or not item.strip():
            raise ArchitectureParseError(
                f"{context}[{index}] must be a non-empty string."
            )

        result.append(item)

    return result


def _component_type(
    value: str,
    context: str,
) -> ComponentType:
    try:
        return ComponentType(value)
    except ValueError as error:
        raise ArchitectureParseError(
            f"{context}.type has unsupported value '{value}'."
        ) from error


def _trust_level(
    value: str,
    context: str,
) -> TrustLevel:
    try:
        return TrustLevel(value)
    except ValueError as error:
        raise ArchitectureParseError(
            f"{context}.trust_level has unsupported value '{value}'."
        ) from error


def _data_classification(
    value: str,
    context: str,
) -> DataClassification:
    try:
        return DataClassification(value)
    except ValueError as error:
        raise ArchitectureParseError(
            f"{context}.classification has unsupported value '{value}'."
        ) from error
