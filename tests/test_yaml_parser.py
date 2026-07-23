from pathlib import Path

import pytest

from archsec_reviewer.domain import (
    ComponentType,
    DataClassification,
    TrustLevel,
)
from archsec_reviewer.parsers import (
    MAX_ARCHITECTURE_BYTES,
    ArchitectureParseError,
    load_yaml_architecture,
    parse_yaml_architecture,
)


COMPLETE_ARCHITECTURE = """
name: Customer Support RAG

trust_zones:
  - id: internet
    name: Internet
    trust_level: untrusted

  - id: application
    name: Application
    trust_level: internal
    owner: Platform Team

components:
  - id: user
    name: Customer
    type: user
    trust_zone: internet

  - id: llm
    name: Support LLM
    type: llm
    trust_zone: application
    privileges:
      - generate responses
    data_handled:
      - user prompts

assets:
  - id: conversation
    name: Customer Conversation
    classification: confidential
    owner_component: llm

data_flows:
  - id: user_to_llm
    source: user
    destination: llm
    data:
      - user prompt
    protocol: HTTPS
    authenticated: true
    encrypted: true

assumptions:
  - User identity is validated before processing.

security_objectives:
  - Prevent customer-data disclosure.
"""


def test_parses_complete_architecture() -> None:
    architecture = parse_yaml_architecture(COMPLETE_ARCHITECTURE)

    assert architecture.name == "Customer Support RAG"
    assert len(architecture.trust_zones) == 2
    assert len(architecture.components) == 2
    assert len(architecture.assets) == 1
    assert len(architecture.data_flows) == 1

    assert architecture.trust_zones[0].trust_level is TrustLevel.UNTRUSTED
    assert architecture.components[1].type is ComponentType.LLM
    assert architecture.assets[0].classification is DataClassification.CONFIDENTIAL
    assert architecture.data_flows[0].authenticated is True
    assert architecture.data_flows[0].encrypted is True


def test_preserves_component_metadata() -> None:
    architecture = parse_yaml_architecture(COMPLETE_ARCHITECTURE)

    llm = architecture.get_component("llm")

    assert llm is not None
    assert llm.privileges == ("generate responses",)
    assert llm.data_handled == ("user prompts",)


def test_rejects_invalid_yaml() -> None:
    with pytest.raises(
        ArchitectureParseError,
        match="Invalid YAML",
    ):
        parse_yaml_architecture("name: [unclosed")


def test_rejects_non_mapping_root() -> None:
    with pytest.raises(
        ArchitectureParseError,
        match="architecture must be a mapping",
    ):
        parse_yaml_architecture("- one\n- two")


def test_requires_architecture_name() -> None:
    with pytest.raises(
        ArchitectureParseError,
        match="architecture.name",
    ):
        parse_yaml_architecture(
            """
components: []
"""
        )


def test_rejects_unsupported_component_type() -> None:
    with pytest.raises(
        ArchitectureParseError,
        match="unsupported value 'spaceship'",
    ):
        parse_yaml_architecture(
            """
name: Invalid Component

components:
  - id: ship
    name: Spaceship
    type: spaceship
"""
        )


def test_rejects_string_in_boolean_field() -> None:
    with pytest.raises(
        ArchitectureParseError,
        match="authenticated must be a boolean",
    ):
        parse_yaml_architecture(
            """
name: Invalid Boolean

components:
  - id: user
    name: User
    type: user

  - id: api
    name: API
    type: api

data_flows:
  - id: user_to_api
    source: user
    destination: api
    authenticated: "yes"
"""
        )


def test_rejects_unknown_flow_reference() -> None:
    with pytest.raises(
        ArchitectureParseError,
        match="unknown destination 'missing'",
    ):
        parse_yaml_architecture(
            """
name: Broken Flow

components:
  - id: user
    name: User
    type: user

data_flows:
  - id: broken
    source: user
    destination: missing
"""
        )


def test_safe_loader_rejects_python_object_tags() -> None:
    malicious_yaml = """
!!python/object/apply:os.system
- echo unsafe
"""

    with pytest.raises(
        ArchitectureParseError,
        match="Invalid YAML",
    ):
        parse_yaml_architecture(malicious_yaml)


def test_loads_architecture_file(tmp_path: Path) -> None:
    architecture_file = tmp_path / "architecture.yaml"
    architecture_file.write_text(
        COMPLETE_ARCHITECTURE,
        encoding="utf-8",
    )

    architecture = load_yaml_architecture(architecture_file)

    assert architecture.name == "Customer Support RAG"


def test_rejects_missing_architecture_file(
    tmp_path: Path,
) -> None:
    missing_file = tmp_path / "missing.yaml"

    with pytest.raises(
        ArchitectureParseError,
        match="file not found",
    ):
        load_yaml_architecture(missing_file)


def test_rejects_oversized_architecture_file(
    tmp_path: Path,
) -> None:
    architecture_file = tmp_path / "large.yaml"
    architecture_file.write_bytes(b"x" * (MAX_ARCHITECTURE_BYTES + 1))

    with pytest.raises(
        ArchitectureParseError,
        match="exceeds the 1 MB size limit",
    ):
        load_yaml_architecture(architecture_file)
