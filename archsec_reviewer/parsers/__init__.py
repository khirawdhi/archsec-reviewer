"""Architecture input parsers."""

from .yaml_parser import (
    MAX_ARCHITECTURE_BYTES,
    ArchitectureParseError,
    load_yaml_architecture,
    parse_yaml_architecture,
)

__all__ = [
    "MAX_ARCHITECTURE_BYTES",
    "ArchitectureParseError",
    "load_yaml_architecture",
    "parse_yaml_architecture",
]
