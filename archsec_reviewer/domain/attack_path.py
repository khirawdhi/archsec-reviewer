"""Attack-path domain model."""

from dataclasses import dataclass
from enum import Enum


class PathPriority(str, Enum):
    """Review priority assigned to an attack path."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class TrustTransition:
    """A data flow crossing between two declared trust zones."""

    source: str
    destination: str
    source_zone: str
    destination_zone: str
    flow_ids: tuple[str, ...]


@dataclass(frozen=True)
class AttackPath:
    """A directed route from an entry point to a security target."""

    id: str
    entry_point: str
    target: str
    nodes: tuple[str, ...]
    flow_ids: tuple[str, ...]
    trust_transitions: tuple[TrustTransition, ...]
    priority: PathPriority = PathPriority.LOW
    priority_score: int = 0
    priority_factors: tuple[str, ...] = ()

    @property
    def hop_count(self) -> int:
        """Return the number of directed relationships in the path."""

        return max(0, len(self.nodes) - 1)

    def describe(self) -> str:
        """Render the component route in a compact readable form."""

        return " → ".join(self.nodes)
