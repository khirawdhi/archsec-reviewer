"""Evidence-backed security finding domain model."""

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from .architecture import Architecture


class Severity(str, Enum):
    """Estimated security impact and urgency."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(str, Enum):
    """Confidence supported by available architecture evidence."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ThreatCategory(str, Enum):
    """Security threat categories supported by findings."""

    SPOOFING = "spoofing"
    TAMPERING = "tampering"
    REPUDIATION = "repudiation"
    INFORMATION_DISCLOSURE = "information_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"
    ELEVATION_OF_PRIVILEGE = "elevation_of_privilege"
    AUTHORIZATION = "authorization"
    DATA_POISONING = "data_poisoning"
    PROMPT_INJECTION = "prompt_injection"
    UNSAFE_ACTION = "unsafe_action"
    SUPPLY_CHAIN = "supply_chain"


class EvidenceType(str, Enum):
    """Origin of evidence supporting a finding."""

    COMPONENT = "component"
    DATA_FLOW = "data_flow"
    TRUST_BOUNDARY = "trust_boundary"
    ASSET = "asset"
    DECLARED_ASSUMPTION = "declared_assumption"
    INFERRED = "inferred"


@dataclass(frozen=True)
class Evidence:
    """A traceable fact or inference supporting a finding."""

    type: EvidenceType
    source_id: str
    description: str


@dataclass(frozen=True)
class StandardReference:
    """Mapping from a finding to an external security standard."""

    framework: str
    identifier: str
    url: Optional[str] = None


@dataclass(frozen=True)
class Finding:
    """A security finding supported by architecture evidence."""

    id: str
    title: str
    category: ThreatCategory
    scenario: str
    severity: Severity
    confidence: Confidence
    affected_components: tuple[str, ...]
    evidence: tuple[Evidence, ...]
    assumptions: tuple[str, ...] = ()
    controls: tuple[str, ...] = ()
    validation_steps: tuple[str, ...] = ()
    references: tuple[StandardReference, ...] = ()

    def validate(self, architecture: Architecture) -> list[str]:
        """Return structural and evidence-quality errors."""

        errors: list[str] = []

        if not self.id.strip():
            errors.append("Finding ID must not be empty.")

        if not self.title.strip():
            errors.append(f"Finding '{self.id}' must have a title.")

        if not self.scenario.strip():
            errors.append(f"Finding '{self.id}' must have a scenario.")

        if not self.affected_components:
            errors.append(f"Finding '{self.id}' must reference at least one component.")

        known_components = {component.id for component in architecture.components}

        for component_id in self.affected_components:
            if component_id not in known_components:
                errors.append(
                    f"Finding '{self.id}' references unknown component "
                    f"'{component_id}'."
                )

        if not self.evidence:
            errors.append(f"Finding '{self.id}' must include supporting evidence.")

        for evidence in self.evidence:
            if not evidence.description.strip():
                errors.append(
                    f"Finding '{self.id}' contains evidence without a description."
                )

        return errors
