"""Complete structured security-review model."""

from dataclasses import dataclass

from .architecture import Architecture
from .attack_path import AttackPath
from .finding import Finding


@dataclass(frozen=True)
class SecurityReview:
    """Combined result of architecture security analysis."""

    architecture: Architecture
    findings: tuple[Finding, ...]
    attack_paths: tuple[AttackPath, ...]

    @property
    def finding_count(self) -> int:
        """Return the number of generated security findings."""

        return len(self.findings)

    @property
    def attack_path_count(self) -> int:
        """Return the number of discovered attack paths."""

        return len(self.attack_paths)
