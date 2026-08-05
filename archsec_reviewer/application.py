"""Application services for complete architecture reviews."""

from archsec_reviewer.domain import (
    Architecture,
    SecurityReview,
)
from archsec_reviewer.engines import (
    analyze_flows,
    find_attack_paths,
    prioritize_attack_paths,
)


def review_architecture(
    architecture: Architecture,
    attack_path_cutoff: int = 6,
) -> SecurityReview:
    """Run all deterministic analysis engines."""

    findings = analyze_flows(architecture)

    discovered_paths = find_attack_paths(
        architecture,
        cutoff=attack_path_cutoff,
    )

    prioritized_paths = prioritize_attack_paths(
        architecture=architecture,
        findings=findings,
        attack_paths=discovered_paths,
    )

    for finding in findings:
        validation_errors = finding.validate(architecture)

        if validation_errors:
            raise RuntimeError(
                f"Generated invalid finding '{finding.id}': "
                + "; ".join(validation_errors)
            )

    return SecurityReview(
        architecture=architecture,
        findings=tuple(findings),
        attack_paths=tuple(prioritized_paths),
    )
