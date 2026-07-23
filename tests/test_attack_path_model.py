from archsec_reviewer.domain import AttackPath, TrustTransition


def test_attack_path_reports_hop_count() -> None:
    path = AttackPath(
        id="AP-001",
        entry_point="user",
        target="refund_tool",
        nodes=("user", "api", "llm", "refund_tool"),
        flow_ids=(
            "user_to_api",
            "api_to_llm",
            "llm_to_refund",
        ),
        trust_transitions=(),
    )

    assert path.hop_count == 3


def test_attack_path_describes_route() -> None:
    path = AttackPath(
        id="AP-001",
        entry_point="user",
        target="refund_tool",
        nodes=("user", "api", "llm", "refund_tool"),
        flow_ids=(
            "user_to_api",
            "api_to_llm",
            "llm_to_refund",
        ),
        trust_transitions=(),
    )

    assert path.describe() == "user → api → llm → refund_tool"


def test_attack_path_preserves_trust_transitions() -> None:
    transition = TrustTransition(
        source="llm",
        destination="refund_tool",
        source_zone="application",
        destination_zone="privileged",
        flow_ids=("llm_to_refund",),
    )

    path = AttackPath(
        id="AP-001",
        entry_point="user",
        target="refund_tool",
        nodes=("user", "llm", "refund_tool"),
        flow_ids=("user_to_llm", "llm_to_refund"),
        trust_transitions=(transition,),
    )

    assert path.trust_transitions == (transition,)
    assert path.trust_transitions[0].destination_zone == "privileged"
