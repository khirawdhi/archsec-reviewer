from archsec_reviewer import analyze_architecture


RAG_ARCHITECTURE = """
A customer uses a backend API to ask questions.
The API retrieves documents from a vector database.
The retrieved context is sent to an LLM.
An AI agent can invoke a refund tool.
OAuth tokens are used for authentication.
"""


def test_detects_rag_components() -> None:
    review = analyze_architecture(RAG_ARCHITECTURE)

    assert "user" in review.components
    assert "api" in review.components
    assert "vector_db" in review.components
    assert "llm" in review.components
    assert "tool" in review.components
    assert "identity" in review.components


def test_generates_llm_tool_attack_path() -> None:
    review = analyze_architecture(RAG_ARCHITECTURE)

    assert any(
        "Prompt injection" in attack_path
        and "unauthorized tool selection" in attack_path
        for attack_path in review.attack_paths
    )


def test_generates_retrieval_attack_path() -> None:
    review = analyze_architecture(RAG_ARCHITECTURE)

    assert any(
        "Poisoned knowledge base document" in attack_path
        for attack_path in review.attack_paths
    )


def test_returns_fallbacks_when_no_components_are_detected() -> None:
    review = analyze_architecture("An unspecified internal system.")

    assert review.components == []
    assert review.trust_boundaries == [
        (
            "No explicit trust boundaries detected. Add users, services, "
            "data stores, identity, and external integrations."
        )
    ]
    assert review.attack_paths == [
        (
            "No clear attack path detected. "
            "Add more architecture details to improve analysis."
        )
    ]


def test_preserves_custom_title() -> None:
    review = analyze_architecture(
        RAG_ARCHITECTURE,
        title="Customer Support Threat Model",
    )

    assert review.title == "Customer Support Threat Model"
