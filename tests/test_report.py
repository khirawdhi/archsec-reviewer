from archsec_reviewer import analyze_architecture
from archsec_reviewer.report import render_markdown_report


def test_renders_complete_markdown_report() -> None:
    review = analyze_architecture(
        """
        A user sends a prompt to an API.
        The API sends the prompt to an LLM.
        The LLM can invoke a refund tool.
        """,
        title="RAG Security Review",
    )

    report = render_markdown_report(review)

    assert report.startswith("# RAG Security Review")
    assert "## System Summary" in report
    assert "## Detected Components" in report
    assert "## Trust Boundaries" in report
    assert "## Attack Paths" in report
    assert "## Threat Scenarios" in report
    assert "## Recommended Controls" in report
    assert "## Validation Checklist" in report
    assert "Prompt injection" in report
    assert "- [ ]" in report


def test_renders_empty_component_message() -> None:
    review = analyze_architecture("An unspecified internal system.")

    report = render_markdown_report(review)

    assert "- No components detected." in report
