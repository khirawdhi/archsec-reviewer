from pathlib import Path

from archsec_reviewer.cli import _generate_report


def test_generates_report_file(tmp_path: Path) -> None:
    input_file = tmp_path / "architecture.md"
    output_file = tmp_path / "reports" / "review.md"

    input_file.write_text(
        """
        A user accesses an API.
        The API retrieves documents from a vector database.
        The context is sent to an LLM.
        """,
        encoding="utf-8",
    )

    _generate_report(
        input_file=input_file,
        output_file=output_file,
        title="Test Security Review",
    )

    assert output_file.is_file()

    report = output_file.read_text(encoding="utf-8")

    assert report.startswith("# Test Security Review")
    assert "Vector Db" in report
    assert "Prompt injection" in report


def test_creates_missing_output_directory(tmp_path: Path) -> None:
    input_file = tmp_path / "architecture.md"
    output_file = tmp_path / "nested" / "reports" / "review.md"

    input_file.write_text(
        "A user accesses an API.",
        encoding="utf-8",
    )

    _generate_report(
        input_file=input_file,
        output_file=output_file,
        title="Security Review",
    )

    assert output_file.exists()
