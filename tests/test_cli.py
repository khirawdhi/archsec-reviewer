import argparse
import json
from pathlib import Path

import pytest

from archsec_reviewer.cli import (
    _generate_report,
    _generate_structured_report,
    _is_yaml_file,
    _positive_integer,
    main,
)


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


def test_creates_missing_output_directory(
    tmp_path: Path,
) -> None:
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


def test_generates_structured_yaml_report(
    tmp_path: Path,
) -> None:
    input_file = tmp_path / "architecture.yaml"
    output_file = tmp_path / "reports" / "structured.md"

    input_file.write_text(
        """
name: Tool-Using Assistant

trust_zones:
  - id: internet
    name: Internet
    trust_level: untrusted

  - id: ai
    name: AI Runtime
    trust_level: internal

  - id: privileged
    name: Privileged Operations
    trust_level: privileged

components:
  - id: user
    name: Customer
    type: user
    trust_zone: internet

  - id: llm
    name: LLM
    type: llm
    trust_zone: ai

  - id: refund_tool
    name: Refund Tool
    type: tool
    trust_zone: privileged

data_flows:
  - id: user_to_llm
    source: user
    destination: llm
    authenticated: true
    encrypted: true

  - id: llm_to_refund
    source: llm
    destination: refund_tool
    authenticated: true
    encrypted: true
""",
        encoding="utf-8",
    )

    _generate_structured_report(
        input_file=input_file,
        output_file=output_file,
        attack_path_cutoff=6,
    )

    report = output_file.read_text(encoding="utf-8")

    assert report.startswith("# Security Architecture Review: Tool-Using Assistant")
    assert "AI-PROMPT-001:user_to_llm" in report
    assert "AI-TOOL-001:llm_to_refund" in report
    assert "user → llm → refund_tool" in report


def test_generates_structured_json_report_from_cli(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    input_file = tmp_path / "architecture.yaml"
    output_file = tmp_path / "reports" / "review.json"

    input_file.write_text(
        """
name: JSON Export Test

trust_zones:
  - id: internet
    name: Internet
    trust_level: untrusted

  - id: application
    name: Application
    trust_level: internal

components:
  - id: customer
    name: Customer
    type: user
    trust_zone: internet

  - id: api
    name: API
    type: api
    trust_zone: application

data_flows:
  - id: customer-to-api
    source: customer
    destination: api
    data:
      - request
    protocol: HTTPS
    authenticated: true
    encrypted: true
""",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "sys.argv",
        [
            "archsec-review",
            "--input",
            str(input_file),
            "--output",
            str(output_file),
            "--format",
            "json",
        ],
    )

    main()

    document = json.loads(output_file.read_text(encoding="utf-8"))

    assert document["schema_version"] == "1.0"
    assert document["architecture"]["name"] == "JSON Export Test"
    assert document["architecture"]["components"][1]["type"] == "api"
    assert isinstance(document["findings"], list)
    assert isinstance(document["attack_paths"], list)


def test_detects_yaml_file_extensions() -> None:
    assert _is_yaml_file(Path("architecture.yaml"))
    assert _is_yaml_file(Path("architecture.yml"))
    assert _is_yaml_file(Path("ARCHITECTURE.YAML"))
    assert not _is_yaml_file(Path("architecture.md"))


def test_validates_attack_path_cutoff() -> None:
    assert _positive_integer("6") == 6

    with pytest.raises(
        argparse.ArgumentTypeError,
        match="must be at least 1",
    ):
        _positive_integer("0")

    with pytest.raises(
        argparse.ArgumentTypeError,
        match="must be an integer",
    ):
        _positive_integer("invalid")
