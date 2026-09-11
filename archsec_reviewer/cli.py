"""Command-line interface for ArchSec Reviewer."""

import argparse
from pathlib import Path

from .analyzer import analyze_architecture
from .application import review_architecture
from .parsers import (
    ArchitectureParseError,
    load_yaml_architecture,
)
from .report import render_markdown_report
from .reporters import render_json_review, render_structured_review


YAML_SUFFIXES = {".yaml", ".yml"}


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="archsec-review",
        description=(
            "Generate a security architecture review from a "
            "structured YAML definition or a Markdown description."
        ),
    )

    parser.add_argument(
        "-i",
        "--input",
        required=True,
        type=Path,
        help=(
            "Architecture input file. YAML uses structured analysis; "
            "Markdown and text use legacy keyword analysis."
        ),
    )

    parser.add_argument(
        "-o",
        "--output",
        required=True,
        type=Path,
        help="Output report path.",
    )

    parser.add_argument(
        "-f",
        "--format",
        dest="output_format",
        choices=("markdown", "json"),
        default="markdown",
        help="Structured report format. Default: markdown.",
    )

    parser.add_argument(
        "-t",
        "--title",
        default="Security Architecture Review",
        help=(
            "Report title for Markdown or text input. "
            "YAML reports use the architecture name."
        ),
    )

    parser.add_argument(
        "--attack-path-cutoff",
        type=_positive_integer,
        default=6,
        help=("Maximum number of graph edges in a discovered attack path. Default: 6."),
    )

    return parser


def _generate_report(
    input_file: Path,
    output_file: Path,
    title: str,
) -> None:
    """Generate a legacy report from Markdown or text."""

    architecture = input_file.read_text(encoding="utf-8")

    review = analyze_architecture(
        architecture,
        title=title,
    )

    _write_report(
        output_file,
        render_markdown_report(review),
    )


def _generate_structured_report(
    input_file: Path,
    output_file: Path,
    attack_path_cutoff: int,
    output_format: str = "markdown",
) -> None:
    """Generate an architecture-aware report from YAML."""
    architecture = load_yaml_architecture(input_file)

    review = review_architecture(
        architecture,
        attack_path_cutoff=attack_path_cutoff,
    )

    if output_format == "json":
        report = render_json_review(review)
    else:
        report = render_structured_review(review)

    _write_report(
        output_file,
        report,
    )


def _write_report(
    output_file: Path,
    report: str,
) -> None:
    output_file.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_file.write_text(
        report,
        encoding="utf-8",
    )


def _is_yaml_file(path: Path) -> bool:
    return path.suffix.lower() in YAML_SUFFIXES


def _positive_integer(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be an integer") from error

    if parsed < 1:
        raise argparse.ArgumentTypeError("must be at least 1")

    return parsed


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    if not args.input.is_file():
        parser.error(f"Input file not found: {args.input}")

    if args.output_format == "json" and not _is_yaml_file(args.input):
        parser.error("JSON output requires a structured YAML input file.")

    try:
        if _is_yaml_file(args.input):
            _generate_structured_report(
                input_file=args.input,
                output_file=args.output,
                attack_path_cutoff=args.attack_path_cutoff,
                output_format=args.output_format,
            )
        else:
            _generate_report(
                input_file=args.input,
                output_file=args.output,
                title=args.title,
            )
    except ArchitectureParseError as error:
        parser.error(str(error))
    except (OSError, UnicodeError) as error:
        parser.error(f"Unable to process architecture file: {error}")

    print(f"✓ Report written to {args.output}")


if __name__ == "__main__":
    main()
