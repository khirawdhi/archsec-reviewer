"""
Command-line interface for ArchSec Reviewer.
"""

import argparse
from pathlib import Path

from .analyzer import analyze_architecture
from .report import render_markdown_report


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="archsec-review",
        description=(
            "Generate a security architecture review from an architecture description."
        ),
    )

    parser.add_argument(
        "-i",
        "--input",
        required=True,
        type=Path,
        help="Architecture description (Markdown or text).",
    )

    parser.add_argument(
        "-o",
        "--output",
        required=True,
        type=Path,
        help="Output Markdown report.",
    )

    parser.add_argument(
        "-t",
        "--title",
        default="Security Architecture Review",
        help="Report title.",
    )

    return parser


def _generate_report(
    input_file: Path,
    output_file: Path,
    title: str,
) -> None:
    architecture = input_file.read_text(encoding="utf-8")

    review = analyze_architecture(
        architecture,
        title=title,
    )

    output_file.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_file.write_text(
        render_markdown_report(review),
        encoding="utf-8",
    )


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    if not args.input.is_file():
        parser.error(f"Input file not found: {args.input}")

    _generate_report(
        input_file=args.input,
        output_file=args.output,
        title=args.title,
    )

    print(f"✓ Report written to {args.output}")


if __name__ == "__main__":
    main()
