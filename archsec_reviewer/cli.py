"""
Command-line interface for ArchSec Reviewer.
"""

import argparse
from pathlib import Path

from .analyzer import analyze_architecture
from .report import render_markdown_report


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="archsec-review",
        description="Generate a security architecture review from an architecture description.",
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

    args = parser.parse_args()

    if not args.input.is_file():
        parser.error(f"Input file not found: {args.input}")

    architecture = args.input.read_text(encoding="utf-8")

    review = analyze_architecture(
        architecture,
        title=args.title,
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)

    args.output.write_text(
        render_markdown_report(review),
        encoding="utf-8",
    )

    print(f"✓ Report written to {args.output}")


if __name__ == "__main__":
    main()
