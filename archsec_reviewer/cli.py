import argparse
from pathlib import Path

from .analyzer import analyze_architecture
from .report import render_markdown_report


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate a security architecture review from an architecture description."
    )
    parser.add_argument("--input", "-i", required=True, help="Path to architecture markdown/text file")
    parser.add_argument("--output", "-o", required=True, help="Path to output markdown report")
    parser.add_argument("--title", default="Security Architecture Review", help="Report title")

    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)

    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    architecture_text = input_path.read_text(encoding="utf-8")
    review = analyze_architecture(architecture_text, title=args.title)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render_markdown_report(review), encoding="utf-8")

    print(f"[+] Security architecture review generated: {output_path}")
