import argparse
import json
from scanner import analyze_target
from pdf_report import generate_pdf_report


def normalize_target(target):
    target = target.replace("https://", "")
    target = target.replace("http://", "")
    target = target.split("/")[0]
    return target


def save_json_report(data, filename):
    try:
        with open(filename, "w") as f:
            json.dump(data, f, indent=4)
        print(f"\nJSON report saved to {filename}")
    except Exception as e:
        print("Failed to save JSON report:", e)


def main():
    parser = argparse.ArgumentParser(
        description="CypherQube TLS / Quantum Risk Scanner"
    )

    parser.add_argument(
        "target",
        help="Target domain or IP"
    )

    parser.add_argument(
        "--port",
        type=int,
        default=443,
        help="Target TLS port (default: 443)"
    )

    parser.add_argument(
        "--json",
        metavar="FILE",
        help="Save report to JSON file (e.g. report.json)"
    )

    parser.add_argument(
        "--pdf",
        metavar="FILE",
        help="Save report to PDF file (e.g. report.pdf)"
    )

    args = parser.parse_args()

    target = normalize_target(args.target)
    report = analyze_target(target, args.port)

    if report:
        if args.json:
            save_json_report(report, args.json)

        if args.pdf:
            generate_pdf_report(report, output_path=args.pdf)


if __name__ == "__main__":
    main()