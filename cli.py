import argparse
import json
from core import badge
from scanner import analyze_target
from pdf_report import generate_pdf_report
from core.badge import determine_badge


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

    parser.add_argument("target", help="Target domain or IP")

    parser.add_argument("--port", type=int, default=443)

    parser.add_argument("--json", metavar="FILE")
    parser.add_argument("--pdf", metavar="FILE")

    args = parser.parse_args()

    target = normalize_target(args.target)

    print("\n🔍 Scanning target:", target)
    print("⚡ Initializing TLS + Quantum Risk Analysis...\n")

    try:
        report = analyze_target(target, args.port)

        if not report:
            raise RuntimeError("Scan returned no data")

    except Exception as e:
        print(f"\n❌ Scan failed: {e}")
        return

    # ─── Show Summary ───────────────────────────────────────────────────────
    risk = report.get("quantum_risk", {})
    score = risk.get("risk_score", "N/A")
    badge = determine_badge(score, target)
    print(f"\n  Certification: {badge.label}")

    print("\n==============================")
    print("   FINAL QUANTUM RISK SCORE")
    print("==============================")
    print(f"Score: {score}/10")

    if isinstance(score, int):
        if score >= 7:
            print("⚠️  Status: HIGH RISK (Quantum Vulnerable)")
        elif score >= 4:
            print("⚠️  Status: MODERATE RISK")
        else:
            print("✅ Status: LOW RISK (Quantum Ready)")

    # ─── Export Options ─────────────────────────────────────────────────────
    if args.json:
        save_json_report(report, args.json)

    if args.pdf:
        generate_pdf_report(report, output_path=args.pdf)

    print("\n✅ Scan completed successfully.\n")


if __name__ == "__main__":
    main()