"""Application entry point for CypherQube."""

import sys
from modules import assess_target, batch_assess_targets
from reports import generate_pdf_report
from templates import render_app


def main() -> int:
    """Run the Streamlit dashboard through the shared template renderer."""
    if "streamlit" not in sys.argv[0] and not any("streamlit" in a for a in sys.argv):
        print("Run this app with:  streamlit run app.py")
        return 1

    render_app(
        assess_target=assess_target,
        batch_assess_targets=batch_assess_targets,
        generate_pdf_report=generate_pdf_report,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())