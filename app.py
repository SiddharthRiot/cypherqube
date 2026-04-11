"""Application entry point for CypherQube."""

import os
from pathlib import Path

from modules import assess_target, batch_assess_targets
from reports import generate_pdf_report
from templates import relaunch_with_streamlit, render_app


def main() -> int:
    """Run the Streamlit dashboard through the shared template renderer."""
    if os.environ.get("CYPHERQUBE_STREAMLIT_BOOTSTRAPPED") != "1":
        return relaunch_with_streamlit(str(Path(__file__).resolve()))

    render_app(
        assess_target=assess_target,
        batch_assess_targets=batch_assess_targets,
        generate_pdf_report=generate_pdf_report,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
