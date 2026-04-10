"""Application entry point for CypherQube."""

import os
from pathlib import Path

from core import CBOMGenerator, determine_badge
from modules import analyze_target
from reports import generate_pdf_report
from templates import relaunch_with_streamlit, render_app


def main() -> int:
    """Run the Streamlit dashboard through the shared template renderer."""
    if os.environ.get("CYPHERQUBE_STREAMLIT_BOOTSTRAPPED") != "1":
        return relaunch_with_streamlit(str(Path(__file__).resolve()))

    render_app(
        analyze_target=analyze_target,
        generate_pdf_report=generate_pdf_report,
        determine_badge=determine_badge,
        cbom_generator_cls=CBOMGenerator,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
