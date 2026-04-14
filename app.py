import sys
from modules import assess_target, batch_assess_targets
from reports import generate_pdf_report
from templates import render_app


def main() -> int:
    render_app(
        assess_target=assess_target,
        batch_assess_targets=batch_assess_targets,
        generate_pdf_report=generate_pdf_report,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())