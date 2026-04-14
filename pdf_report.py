"""
pdf_report.py — CypherQube PDF Report Generator
Clean white/formal theme. Professional look for client delivery.
"""

from datetime import datetime
from io import BytesIO

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether
)
from reportlab.lib.colors import HexColor
from core.badge import determine_badge


# Formal white palette
C_BG        = HexColor("#ffffff")   # page background
C_HEADER_BG = HexColor("#1a3a5c")   # deep navy header bar
C_CARD      = HexColor("#f7f9fc")   # card / row background
C_CARD_ALT  = HexColor("#eef2f7")   # alternating row
C_BORDER    = HexColor("#d0d9e4")   # subtle border
C_TEXT1     = HexColor("#0f1f2e")   # primary text (near-black navy)
C_TEXT2     = HexColor("#3a4a5c")   # secondary text
C_TEXT3     = HexColor("#7a8fa6")   # muted / label text
C_ACCENT    = HexColor("#1a3a5c")   # accent (navy)
C_RED       = HexColor("#c0392b")   # critical / high
C_AMBER     = HexColor("#d4680a")   # medium
C_GREEN     = HexColor("#1a7a4a")   # low / safe
C_BLUE      = HexColor("#1a5fa6")   # info
C_WHITE     = HexColor("#ffffff")

SEV_COLOR = {
    "CRITICAL": C_RED,
    "HIGH":     C_RED,
    "MEDIUM":   C_AMBER,
    "LOW":      C_GREEN,
    "INFO":     C_BLUE,
}

# Severity badge background (lighter tints for white theme)
SEV_BG = {
    "CRITICAL": HexColor("#fde8e8"),
    "HIGH":     HexColor("#fde8e8"),
    "MEDIUM":   HexColor("#fef3e2"),
    "LOW":      HexColor("#e6f5ec"),
    "INFO":     HexColor("#e6f0fa"),
}

PAGE_W, PAGE_H = A4
MARGIN    = 20 * mm
CONTENT_W = PAGE_W - 2 * MARGIN


# Page decorator
def _page_decorator(canvas, doc, target="", scan_time=""):
    canvas.saveState()

    # White page background
    canvas.setFillColor(C_BG)
    canvas.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)

    # Navy header bar
    canvas.setFillColor(C_HEADER_BG)
    canvas.rect(0, PAGE_H - 14 * mm, PAGE_W, 14 * mm, fill=1, stroke=0)

    # Header: product name
    canvas.setFillColor(C_WHITE)
    canvas.setFont("Helvetica-Bold", 9)
    canvas.drawString(MARGIN, PAGE_H - 9 * mm, "CYPHERCUBE")
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(HexColor("#a8c4dc"))
    canvas.drawString(MARGIN + 58, PAGE_H - 9 * mm, "TLS / QUANTUM RISK SCANNER")

    # Header: target (right-aligned)
    canvas.setFillColor(HexColor("#c8daea"))
    canvas.setFont("Courier", 7)
    canvas.drawRightString(PAGE_W - MARGIN, PAGE_H - 9 * mm, str(target))

    # Footer separator
    canvas.setStrokeColor(C_BORDER)
    canvas.setLineWidth(0.5)
    canvas.line(MARGIN, 13 * mm, PAGE_W - MARGIN, 13 * mm)

    # Footer text
    canvas.setFillColor(C_TEXT3)
    canvas.setFont("Courier", 6.5)
    canvas.drawString(MARGIN, 8.5 * mm, f"Generated: {scan_time}")
    canvas.drawRightString(PAGE_W - MARGIN, 8.5 * mm, f"Page {doc.page}")

    canvas.restoreState()


# Styles
def _styles():
    return {
        "h1": ParagraphStyle("h1", fontName="Helvetica-Bold", fontSize=20,
            textColor=C_TEXT1, leading=26, spaceAfter=3),
        "h1sub": ParagraphStyle("h1sub", fontName="Helvetica", fontSize=8.5,
            textColor=C_TEXT3, leading=13),
        "section": ParagraphStyle("section", fontName="Helvetica-Bold", fontSize=8,
            textColor=C_ACCENT, leading=11, spaceAfter=4, spaceBefore=12, letterSpacing=0.8),
        "label": ParagraphStyle("label", fontName="Helvetica", fontSize=7.5,
            textColor=C_TEXT3, leading=11),
        "value": ParagraphStyle("value", fontName="Helvetica", fontSize=8.5,
            textColor=C_TEXT1, leading=12),
        "finding_text": ParagraphStyle("finding_text", fontName="Helvetica", fontSize=8.5,
            textColor=C_TEXT2, leading=13),
        "category": ParagraphStyle("category", fontName="Helvetica-Bold", fontSize=9,
            textColor=C_TEXT1, leading=13, spaceAfter=2),
        "rem_label": ParagraphStyle("rem_label", fontName="Helvetica-Bold", fontSize=6.5,
            textColor=C_TEXT3, leading=10, letterSpacing=0.8, spaceAfter=3),
        "rem_text": ParagraphStyle("rem_text", fontName="Helvetica", fontSize=8,
            textColor=C_TEXT2, leading=12),
        "footer_note": ParagraphStyle("footer_note", fontName="Helvetica", fontSize=7.5,
            textColor=C_TEXT3, leading=11),
    }


# Helpers
def _hr(story):
    story.append(HRFlowable(
        width="100%", thickness=0.75, color=C_BORDER,
        spaceAfter=6, spaceBefore=0
    ))


def _section_title(story, title, S):
    story.append(Paragraph(title.upper(), S["section"]))


def _kv_table(rows, S):
    data = [
        [Paragraph(k.upper(), S["label"]), Paragraph(str(v), S["value"])]
        for k, v in rows
    ]
    t = Table(data, colWidths=[52 * mm, CONTENT_W - 52 * mm], hAlign="LEFT")
    t.setStyle(TableStyle([
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [C_BG, C_CARD]),
        ("LINEBELOW",      (0, 0), (-1, -2), 0.4, C_BORDER),
        ("TOPPADDING",     (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 5),
        ("LEFTPADDING",    (0, 0), (0, -1),  0),
        ("LEFTPADDING",    (1, 0), (1, -1),  8),
        ("RIGHTPADDING",   (0, 0), (-1, -1), 6),
        ("VALIGN",         (0, 0), (-1, -1), "TOP"),
    ]))
    return t


def _risk_label(score):
    if score >= 7:   return "CRITICAL QUANTUM RISK", C_RED
    elif score >= 4: return "MODERATE QUANTUM RISK", C_AMBER
    else:            return "LOW QUANTUM RISK",      C_GREEN


def _assessment_view(report: dict) -> tuple[dict, dict, list, list, list, dict]:
    inventory       = report.get("inventory", report)
    risk            = report.get("quantum_risk", inventory.get("quantum_risk", {}))
    findings        = report.get("findings", risk.get("findings", []))
    remediation     = report.get("remediation", [])
    nist_references = report.get("nist_references", [])
    cbom            = report.get("cbom", {"entries": [], "summary": {}})
    return inventory, risk, findings, remediation, nist_references, cbom


# Main generator
def generate_pdf_report(report: dict, output_path: str = None) -> bytes:
    buf       = BytesIO()
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    inventory, risk, findings, remediation, nist_references, cbom = _assessment_view(report)
    target_label = str(report.get("target", inventory.get("target", "Unknown Target")))

    def on_page(canvas, doc):
        _page_decorator(canvas, doc, target=target_label, scan_time=scan_time)

    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=18 * mm, bottomMargin=18 * mm,
        title=f"CypherQube Report — {target_label}",
        author="CypherQube Scanner",
    )

    S     = _styles()
    story = []

    #Cover block
    story.append(Spacer(1, 6 * mm))
    story.append(Paragraph("Quantum Risk Assessment Report", S["h1"]))
    story.append(Spacer(1, 2 * mm))
    story.append(Paragraph(
        f"Target: {target_label}  ·  Scanned: {scan_time}", S["h1sub"]
    ))
    story.append(Spacer(1, 5 * mm))
    _hr(story)

    # Risk score summary
    score    = float(risk.get("risk_score") or 0)
    badge_data = report.get("badge")
    badge = (
        determine_badge(int(badge_data.get("score", score)), target_label)
        if badge_data else
        determine_badge(int(score), target_label)
    )
    rlabel, rcolor = _risk_label(score)

    n_crit = len([f for f in findings if f.get("severity") in ("CRITICAL", "HIGH")])
    n_med  = len([f for f in findings if f.get("severity") == "MEDIUM"])
    n_info = len([f for f in findings if f.get("severity") == "INFO"])

    score_style    = ParagraphStyle("sc", fontName="Helvetica-Bold", fontSize=36,
                        textColor=rcolor, leading=42)
    risk_lbl_style = ParagraphStyle("rl", fontName="Helvetica-Bold", fontSize=9,
                        textColor=rcolor, leading=14)
    counts_style   = ParagraphStyle("cs", fontName="Helvetica", fontSize=7.5,
                        textColor=C_TEXT3, leading=11)

    summary = Table([[
        Paragraph(f"{score}/10", score_style),
        Table(
            [[Paragraph(rlabel, risk_lbl_style)],
             [Paragraph(
                 f"{n_crit} critical/high  ·  {n_med} medium  ·  {n_info} informational",
                 counts_style
             )]],
            colWidths=[CONTENT_W - 36 * mm], hAlign="LEFT"
        )
    ]], colWidths=[36 * mm, CONTENT_W - 36 * mm], hAlign="LEFT")

    summary.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), C_CARD),
        ("BOX",           (0, 0), (-1, -1), 0.75, C_BORDER),
        ("LINEBEFORE",    (0, 0), (0, -1),  3,    rcolor),
        ("LEFTPADDING",   (0, 0), (-1, -1), 12),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 12),
        ("TOPPADDING",    (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(summary)
    story.append(Spacer(1, 6 * mm))

    # Badge
    _section_title(story, "Quantum Certification", S)
    _hr(story)
    story.append(Paragraph(f"<b>{badge.label}</b> — {badge.sublabel}", S["value"]))
    story.append(Spacer(1, 5 * mm))

    # TLS Configuration
    _section_title(story, "TLS Configuration", S)
    _hr(story)
    story.append(_kv_table([
        ("TLS Version",   inventory.get("tls_version",  "—")),
        ("Cipher Suite",  inventory.get("cipher_suite", "—")),
        ("Key Exchange",  inventory.get("key_exchange", "—")),
        ("Hash Function", inventory.get("hash_function", "—")),
        ("TLS Signature", inventory.get("tls_signature", "—")),
    ], S))
    story.append(Spacer(1, 5 * mm))

    # Certificate Details
    _section_title(story, "Certificate Details", S)
    _hr(story)
    cert = inventory.get("certificate", {})
    story.append(_kv_table([
        ("Public Key Algorithm", cert.get("public_key_algorithm", "—")),
        ("Key Size",             f"{cert.get('key_size', '—')} bits"),
        ("Signature Algorithm",  cert.get("signature_algorithm", "—")),
        ("Issuer",               cert.get("issuer", "—")),
        ("Expiry",               cert.get("expiry", "—")),
    ], S))
    story.append(Spacer(1, 5 * mm))

    # Findings
    _section_title(story, f"Quantum Risk Findings  ({len(findings)})", S)
    _hr(story)

    if not findings:
        story.append(Paragraph(
            "No quantum vulnerabilities detected. Configuration appears post-quantum safe.",
            S["finding_text"]
        ))
    else:
        for f in findings:
            sev      = f.get("severity", "INFO")
            category = f.get("category", "")
            finding  = f.get("finding", "")
            rem      = f.get("remediation", "")
            sev_c    = SEV_COLOR.get(sev, C_TEXT3)
            sev_bg   = SEV_BG.get(sev, C_CARD)

            # Severity pill — tinted background, coloured text
            pill = Table([[sev]], colWidths=[18 * mm], rowHeights=[5 * mm])
            pill.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), sev_bg),
                ("TEXTCOLOR",     (0, 0), (-1, -1), sev_c),
                ("FONTNAME",      (0, 0), (-1, -1), "Helvetica-Bold"),
                ("FONTSIZE",      (0, 0), (-1, -1), 6.5),
                ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
                ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
                ("BOX",           (0, 0), (-1, -1), 0.5, sev_c),
                ("TOPPADDING",    (0, 0), (-1, -1), 1),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
            ]))

            header = Table(
                [[pill, Paragraph(category, S["category"])]],
                colWidths=[22 * mm, CONTENT_W - 22 * mm - 20], hAlign="LEFT"
            )
            header.setStyle(TableStyle([
                ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
                ("BACKGROUND",    (0, 0), (-1, -1), C_BG),
                ("LEFTPADDING",   (0, 0), (-1, -1), 0),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
                ("TOPPADDING",    (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))

            rem_block = Table(
                [[Paragraph("REMEDIATION", S["rem_label"])],
                 [Paragraph(rem, S["rem_text"])]],
                colWidths=[CONTENT_W - 20], hAlign="LEFT"
            )
            rem_block.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), C_CARD),
                ("LINEABOVE",     (0, 0), (-1, 0),  0.5, C_BORDER),
                ("LEFTPADDING",   (0, 0), (-1, -1), 10),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
                ("TOPPADDING",    (0, 0), (0, 0),   6),
                ("TOPPADDING",    (0, 1), (0, 1),   2),
                ("BOTTOMPADDING", (0, -1), (-1, -1), 8),
            ]))

            card = Table(
                [[header],
                 [Paragraph(finding, S["finding_text"])],
                 [rem_block]],
                colWidths=[CONTENT_W], hAlign="LEFT"
            )
            card.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), C_BG),
                ("BOX",           (0, 0), (-1, -1), 0.75, C_BORDER),
                ("LINEBEFORE",    (0, 0), (0, -1),  3,    sev_c),
                ("LEFTPADDING",   (0, 0), (-1, 1),  12),
                ("LEFTPADDING",   (0, 2), (-1, 2),  0),
                ("RIGHTPADDING",  (0, 0), (-1, 1),  12),
                ("RIGHTPADDING",  (0, 2), (-1, 2),  0),
                ("TOPPADDING",    (0, 0), (-1, 0),  10),
                ("TOPPADDING",    (0, 1), (-1, 1),  4),
                ("TOPPADDING",    (0, 2), (-1, 2),  0),
                ("BOTTOMPADDING", (0, 1), (-1, 1),  8),
                ("BOTTOMPADDING", (0, 2), (-1, 2),  0),
                ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ]))

            story.append(KeepTogether([card, Spacer(1, 6)]))

    #  Actionable Remediation
    if remediation:
        _section_title(story, f"Actionable Remediation  ({len(remediation)})", S)
        _hr(story)
        for item in remediation:
            refs = ", ".join(ref["id"] for ref in item.get("nist_references", [])) or "General guidance"
            story.append(_kv_table([
                ("Component",           item.get("component", "Unknown")),
                ("Priority",            item.get("priority", "UNKNOWN")),
                ("Action",              item.get("recommended_action", "Manual review required")),
                ("Implementation Hint", item.get("implementation_hint", "Review and migrate as needed")),
                ("NIST Reference",      refs),
            ], S))
            story.append(Spacer(1, 3 * mm))

    # NIST PQC References
    if nist_references:
        _section_title(story, "NIST PQC Standards", S)
        _hr(story)
        story.append(_kv_table([
            (ref.get("id", ""), f"{ref.get('name', '')}  {ref.get('url', '')}")
            for ref in nist_references
        ], S))
        story.append(Spacer(1, 5 * mm))

    # CBOM
    if cbom.get("entries"):
        _section_title(story, "CBOM Summary", S)
        _hr(story)
        cbom_summary = cbom.get("summary", {})
        story.append(_kv_table([
            ("Total Assets",    cbom_summary.get("total_assets", 0)),
            ("Quantum Safe",    cbom_summary.get("quantum_safe", 0)),
            ("Not Quantum Safe",cbom_summary.get("not_quantum_safe", 0)),
            ("Risk Ratio",      cbom_summary.get("risk_ratio", "0/0")),
        ], S))
        story.append(Spacer(1, 3 * mm))
        first_entry = cbom["entries"][0]
        story.append(_kv_table([
            ("Protocol",               first_entry.get("protocol", "HTTPS")),
            ("TLS Signature",          first_entry.get("tls_signature", "—")),
            ("Certificate Signature",  first_entry.get("certificate_signature_algorithm", "—")),
            ("Hash Function",          first_entry.get("hash_function", "—")),
            ("PQC Readiness",          first_entry.get("pqc_readiness", "Unknown")),
        ], S))

    #Disclaimer
    story.append(Spacer(1, 6 * mm))
    _hr(story)
    story.append(Paragraph(
        "This report was generated automatically by CypherQube. Risk scores are based on known "
        "post-quantum cryptography vulnerabilities per NIST PQC standards (FIPS 203/204/205/206). "
        "This is not a substitute for a full security audit.",
        S["footer_note"]
    ))

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)

    pdf_bytes = buf.getvalue()
    if output_path:
        with open(output_path, "wb") as fh:
            fh.write(pdf_bytes)
        print(f"\nPDF report saved to {output_path}")

    return pdf_bytes