"""
pdf_report.py — CypherQube PDF Report Generator
Uses reportlab Platypus with onPage callbacks so the dark background
is painted BEFORE content, not after (which caused the blank PDF).
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


C_BG     = HexColor("#141414")
C_CARD   = HexColor("#1c1c1c")
C_BORDER = HexColor("#333333")
C_TEXT1  = HexColor("#e8e8e8")
C_TEXT2  = HexColor("#a0a0a0")
C_TEXT3  = HexColor("#606060")
C_RED    = HexColor("#e05252")
C_AMBER  = HexColor("#d4903a")
C_GREEN  = HexColor("#52a878")
C_BLUE   = HexColor("#5b8db8")
C_WHITE  = HexColor("#ffffff")

SEV_COLOR = {
    "CRITICAL": C_RED,
    "HIGH":     C_RED,
    "MEDIUM":   C_AMBER,
    "LOW":      C_GREEN,
    "INFO":     C_BLUE,
}

PAGE_W, PAGE_H = A4
MARGIN = 20 * mm
CONTENT_W = PAGE_W - 2 * MARGIN


def _page_decorator(canvas, doc, target="", scan_time=""):
    canvas.saveState()
    canvas.setFillColor(C_BG)
    canvas.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)
    canvas.setFillColor(C_CARD)
    canvas.rect(0, PAGE_H - 13 * mm, PAGE_W, 13 * mm, fill=1, stroke=0)
    canvas.setStrokeColor(C_BORDER)
    canvas.setLineWidth(0.5)
    canvas.line(0, PAGE_H - 13 * mm, PAGE_W, PAGE_H - 13 * mm)
    canvas.setFillColor(C_TEXT1)
    canvas.setFont("Helvetica-Bold", 9)
    canvas.drawString(MARGIN, PAGE_H - 8.5 * mm, "CYPHERCUBE")
    canvas.setFillColor(C_TEXT3)
    canvas.setFont("Helvetica", 7)
    canvas.drawString(MARGIN + 54, PAGE_H - 8.5 * mm, "TLS / QUANTUM RISK SCANNER")
    canvas.setFillColor(C_TEXT2)
    canvas.setFont("Courier", 7)
    canvas.drawRightString(PAGE_W - MARGIN, PAGE_H - 8.5 * mm, str(target))
    canvas.setStrokeColor(C_BORDER)
    canvas.setLineWidth(0.4)
    canvas.line(MARGIN, 12 * mm, PAGE_W - MARGIN, 12 * mm)
    canvas.setFillColor(C_TEXT3)
    canvas.setFont("Courier", 6.5)
    canvas.drawString(MARGIN, 8 * mm, f"Generated: {scan_time}")
    canvas.drawRightString(PAGE_W - MARGIN, 8 * mm, f"Page {doc.page}")
    canvas.restoreState()


def _styles():
    return {
        "h1": ParagraphStyle("h1", fontName="Helvetica-Bold", fontSize=22,
            textColor=C_TEXT1, leading=28, spaceAfter=3),
        "h1sub": ParagraphStyle("h1sub", fontName="Helvetica", fontSize=8.5,
            textColor=C_TEXT3, leading=13),
        "section": ParagraphStyle("section", fontName="Courier", fontSize=7,
            textColor=C_TEXT3, leading=10, spaceAfter=5, spaceBefore=12, letterSpacing=1.5),
        "label": ParagraphStyle("label", fontName="Courier", fontSize=7,
            textColor=C_TEXT3, leading=10),
        "value": ParagraphStyle("value", fontName="Courier", fontSize=8.5,
            textColor=C_TEXT1, leading=12),
        "finding_text": ParagraphStyle("finding_text", fontName="Helvetica", fontSize=8.5,
            textColor=C_TEXT2, leading=13),
        "category": ParagraphStyle("category", fontName="Helvetica-Bold", fontSize=9,
            textColor=C_TEXT1, leading=13, spaceAfter=2),
        "rem_label": ParagraphStyle("rem_label", fontName="Courier", fontSize=6.5,
            textColor=C_TEXT3, leading=10, letterSpacing=1.2, spaceAfter=3),
        "rem_text": ParagraphStyle("rem_text", fontName="Helvetica", fontSize=8,
            textColor=C_TEXT2, leading=12),
        "footer_note": ParagraphStyle("footer_note", fontName="Helvetica", fontSize=7.5,
            textColor=C_TEXT3, leading=11),
    }


def _hr(story):
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=6, spaceBefore=0))


def _section_title(story, title, S):
    story.append(Paragraph(f"// {title}", S["section"]))


def _kv_table(rows, S):
    data = [
        [Paragraph(k.upper(), S["label"]), Paragraph(str(v), S["value"])]
        for k, v in rows
    ]
    t = Table(data, colWidths=[52 * mm, CONTENT_W - 52 * mm], hAlign="LEFT")
    t.setStyle(TableStyle([
        ("ROWBACKGROUNDS", (0,0), (-1,-1), [C_BG, HexColor("#181818")]),
        ("LINEBELOW",      (0,0), (-1,-2), 0.4, C_BORDER),
        ("TOPPADDING",     (0,0), (-1,-1), 5),
        ("BOTTOMPADDING",  (0,0), (-1,-1), 5),
        ("LEFTPADDING",    (0,0), (0,-1),  0),
        ("LEFTPADDING",    (1,0), (1,-1),  8),
        ("RIGHTPADDING",   (0,0), (-1,-1), 6),
        ("VALIGN",         (0,0), (-1,-1), "TOP"),
    ]))
    return t


def _risk_label(score):
    if score >= 7:   return "CRITICAL QUANTUM RISK", C_RED
    elif score >= 4: return "MODERATE QUANTUM RISK", C_AMBER
    else:            return "LOW QUANTUM RISK",      C_GREEN


def _assessment_view(report: dict) -> tuple[dict, dict, list, list, list, dict]:
    inventory = report.get("inventory", report)
    risk = report.get("quantum_risk", inventory.get("quantum_risk", {}))
    findings = report.get("findings", risk.get("findings", []))
    remediation = report.get("remediation", [])
    nist_references = report.get("nist_references", [])
    cbom = report.get("cbom", {"entries": [], "summary": {}})
    return inventory, risk, findings, remediation, nist_references, cbom


def generate_pdf_report(report: dict, output_path: str = None) -> bytes:
    buf = BytesIO()
    scan_time    = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    inventory, risk, findings, remediation, nist_references, cbom = _assessment_view(report)
    target_label = str(report.get("target", inventory.get("target", "Unknown Target")))

    def on_page(canvas, doc):
        _page_decorator(canvas, doc, target=target_label, scan_time=scan_time)

    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=17 * mm, bottomMargin=17 * mm,
        title=f"CypherQube Report — {target_label}",
        author="CypherQube Scanner",
    )

    S = _styles()
    story = []

    story.append(Spacer(1, 6 * mm))
    story.append(Paragraph("Quantum Risk Assessment Report", S["h1"]))
    story.append(Spacer(1, 2 * mm))
    story.append(Paragraph(f"Target: {target_label}  ·  Scanned: {scan_time}", S["h1sub"]))
    story.append(Spacer(1, 5 * mm))
    _hr(story)

    score    = float(risk.get("risk_score") or 0)
    badge_data = report.get("badge")
    badge = determine_badge(int(score), target_label) if not badge_data else determine_badge(int(badge_data.get("score", score)), target_label)
    rlabel, rcolor = _risk_label(score)

    n_crit = len([f for f in findings if f.get("severity") in ("CRITICAL","HIGH")])
    n_med  = len([f for f in findings if f.get("severity") == "MEDIUM"])
    n_info = len([f for f in findings if f.get("severity") == "INFO"])

    score_style   = ParagraphStyle("sc", fontName="Helvetica-Bold", fontSize=38, textColor=rcolor, leading=44)
    risk_lbl_style= ParagraphStyle("rl", fontName="Helvetica",      fontSize=9,  textColor=rcolor, leading=14)
    counts_style  = ParagraphStyle("cs", fontName="Courier",         fontSize=7,  textColor=C_TEXT3, leading=11)

    summary = Table([[
        Paragraph(f"{score}/10", score_style),
        Table(
            [[Paragraph(rlabel, risk_lbl_style)],
             [Paragraph(f"{n_crit} critical/high  ·  {n_med} medium  ·  {n_info} informational", counts_style)]],
            colWidths=[CONTENT_W - 36 * mm], hAlign="LEFT"
        )
    ]], colWidths=[36 * mm, CONTENT_W - 36 * mm], hAlign="LEFT")
    summary.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), C_CARD),
        ("BOX",           (0,0), (-1,-1), 0.5, C_BORDER),
        ("LEFTPADDING",   (0,0), (-1,-1), 10),
        ("RIGHTPADDING",  (0,0), (-1,-1), 10),
        ("TOPPADDING",    (0,0), (-1,-1), 10),
        ("BOTTOMPADDING", (0,0), (-1,-1), 10),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
    ]))
    story.append(summary)
    story.append(Spacer(1, 6 * mm))

    _section_title(story, "Quantum Certification", S)
    _hr(story)

    story.append(Paragraph(
        f"<b>{badge.label}</b> — {badge.sublabel}",
        S["value"]
    ))
    story.append(Spacer(1, 5 * mm))

    _section_title(story, "TLS Configuration", S)
    _hr(story)
    story.append(_kv_table([
        ("TLS Version",   inventory.get("tls_version",  "—")),
        ("Cipher Suite",  inventory.get("cipher_suite", "—")),
        ("Key Exchange",  inventory.get("key_exchange", "—")),
        ("Hash Function", inventory.get("hash_function","—")),
        ("TLS Signature", inventory.get("tls_signature","—")),
    ], S))
    story.append(Spacer(1, 5 * mm))

    _section_title(story, "Certificate Details", S)
    _hr(story)
    cert = inventory.get("certificate", {})
    story.append(_kv_table([
        ("Public Key Algorithm", cert.get("public_key_algorithm","—")),
        ("Key Size",             f"{cert.get('key_size','—')} bits"),
        ("Signature Algorithm",  cert.get("signature_algorithm", "—")),
        ("Issuer",               cert.get("issuer", "—")),
        ("Expiry",               cert.get("expiry", "—")),
    ], S))
    story.append(Spacer(1, 5 * mm))

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
            finding  = f.get("finding",  "")
            rem      = f.get("remediation", "")
            sev_c    = SEV_COLOR.get(sev, C_TEXT3)

            pill = Table([[sev]], colWidths=[18*mm], rowHeights=[5*mm])
            pill.setStyle(TableStyle([
                ("BACKGROUND",    (0,0),(-1,-1), sev_c),
                ("TEXTCOLOR",     (0,0),(-1,-1), C_WHITE),
                ("FONTNAME",      (0,0),(-1,-1), "Courier-Bold"),
                ("FONTSIZE",      (0,0),(-1,-1), 6.5),
                ("ALIGN",         (0,0),(-1,-1), "CENTER"),
                ("VALIGN",        (0,0),(-1,-1), "MIDDLE"),
                ("TOPPADDING",    (0,0),(-1,-1), 1),
                ("BOTTOMPADDING", (0,0),(-1,-1), 1),
            ]))

            header = Table(
                [[pill, Paragraph(category, S["category"])]],
                colWidths=[22*mm, CONTENT_W - 22*mm - 20], hAlign="LEFT"
            )
            header.setStyle(TableStyle([
                ("VALIGN",        (0,0),(-1,-1), "MIDDLE"),
                ("BACKGROUND",    (0,0),(-1,-1), C_CARD),
                ("LEFTPADDING",   (0,0),(-1,-1), 0),
                ("RIGHTPADDING",  (0,0),(-1,-1), 0),
                ("TOPPADDING",    (0,0),(-1,-1), 0),
                ("BOTTOMPADDING", (0,0),(-1,-1), 4),
            ]))

            rem_block = Table(
                [[Paragraph("REMEDIATION", S["rem_label"])],
                 [Paragraph(rem, S["rem_text"])]],
                colWidths=[CONTENT_W - 20], hAlign="LEFT"
            )
            rem_block.setStyle(TableStyle([
                ("BACKGROUND",    (0,0),(-1,-1), HexColor("#202020")),
                ("LINEABOVE",     (0,0),(-1, 0), 0.4, C_BORDER),
                ("LEFTPADDING",   (0,0),(-1,-1), 8),
                ("RIGHTPADDING",  (0,0),(-1,-1), 8),
                ("TOPPADDING",    (0,0),( 0, 0), 6),
                ("TOPPADDING",    (0,1),( 0, 1), 2),
                ("BOTTOMPADDING", (0,-1),(-1,-1),8),
            ]))

            card = Table(
                [[header],
                 [Paragraph(finding, S["finding_text"])],
                 [rem_block]],
                colWidths=[CONTENT_W], hAlign="LEFT"
            )
            card.setStyle(TableStyle([
                ("BACKGROUND",    (0,0),(-1,-1), C_CARD),
                ("BOX",           (0,0),(-1,-1), 0.5, C_BORDER),
                ("LINEBEFORE",    (0,0),( 0,-1), 2.5, sev_c),
                ("LEFTPADDING",   (0,0),(-1, 1), 10),
                ("LEFTPADDING",   (0,2),(-1, 2), 0),
                ("RIGHTPADDING",  (0,0),(-1, 1), 10),
                ("RIGHTPADDING",  (0,2),(-1, 2), 0),
                ("TOPPADDING",    (0,0),(-1, 0), 8),
                ("TOPPADDING",    (0,1),(-1, 1), 3),
                ("TOPPADDING",    (0,2),(-1, 2), 0),
                ("BOTTOMPADDING", (0,1),(-1, 1), 6),
                ("BOTTOMPADDING", (0,2),(-1, 2), 0),
                ("VALIGN",        (0,0),(-1,-1), "TOP"),
            ]))

            story.append(KeepTogether([card, Spacer(1, 5)]))

    if remediation:
        _section_title(story, f"Actionable Remediation  ({len(remediation)})", S)
        _hr(story)
        for item in remediation:
            refs = ", ".join(ref["id"] for ref in item.get("nist_references", [])) or "General guidance"
            story.append(_kv_table([
                ("Component", item.get("component", "Unknown")),
                ("Priority", item.get("priority", "UNKNOWN")),
                ("Action", item.get("recommended_action", "Manual review required")),
                ("Implementation Hint", item.get("implementation_hint", "Review and migrate as needed")),
                ("NIST Reference", refs),
            ], S))
            story.append(Spacer(1, 3 * mm))

    if nist_references:
        _section_title(story, "NIST PQC Standards", S)
        _hr(story)
        story.append(_kv_table([
            (ref.get("id", ""), f"{ref.get('name', '')}  {ref.get('url', '')}")
            for ref in nist_references
        ], S))
        story.append(Spacer(1, 5 * mm))

    if cbom.get("entries"):
        _section_title(story, "CBOM Summary", S)
        _hr(story)
        summary = cbom.get("summary", {})
        story.append(_kv_table([
            ("Total Assets", summary.get("total_assets", 0)),
            ("Quantum Safe", summary.get("quantum_safe", 0)),
            ("Not Quantum Safe", summary.get("not_quantum_safe", 0)),
            ("Risk Ratio", summary.get("risk_ratio", "0/0")),
        ], S))
        story.append(Spacer(1, 3 * mm))
        first_entry = cbom["entries"][0]
        story.append(_kv_table([
            ("Protocol", first_entry.get("protocol", "HTTPS")),
            ("TLS Signature", first_entry.get("tls_signature", "—")),
            ("Certificate Signature", first_entry.get("certificate_signature_algorithm", "—")),
            ("Hash Function", first_entry.get("hash_function", "—")),
            ("PQC Readiness", first_entry.get("pqc_readiness", "Unknown")),
        ], S))

    story.append(Spacer(1, 5 * mm))
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
