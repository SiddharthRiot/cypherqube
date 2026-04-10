"""
core/badge.py — CypherQube Badge Generator

Badge Types:
  - FULLY_QUANTUM_SAFE  : Risk score 0     → Green  "Fully Quantum Safe"
  - PQC_READY           : Risk score 1–3   → Teal   "PQC Ready"
  - PARTIAL_RISK        : Risk score 4–6   → Amber  "Partial Quantum Risk"
  - VULNERABLE          : Risk score 7–10  → Red    "Quantum Vulnerable"
"""

from dataclasses import dataclass
from datetime import UTC, datetime

BADGE_FULLY_QUANTUM_SAFE = "FULLY_QUANTUM_SAFE"
BADGE_PQC_READY          = "PQC_READY"
BADGE_PARTIAL_RISK       = "PARTIAL_RISK"
BADGE_VULNERABLE         = "VULNERABLE"


BADGE_META = {
    BADGE_FULLY_QUANTUM_SAFE: {
        "label":       "Fully Quantum Safe",
        "sublabel":    "NIST PQC Compliant",
        "icon":        "✦",
        "color_fill":  "#dcfce7",
        "color_stroke":"#16a34a",
        "color_text":  "#14532d",
        "color_icon":  "#16a34a",
        "score_range": "0",
        "description": (
            "This asset uses NIST-standardised post-quantum algorithms across all "
            "cryptographic components. It is shielded against Shor's and Grover's "
            "quantum attacks."
        ),
    },
    BADGE_PQC_READY: {
        "label":       "PQC Ready",
        "sublabel":    "Post-Quantum Capable",
        "icon":        "◈",
        "color_fill":  "#e0f2fe",
        "color_stroke":"#0284c7",
        "color_text":  "#0c4a6e",
        "color_icon":  "#0284c7",
        "score_range": "1–3",
        "description": (
            "This asset has low quantum exposure. Minor components may need attention, "
            "but the core cryptographic posture is post-quantum capable."
        ),
    },
    BADGE_PARTIAL_RISK: {
        "label":       "Partial Quantum Risk",
        "sublabel":    "Migration Recommended",
        "icon":        "⚠",
        "color_fill":  "#fef9c3",
        "color_stroke":"#ca8a04",
        "color_text":  "#713f12",
        "color_icon":  "#ca8a04",
        "score_range": "4–6",
        "description": (
            "This asset has moderate quantum exposure. A structured migration plan "
            "to NIST PQC standards is recommended within the next refresh cycle."
        ),
    },
    BADGE_VULNERABLE: {
        "label":       "Quantum Vulnerable",
        "sublabel":    "Immediate Action Required",
        "icon":        "✕",
        "color_fill":  "#fee2e2",
        "color_stroke":"#dc2626",
        "color_text":  "#7f1d1d",
        "color_icon":  "#dc2626",
        "score_range": "7–10",
        "description": (
            "This asset uses cryptographic algorithms that are vulnerable to quantum attacks. "
            "Immediate migration to NIST PQC standards is strongly recommended to protect "
            "against 'harvest now, decrypt later' threats."
        ),
    },
}


@dataclass
class Badge:
    badge_type:   str
    label:        str
    sublabel:     str
    icon:         str
    score:        int
    score_range:  str
    description:  str
    target:       str
    issued_at:    str
    color_fill:   str
    color_stroke: str
    color_text:   str
    color_icon:   str

    def is_safe(self) -> bool:
        """True iff badge is FULLY_QUANTUM_SAFE ya PQC_READY."""
        return self.badge_type in (BADGE_FULLY_QUANTUM_SAFE, BADGE_PQC_READY)

    def is_critical(self) -> bool:
        """True iff badge is VULNERABLE."""
        return self.badge_type == BADGE_VULNERABLE

    def to_dict(self) -> dict:
        return {
            "badge_type":  self.badge_type,
            "label":       self.label,
            "sublabel":    self.sublabel,
            "score":       self.score,
            "score_range": self.score_range,
            "description": self.description,
            "target":      self.target,
            "issued_at":   self.issued_at,
        }


def determine_badge(risk_score: int, target: str = "") -> Badge:
    """
    Risk score ke basis pe correct badge return karta hai.

    Args:
        risk_score : Integer 0–10 (risk_engine se aata hai)
        target     : Target host string (e.g. "api.example.com:443")

    Returns:
        Badge dataclass instance
    """
    score = max(0, min(10, int(risk_score)))

    if score == 0:
        badge_type = BADGE_FULLY_QUANTUM_SAFE
    elif score <= 3:
        badge_type = BADGE_PQC_READY
    elif score <= 6:
        badge_type = BADGE_PARTIAL_RISK
    else:
        badge_type = BADGE_VULNERABLE

    meta = BADGE_META[badge_type]

    return Badge(
        badge_type   = badge_type,
        label        = meta["label"],
        sublabel     = meta["sublabel"],
        icon         = meta["icon"],
        score        = score,
        score_range  = meta["score_range"],
        description  = meta["description"],
        target       = target,
        issued_at    = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        color_fill   = meta["color_fill"],
        color_stroke = meta["color_stroke"],
        color_text   = meta["color_text"],
        color_icon   = meta["color_icon"],
    )


def generate_svg_badge(badge: Badge, width: int = 320) -> str:
    """
    Badge ke liye SVG string generate karta hai.
    Streamlit mein st.markdown(..., unsafe_allow_html=True) se render hoga.

    Args:
        badge : Badge dataclass instance
        width : SVG width in pixels (default 320)

    Returns:
        SVG string
    """
    height   = 100
    icon_x   = 28
    icon_y   = 50
    text_x   = 56
    label_y  = 38
    sub_y    = 56
    score_x  = width - 28
    score_y  = 38
    date_y   = 72

    svg = f"""<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}"
    xmlns="http://www.w3.org/2000/svg" role="img"
    aria-label="CypherQube Badge: {badge.label} for {badge.target}">

  <!-- Background -->
  <rect x="1" y="1" width="{width-2}" height="{height-2}" rx="10"
        fill="{badge.color_fill}" stroke="{badge.color_stroke}" stroke-width="1.5"/>

  <!-- Left accent bar -->
  <rect x="1" y="1" width="5" height="{height-2}" rx="3"
        fill="{badge.color_stroke}" stroke="none"/>

  <!-- Icon -->
  <text x="{icon_x}" y="{icon_y}" font-family="Arial, sans-serif"
        font-size="22" fill="{badge.color_icon}"
        text-anchor="middle" dominant-baseline="central">{badge.icon}</text>

  <!-- Label -->
  <text x="{text_x}" y="{label_y}" font-family="Arial, sans-serif"
        font-size="14" font-weight="700" fill="{badge.color_text}">{badge.label}</text>

  <!-- Sub-label -->
  <text x="{text_x}" y="{sub_y}" font-family="Arial, sans-serif"
        font-size="10" fill="{badge.color_stroke}">{badge.sublabel}</text>

  <!-- Score pill (right side) -->
  <rect x="{score_x - 36}" y="18" width="48" height="26" rx="13"
        fill="{badge.color_stroke}" opacity="0.15"/>
  <text x="{score_x - 12}" y="{score_y}" font-family="Arial, sans-serif"
        font-size="13" font-weight="700" fill="{badge.color_stroke}"
        text-anchor="middle" dominant-baseline="central">{badge.score}/10</text>

  <!-- Divider -->
  <line x1="{text_x}" y1="64" x2="{width - 20}" y2="64"
        stroke="{badge.color_stroke}" stroke-width="0.5" opacity="0.3"/>

  <!-- Issued date + target -->
  <text x="{text_x}" y="{date_y + 10}" font-family="Arial, sans-serif"
        font-size="9" fill="{badge.color_stroke}" opacity="0.7">
    Issued: {badge.issued_at}  ·  {badge.target}
  </text>

  <!-- CypherQube watermark -->
  <text x="{width - 20}" y="{height - 10}" font-family="Arial, sans-serif"
        font-size="8" fill="{badge.color_stroke}" opacity="0.4"
        text-anchor="end">CypherQube v2.1.0</text>
</svg>"""

    return svg


def generate_inline_badge_html(badge: Badge) -> str:
    """
    Ek chhoti si inline HTML badge generate karta hai.
    Streamlit metric cards ya findings panel ke andar use hoga.

    Returns:
        HTML string (single div)
    """
    return f"""
<div style="
    display: inline-flex;
    align-items: center;
    gap: 8px;
    background: {badge.color_fill};
    border: 1.5px solid {badge.color_stroke};
    border-radius: 20px;
    padding: 5px 14px 5px 10px;
    font-family: Arial, sans-serif;
">
    <span style="font-size: 14px; color: {badge.color_icon};">{badge.icon}</span>
    <span style="font-size: 12px; font-weight: 700; color: {badge.color_text};">
        {badge.label}
    </span>
    <span style="
        font-size: 10px;
        font-weight: 600;
        color: {badge.color_stroke};
        background: white;
        border: 1px solid {badge.color_stroke};
        border-radius: 10px;
        padding: 1px 7px;
        opacity: 0.85;
    ">{badge.score}/10</span>
</div>"""


def generate_certificate_html(badge: Badge) -> str:
    """
    Ek poora "PQC Certificate" card generate karta hai —
    Hackathon mein yahi sabse zyada impress karega.

    Returns:
        HTML string
    """
    is_safe    = badge.is_safe()
    is_vuln    = badge.is_critical()

    check_icon = "✓" if is_safe else ("✕" if is_vuln else "⚠")

    return f"""
<div style="
    background: {badge.color_fill};
    border: 2px solid {badge.color_stroke};
    border-radius: 12px;
    padding: 24px 28px;
    font-family: Arial, sans-serif;
    position: relative;
    overflow: hidden;
    margin-bottom: 16px;
">
    <!-- Decorative background watermark -->
    <div style="
        position: absolute;
        right: 20px;
        top: 50%;
        transform: translateY(-50%);
        font-size: 80px;
        color: {badge.color_stroke};
        opacity: 0.06;
        font-weight: 900;
        pointer-events: none;
        user-select: none;
        line-height: 1;
    ">{check_icon}</div>

    <!-- Header row -->
    <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 16px;">
        <div style="
            width: 40px; height: 40px;
            background: {badge.color_stroke};
            border-radius: 50%;
            display: flex; align-items: center; justify-content: center;
            font-size: 18px; color: white; font-weight: bold;
            flex-shrink: 0;
        ">{check_icon}</div>
        <div>
            <div style="font-size: 18px; font-weight: 700; color: {badge.color_text}; line-height: 1.2;">
                {badge.label}
            </div>
            <div style="font-size: 11px; color: {badge.color_stroke}; font-weight: 600;
                        text-transform: uppercase; letter-spacing: 0.08em; margin-top: 2px;">
                {badge.sublabel}
            </div>
        </div>
        <!-- Score pill -->
        <div style="margin-left: auto; text-align: center;">
            <div style="
                font-size: 28px; font-weight: 700; color: {badge.color_stroke};
                line-height: 1;
            ">{badge.score}<span style="font-size: 14px; font-weight: 400; color: {badge.color_stroke}; opacity: 0.6;">/10</span></div>
            <div style="font-size: 9px; color: {badge.color_stroke}; opacity: 0.7;
                        text-transform: uppercase; letter-spacing: 0.1em;">Risk Score</div>
        </div>
    </div>

    <!-- Divider -->
    <div style="border-top: 1px solid {badge.color_stroke}; opacity: 0.2; margin-bottom: 14px;"></div>

    <!-- Description -->
    <div style="font-size: 13px; color: {badge.color_text}; line-height: 1.6;
                margin-bottom: 16px; opacity: 0.9;">
        {badge.description}
    </div>

    <!-- Meta row -->
    <div style="display: flex; gap: 24px; flex-wrap: wrap;">
        <div>
            <div style="font-size: 9px; text-transform: uppercase; letter-spacing: 0.1em;
                        color: {badge.color_stroke}; opacity: 0.6; margin-bottom: 2px;">Target</div>
            <div style="font-size: 12px; font-weight: 600; color: {badge.color_text}; font-family: monospace;">
                {badge.target or "—"}
            </div>
        </div>
        <div>
            <div style="font-size: 9px; text-transform: uppercase; letter-spacing: 0.1em;
                        color: {badge.color_stroke}; opacity: 0.6; margin-bottom: 2px;">Score Range</div>
            <div style="font-size: 12px; font-weight: 600; color: {badge.color_text};">{badge.score_range}</div>
        </div>
        <div>
            <div style="font-size: 9px; text-transform: uppercase; letter-spacing: 0.1em;
                        color: {badge.color_stroke}; opacity: 0.6; margin-bottom: 2px;">Issued</div>
            <div style="font-size: 12px; font-weight: 600; color: {badge.color_text};">{badge.issued_at}</div>
        </div>
        <div>
            <div style="font-size: 9px; text-transform: uppercase; letter-spacing: 0.1em;
                        color: {badge.color_stroke}; opacity: 0.6; margin-bottom: 2px;">Standard</div>
            <div style="font-size: 12px; font-weight: 600; color: {badge.color_text};">NIST FIPS 203–206</div>
        </div>
    </div>
</div>"""


def get_pdf_badge_data(badge: Badge) -> dict:
    """
    pdf_report.py ke liye badge data dict return karta hai.
    ReportLab Table mein directly use hoga.

    Returns:
        dict with label, sublabel, score, color strings (hex), description
    """
    return {
        "label":       badge.label,
        "sublabel":    badge.sublabel,
        "icon":        badge.icon,
        "score":       badge.score,
        "description": badge.description,
        "target":      badge.target,
        "issued_at":   badge.issued_at,
        "color_fill":  badge.color_fill,
        "color_stroke":badge.color_stroke,
        "color_text":  badge.color_text,
    }


def summarise_bulk_badges(badges: list[Badge]) -> dict:
    """
    Multiple badges ka summary dict return karta hai.
    Bulk scan results table ke liye use hoga.

    Args:
        badges : List of Badge instances

    Returns:
        {
          "total": int,
          "fully_safe": int,
          "pqc_ready": int,
          "partial": int,
          "vulnerable": int,
          "overall_risk": str   # worst badge type across all
        }
    """
    counts = {
        BADGE_FULLY_QUANTUM_SAFE: 0,
        BADGE_PQC_READY:          0,
        BADGE_PARTIAL_RISK:       0,
        BADGE_VULNERABLE:         0,
    }
    for b in badges:
        counts[b.badge_type] += 1

    # Worst badge = highest risk wala
    if counts[BADGE_VULNERABLE] > 0:
        overall = BADGE_VULNERABLE
    elif counts[BADGE_PARTIAL_RISK] > 0:
        overall = BADGE_PARTIAL_RISK
    elif counts[BADGE_PQC_READY] > 0:
        overall = BADGE_PQC_READY
    else:
        overall = BADGE_FULLY_QUANTUM_SAFE

    return {
        "total":       len(badges),
        "fully_safe":  counts[BADGE_FULLY_QUANTUM_SAFE],
        "pqc_ready":   counts[BADGE_PQC_READY],
        "partial":     counts[BADGE_PARTIAL_RISK],
        "vulnerable":  counts[BADGE_VULNERABLE],
        "overall_risk":overall,
        "overall_label": BADGE_META[overall]["label"],
    }

if __name__ == "__main__":
    for score, target in [(0, "secure.example.com:443"),
                          (2, "api.bank.com:443"),
                          (5, "legacy.corp.com:8443"),
                          (8, "old-server.internal:443")]:
        b = determine_badge(score, target)
        print(f"\nScore {score:>2} → [{b.badge_type}]  {b.label}")
        print(f"         Target : {b.target}")
        print(f"         Issued : {b.issued_at}")
        print(f"         Safe   : {b.is_safe()} | Critical: {b.is_critical()}")
