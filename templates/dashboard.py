"""Streamlit dashboard renderer for CypherQube."""

import json

import pandas as pd
import streamlit as st


def render_app(*, assess_target, batch_assess_targets, generate_pdf_report):
    """Render the Streamlit application using injected modules."""

    st.set_page_config(
        page_title="CypherQube — TLS Scanner",
        page_icon="🔒",
        layout="wide",
        initial_sidebar_state="collapsed"
    )
    
    st.markdown("""
    <style>
    
    /* ── GLOBAL ── */
    html, body, [class*="css"] {
        background-color: #f5f6f8 !important;
        color: #1a2332 !important;
        font-family: Arial, Helvetica, sans-serif !important;
    }
    .stApp {
        background: #f5f6f8 !important;
    }
    .main .block-container {
        padding: 0 2.5rem 5rem !important;
        max-width: 1380px !important;
    }
    #MainMenu, footer, .stDeployButton { display: none !important; }
    
    /* ── TOP HEADER BANNER ── */
    .cq-header-banner {
        background: #0a2352;
        margin: 0 -2.5rem 0;
        padding: 0 2.5rem;
        height: 56px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        position: sticky;
        top: 0;
        z-index: 300;
        border-bottom: 3px solid #1a56db;
    }
    .cq-header-left {
        display: flex;
        align-items: center;
        gap: 16px;
    }
    .cq-header-logo {
        display: flex;
        align-items: center;
        gap: 10px;
    }
    .cq-header-logo-mark {
        width: 30px;
        height: 30px;
        background: #1a56db;
        border: 2px solid rgba(255,255,255,0.2);
        border-radius: 5px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 14px;
        color: white;
        font-weight: bold;
        font-family: Arial, Helvetica, sans-serif;
        letter-spacing: -1px;
    }
    .cq-header-title {
        font-family: Arial, Helvetica, sans-serif;
        font-size: 1rem;
        font-weight: 700;
        color: #ffffff;
        letter-spacing: 0.02em;
    }
    .cq-header-title span {
        color: #7ab3ff;
        font-weight: 400;
    }
    .cq-header-divider {
        width: 1px;
        height: 22px;
        background: rgba(255,255,255,0.2);
        margin: 0 4px;
    }
    .cq-header-subtitle {
        font-family: Arial, Helvetica, sans-serif;
        font-size: 0.72rem;
        color: rgba(255,255,255,0.5);
        letter-spacing: 0.01em;
    }
    .cq-header-right {
        display: flex;
        align-items: center;
        gap: 0;
    }
    .cq-header-stat {
        display: flex;
        flex-direction: column;
        align-items: flex-end;
        padding: 0 18px;
        border-left: 1px solid rgba(255,255,255,0.1);
    }
    .cq-header-stat-label {
        font-family: Arial, Helvetica, sans-serif;
        font-size: 0.5rem;
        letter-spacing: 0.12em;
        text-transform: uppercase;
        color: rgba(255,255,255,0.4);
        margin-bottom: 2px;
    }
    .cq-header-stat-value {
        font-family: Arial, Helvetica, sans-serif;
        font-size: 0.68rem;
        color: rgba(255,255,255,0.75);
        font-weight: 600;
    }
    .cq-header-stat-value.live {
        color: #4ade80;
    }
    .cq-live-dot {
        display: inline-block;
        width: 5px;
        height: 5px;
        border-radius: 50%;
        background: #4ade80;
        margin-right: 5px;
        animation: blink 2.5s ease-in-out infinite;
    }
    @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.2} }
    
    /* ── SECONDARY NAV STRIP ── */
    .cq-nav-strip {
        background: #ffffff;
        border-bottom: 1px solid #dde2ea;
        margin: 0 -2.5rem 2rem;
        padding: 0 2.5rem;
        height: 44px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        box-shadow: 0 1px 4px rgba(0,0,0,0.06);
    }
    .cq-nav-breadcrumb {
        display: flex;
        align-items: center;
        gap: 6px;
        font-family: Arial, Helvetica, sans-serif;
        font-size: 0.72rem;
        color: #6b7a8d;
    }
    .cq-nav-breadcrumb .sep { color: #c0c9d4; }
    .cq-nav-breadcrumb .active { color: #0a2352; font-weight: 600; }
    .cq-compliance-strip {
        display: flex;
        align-items: center;
        gap: 6px;
    }
    .cq-compliance-tag {
        font-family: Arial, Helvetica, sans-serif;
        font-size: 0.58rem;
        font-weight: 700;
        letter-spacing: 0.06em;
        padding: 3px 9px;
        border-radius: 3px;
        text-transform: uppercase;
        background: #eef2ff;
        color: #3b5adb;
        border: 1px solid #c5d0fa;
    }
    
    /* ── PAGE HERO ── */
    .cq-page-hero {
        background: #ffffff;
        border: 1px solid #dde2ea;
        border-radius: 8px;
        padding: 2.2rem 2.5rem;
        margin-bottom: 2rem;
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 2rem;
        box-shadow: 0 1px 4px rgba(0,0,0,0.05);
        position: relative;
        overflow: hidden;
    }
    .cq-page-hero::before {
        content: '';
        position: absolute;
        left: 0; top: 0; bottom: 0;
        width: 4px;
        background: linear-gradient(180deg, #1a56db, #0a2352);
        border-radius: 8px 0 0 8px;
    }
    .cq-hero-badge {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        background: #eef2ff;
        border: 1px solid #c5d0fa;
        border-radius: 20px;
        padding: 3px 12px;
        font-family: Arial, Helvetica, sans-serif;
        font-size: 0.62rem;
        font-weight: 700;
        color: #3b5adb;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        margin-bottom: 12px;
    }
    .cq-hero-badge-dot {
        width: 5px;
        height: 5px;
        border-radius: 50%;
        background: #3b5adb;
    }
    .cq-hero-title {
        font-family: Arial, Helvetica, sans-serif;
        font-size: 1.55rem;
        font-weight: 700;
        color: #0a2352;
        line-height: 1.25;
        margin-bottom: 8px;
        letter-spacing: -0.01em;
    }
    .cq-hero-desc {
        font-family: Arial, Helvetica, sans-serif;
        font-size: 0.88rem;
        color: #4a5568;
        line-height: 1.65;
        max-width: 580px;
        font-weight: 400;
    }
    .cq-hero-meta {
        display: flex;
        flex-direction: column;
        gap: 10px;
        align-items: flex-end;
        flex-shrink: 0;
    }
    .cq-nist-grid {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 6px;
    }
    .cq-nist-pill {
        font-family: Arial, Helvetica, sans-serif;
        font-size: 0.6rem;
        font-weight: 600;
        padding: 5px 10px;
        border-radius: 4px;
        background: #f8faff;
        border: 1px solid #dde2ea;
        color: #3b5adb;
        text-align: center;
        white-space: nowrap;
    }
    .cq-version-tag {
        font-family: Arial, Helvetica, sans-serif;
        font-size: 0.6rem;
        color: #9aa5b4;
        text-align: right;
    }
    
    /* ── SECTION HEADING ── */
    .cq-section {
        display: flex;
        align-items: center;
        gap: 12px;
        margin: 2.2rem 0 1.2rem;
    }
    .cq-section-num {
        width: 22px;
        height: 22px;
        border-radius: 50%;
        background: #0a2352;
        color: white;
        font-family: Arial, Helvetica, sans-serif;
        font-size: 0.62rem;
        font-weight: 700;
        display: flex;
        align-items: center;
        justify-content: center;
        flex-shrink: 0;
    }
    .cq-section-label {
        font-family: Arial, Helvetica, sans-serif;
        font-size: 0.78rem;
        font-weight: 700;
        color: #0a2352;
        text-transform: uppercase;
        letter-spacing: 0.08em;
    }
    .cq-section-line {
        flex: 1;
        height: 1px;
        background: #dde2ea;
    }
    .cq-section-tag {
        font-family: Arial, Helvetica, sans-serif;
        font-size: 0.58rem;
        font-weight: 600;
        color: #6b7a8d;
        background: #ffffff;
        border: 1px solid #dde2ea;
        border-radius: 4px;
        padding: 2px 9px;
    }
    
    /* ── SCAN PANEL ── */
    .cq-scan-card {
        background: #ffffff;
        border: 1px solid #dde2ea;
        border-radius: 8px;
        padding: 2rem 2rem 1.8rem;
        margin-bottom: 1.5rem;
        box-shadow: 0 1px 4px rgba(0,0,0,0.05);
        position: relative;
    }
    .cq-scan-card-top {
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin-bottom: 1.4rem;
        padding-bottom: 1rem;
        border-bottom: 1px solid #f0f3f8;
    }
    .cq-scan-card-label {
        font-family: Arial, Helvetica, sans-serif;
        font-size: 0.75rem;
        font-weight: 700;
        color: #0a2352;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        display: flex;
        align-items: center;
        gap: 8px;
    }
    .cq-scan-card-label::before {
        content: '';
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background: #1a56db;
        box-shadow: 0 0 0 3px rgba(26,86,219,0.15);
        animation: blink 2s ease-in-out infinite;
        flex-shrink: 0;
    }
    .cq-scan-hint {
        font-family: Arial, Helvetica, sans-serif;
        font-size: 0.7rem;
        color: #9aa5b4;
    }
    
    /* ── INPUTS ── */
    .stTextInput input, .stNumberInput input {
        background: #fafbfc !important;
        border: 1px solid #cdd5df !important;
        border-radius: 5px !important;
        color: #1a2332 !important;
        font-family: Arial, Helvetica, sans-serif !important;
        font-size: 0.9rem !important;
        transition: all 0.15s !important;
        box-shadow: inset 0 1px 2px rgba(0,0,0,0.04) !important;
        padding: 10px 14px !important;
    }
    .stTextInput input:focus, .stNumberInput input:focus {
        border-color: #1a56db !important;
        box-shadow: 0 0 0 3px rgba(26,86,219,0.1), inset 0 1px 2px rgba(0,0,0,0.04) !important;
        outline: none !important;
        background: #ffffff !important;
    }
    .stTextInput input::placeholder { color: #b0bac8 !important; }
    .stTextInput label, .stNumberInput label {
        font-family: Arial, Helvetica, sans-serif !important;
        font-size: 0.72rem !important;
        font-weight: 700 !important;
        color: #374151 !important;
        text-transform: none !important;
        letter-spacing: 0.01em !important;
    }
    
    /* ── TEXTAREA ── */
    .stTextArea textarea {
        background: #fafbfc !important;
        border: 1px solid #cdd5df !important;
        border-radius: 5px !important;
        color: #1a2332 !important;
        font-family: Arial, Helvetica, sans-serif !important;
        font-size: 0.88rem !important;
        transition: all 0.15s !important;
    }
    .stTextArea textarea:focus {
        border-color: #1a56db !important;
        box-shadow: 0 0 0 3px rgba(26,86,219,0.1) !important;
        outline: none !important;
        background: #ffffff !important;
    }
    .stTextArea label {
        font-family: Arial, Helvetica, sans-serif !important;
        font-size: 0.72rem !important;
        font-weight: 700 !important;
        color: #374151 !important;
    }
    
    /* ── PRIMARY BUTTON ── */
    .stButton > button {
        background: #1a56db !important;
        border: 1px solid #1a56db !important;
        color: #ffffff !important;
        font-family: Arial, Helvetica, sans-serif !important;
        font-weight: 700 !important;
        font-size: 0.82rem !important;
        border-radius: 5px !important;
        padding: 0.65rem 1.8rem !important;
        transition: all 0.15s !important;
        letter-spacing: 0.02em !important;
        box-shadow: 0 1px 3px rgba(0,0,0,0.12), 0 2px 8px rgba(26,86,219,0.2) !important;
    }
    .stButton > button:hover {
        background: #1448c8 !important;
        border-color: #1448c8 !important;
        box-shadow: 0 2px 6px rgba(0,0,0,0.15), 0 4px 16px rgba(26,86,219,0.3) !important;
        transform: translateY(-1px) !important;
    }
    .stButton > button:active { transform: translateY(0) !important; }
    
    /* ── METRICS ROW ── */
    .cq-metrics-row {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 14px;
        margin-bottom: 1.5rem;
    }
    .cq-metric-card {
        background: #ffffff;
        border: 1px solid #dde2ea;
        border-radius: 8px;
        padding: 1.3rem 1.5rem;
        box-shadow: 0 1px 4px rgba(0,0,0,0.05);
        position: relative;
        overflow: hidden;
        transition: box-shadow 0.15s, border-color 0.15s;
    }
    .cq-metric-card:hover {
        box-shadow: 0 3px 12px rgba(0,0,0,0.09);
        border-color: #c0c9d8;
    }
    .cq-metric-card::after {
        content: '';
        position: absolute;
        top: 0; left: 0; right: 0;
        height: 3px;
        background: #1a56db;
        border-radius: 8px 8px 0 0;
    }
    .cq-metric-label {
        font-family: Arial, Helvetica, sans-serif;
        font-size: 0.62rem;
        font-weight: 700;
        letter-spacing: 0.1em;
        text-transform: uppercase;
        color: #6b7a8d;
        margin-bottom: 8px;
    }
    .cq-metric-value {
        font-family: Arial, Helvetica, sans-serif;
        font-size: 1rem;
        font-weight: 700;
        color: #0a2352;
        line-height: 1.3;
        word-break: break-word;
    }
    .cq-metric-value.score {
        font-size: 2.2rem;
        font-weight: 700;
        line-height: 1;
    }
    .cq-metric-sub {
        font-family: Arial, Helvetica, sans-serif;
        font-size: 0.65rem;
        color: #9aa5b4;
        margin-top: 5px;
    }
    .score-critical { color: #c81e1e !important; }
    .score-medium   { color: #b45309 !important; }
    .score-safe     { color: #166634 !important; }
    
    /* ── ALERT BANNER ── */
    .cq-alert {
        display: flex;
        align-items: flex-start;
        gap: 14px;
        padding: 1.1rem 1.5rem;
        border-radius: 7px;
        border: 1px solid;
        border-left: 4px solid;
        margin-bottom: 1.5rem;
        background: #ffffff;
        box-shadow: 0 1px 4px rgba(0,0,0,0.05);
    }
    .cq-alert.critical { border-color: #f87171; border-left-color: #c81e1e; background: #fff5f5; }
    .cq-alert.medium   { border-color: #fbbf24; border-left-color: #b45309; background: #fffbeb; }
    .cq-alert.safe     { border-color: #6ee7b7; border-left-color: #166634; background: #f0fdf4; }
    .cq-alert-icon { font-size: 1.2rem; flex-shrink: 0; margin-top: 1px; }
    .cq-alert-title {
        font-family: Arial, Helvetica, sans-serif;
        font-size: 0.82rem;
        font-weight: 700;
        margin-bottom: 3px;
    }
    .critical .cq-alert-title { color: #7f1d1d; }
    .medium   .cq-alert-title { color: #78350f; }
    .safe     .cq-alert-title { color: #14532d; }
    .cq-alert-desc {
        font-family: Arial, Helvetica, sans-serif;
        font-size: 0.8rem;
        line-height: 1.5;
        font-weight: 400;
    }
    .critical .cq-alert-desc { color: #991b1b; }
    .medium   .cq-alert-desc { color: #92400e; }
    .safe     .cq-alert-desc { color: #166634; }
    
    /* ── FINDINGS PANEL ── */
    .cq-findings-panel {
        background: #ffffff;
        border: 1px solid #dde2ea;
        border-radius: 8px;
        overflow: hidden;
        box-shadow: 0 1px 4px rgba(0,0,0,0.05);
        margin-bottom: 1.2rem;
    }
    .cq-findings-header {
        background: #f8fafc;
        padding: 0.9rem 1.4rem;
        border-bottom: 1px solid #dde2ea;
        display: flex;
        align-items: center;
        justify-content: space-between;
    }
    .cq-findings-title {
        font-family: Arial, Helvetica, sans-serif;
        font-size: 0.78rem;
        font-weight: 700;
        color: #0a2352;
        text-transform: uppercase;
        letter-spacing: 0.06em;
    }
    .cq-findings-badge {
        font-family: Arial, Helvetica, sans-serif;
        font-size: 0.65rem;
        font-weight: 600;
        color: #4a5568;
        background: #edf2f7;
        border: 1px solid #dde2ea;
        border-radius: 12px;
        padding: 2px 10px;
    }
    
    /* ── FINDING ROW ── */
    .cq-finding-row {
        border-bottom: 1px solid #f0f3f8;
        background: #ffffff;
    }
    .cq-finding-row:last-child { border-bottom: none; }
    .cq-finding-top {
        display: flex;
        align-items: flex-start;
        gap: 14px;
        padding: 1rem 1.4rem 0.85rem;
    }
    .cq-sev-badge {
        font-family: Arial, Helvetica, sans-serif;
        font-size: 0.6rem;
        font-weight: 700;
        letter-spacing: 0.08em;
        padding: 4px 10px;
        border-radius: 4px;
        flex-shrink: 0;
        margin-top: 2px;
        text-transform: uppercase;
        min-width: 72px;
        text-align: center;
        border: 1px solid;
        display: inline-block;
    }
    .sev-CRITICAL { color: #7f1d1d; background: #fef2f2; border-color: #fca5a5; }
    .sev-HIGH     { color: #78350f; background: #fffbeb; border-color: #fcd34d; }
    .sev-MEDIUM   { color: #713f12; background: #fefce8; border-color: #fde68a; }
    .sev-INFO     { color: #1e40af; background: #eff6ff; border-color: #93c5fd; }
    .sev-LOW      { color: #14532d; background: #f0fdf4; border-color: #86efac; }
    .cq-finding-body { flex: 1; min-width: 0; }
    .cq-finding-cat {
        font-family: Arial, Helvetica, sans-serif;
        font-size: 0.88rem;
        font-weight: 700;
        color: #0a2352;
        margin-bottom: 3px;
    }
    .cq-finding-desc {
        font-family: Arial, Helvetica, sans-serif;
        font-size: 0.82rem;
        color: #4a5568;
        line-height: 1.5;
        font-weight: 400;
    }
    .cq-remediation {
        background: #f8faff;
        border-top: 1px solid #e8edf6;
        border-left: 3px solid #1a56db;
        padding: 0.75rem 1.4rem 0.75rem 1.6rem;
        margin-left: 0;
    }
    .cq-rem-title {
        font-family: Arial, Helvetica, sans-serif;
        font-size: 0.6rem;
        font-weight: 700;
        letter-spacing: 0.1em;
        text-transform: uppercase;
        color: #1a56db;
        margin-bottom: 4px;
    }
    .cq-rem-body {
        font-family: Arial, Helvetica, sans-serif;
        font-size: 0.81rem;
        color: #374151;
        line-height: 1.6;
        font-weight: 400;
    }
    
    /* ── CERT PANEL ── */
    .cq-cert-panel {
        color: black;
        background: #ffffff;
        border: 1px solid #dde2ea;
        border-radius: 8px;
        overflow: hidden;
        box-shadow: 0 1px 4px rgba(0,0,0,0.05);
    }
    .cq-cert-header {
        background: #f8fafc;
        padding: 0.9rem 1.4rem;
        border-bottom: 1px solid #dde2ea;
        display: flex;
        align-items: center;
        gap: 9px;
        font-family: Arial, Helvetica, sans-serif;
        font-size: 0.78rem;
        font-weight: 700;
        color: #0a2352;
        text-transform: uppercase;
        letter-spacing: 0.06em;
    }
    .cq-cert-icon-wrap {
        width: 24px;
        height: 24px;
        background: #eef2ff;
        border: 1px solid #c5d0fa;
        border-radius: 5px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 12px;
    }
    .cq-kv-table { width: 100%; border-collapse: collapse; }
    .cq-kv-row { border-bottom: 1px solid #f0f3f8; transition: background 0.1s; }
    .cq-kv-row:last-child { border-bottom: none; }
    .cq-kv-row:hover { background: #fafbfd; }
    .cq-kv-table td { padding: 0.7rem 1.4rem; vertical-align: top; }
    .cq-kv-key {
        font-family: Arial, Helvetica, sans-serif;
        font-size: 0.65rem;
        font-weight: 700;
        letter-spacing: 0.06em;
        text-transform: uppercase;
        color: #6b7a8d;
        width: 45%;
    }
    .cq-kv-val {
        font-family: Arial, Helvetica, sans-serif;
        font-size: 0.82rem;
        color: #1a2332;
        word-break: break-all;
        font-weight: 400;
    }
    
    /* ── INFO SIDEBAR BOX ── */
    .cq-info-box {
        background: #f8faff;
        border: 1px solid #dde6fa;
        border-radius: 8px;
        padding: 1.2rem 1.4rem;
        margin-top: 1rem;
    }
    .cq-info-box-title {
        font-family: Arial, Helvetica, sans-serif;
        font-size: 0.7rem;
        font-weight: 700;
        color: #1a56db;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        margin-bottom: 10px;
        display: flex;
        align-items: center;
        gap: 7px;
    }
    .cq-info-box-title::before { content: 'ℹ'; font-size: 0.9rem; }
    .cq-info-row {
        display: flex;
        justify-content: space-between;
        padding: 5px 0;
        border-bottom: 1px solid #e8edf6;
        font-family: Arial, Helvetica, sans-serif;
        font-size: 0.75rem;
    }
    .cq-info-row:last-child { border-bottom: none; }
    .cq-info-row-label { color: #6b7a8d; font-weight: 400; }
    .cq-info-row-val { color: #0a2352; font-weight: 600; }
    
    /* ── DOWNLOAD BUTTON ── */
    .stDownloadButton > button {
        background: #ffffff !important;
        border: 1px solid #cdd5df !important;
        color: #374151 !important;
        font-family: Arial, Helvetica, sans-serif !important;
        font-weight: 600 !important;
        font-size: 0.78rem !important;
        border-radius: 5px !important;
        padding: 0.55rem 1.2rem !important;
        transition: all 0.15s !important;
        box-shadow: 0 1px 2px rgba(0,0,0,0.06) !important;
    }
    .stDownloadButton > button:hover {
        background: #f0f7ff !important;
        border-color: #1a56db !important;
        color: #1a56db !important;
        box-shadow: 0 1px 4px rgba(26,86,219,0.15) !important;
    }
    
    /* ── JSON ── */
    .stJson > div {
        background: #fafbfc !important;
        border: 1px solid #dde2ea !important;
        border-radius: 6px !important;
        font-family: 'Courier New', Courier, monospace !important;
        font-size: 0.76rem !important;
    }
    
    /* ── DATAFRAME ── */
    .stDataFrame { border: 1px solid #dde2ea !important; border-radius: 8px !important; overflow: hidden !important; }
    .stDataFrame thead th {
        background: #f8fafc !important;
        color: #374151 !important;
        font-family: Arial, Helvetica, sans-serif !important;
        font-size: 0.65rem !important;
        font-weight: 700 !important;
        letter-spacing: 0.08em !important;
        text-transform: uppercase !important;
        border-bottom: 1px solid #dde2ea !important;
        padding: 11px 14px !important;
    }
    .stDataFrame td {
        font-family: Arial, Helvetica, sans-serif !important;
        font-size: 0.82rem !important;
        color: #374151 !important;
        border-color: #f0f3f8 !important;
        background: #ffffff !important;
        padding: 9px 14px !important;
    }
    .stDataFrame tr:hover td { background: #f8fafd !important; }
    
    /* ── PROGRESS ── */
    .stProgress > div > div { background: #e5e9f0 !important; border-radius: 4px !important; height: 5px !important; }
    .stProgress > div > div > div { background: linear-gradient(90deg, #1a56db, #3b82f6) !important; border-radius: 4px !important; }
    
    /* ── EXPANDER — properly visible, light theme ── */
    [data-testid="stExpander"] {
        background: #ffffff !important;
        border: 1px solid #dde2ea !important;
        border-radius: 8px !important;
        overflow: hidden !important;
        margin-top: 1rem !important;
        box-shadow: 0 1px 4px rgba(0,0,0,0.05) !important;
    }
    [data-testid="stExpander"] summary,
    [data-testid="stExpander"] > div:first-child {
        background: #f8fafc !important;
        color: #0a2352 !important;
        font-family: Arial, Helvetica, sans-serif !important;
        font-size: 0.8rem !important;
        font-weight: 700 !important;
    }
    [data-testid="stExpander"] > div:last-child {
        background: #fafbfc !important;
    }
    .streamlit-expanderHeader {
        background: #f8fafc !important;
        border: 1px solid #dde2ea !important;
        border-radius: 6px !important;
        color: #0a2352 !important;
        font-family: Arial, Helvetica, sans-serif !important;
        font-size: 0.8rem !important;
        font-weight: 700 !important;
    }
    .streamlit-expanderContent {
        border: 1px solid #dde2ea !important;
        border-top: none !important;
        background: #fafbfc !important;
    }
    
    /* ── ST ALERTS ── */
    .stAlert {
        background: #fff5f5 !important;
        border: 1px solid #fca5a5 !important;
        border-radius: 6px !important;
        color: #7f1d1d !important;
        font-family: Arial, Helvetica, sans-serif !important;
    }
    
    /* ── HR ── */
    hr { border: none !important; border-top: 1px solid #dde2ea !important; margin: 2.5rem 0 !important; }
    
    /* ── SCROLLBAR ── */
    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: #f5f6f8; }
    ::-webkit-scrollbar-thumb { background: #c0c9d8; border-radius: 3px; }
    ::-webkit-scrollbar-thumb:hover { background: #9aa5b4; }
    
    /* ── SELECTION ── */
    ::selection { background: rgba(26,86,219,0.12); color: #0a2352; }
    
    /* ── BATCH COMPLETE — white card (not black) ── */
    .cq-batch-complete {
        display: flex;
        align-items: center;
        gap: 12px;
        margin: 1.5rem 0 1.2rem;
        background: #ffffff;
        border: 1px solid #dde2ea;
        border-left: 4px solid #166634;
        border-radius: 8px;
        padding: 0.9rem 1.4rem;
        box-shadow: 0 1px 4px rgba(0,0,0,0.05);
    }
    .cq-batch-icon {
        width: 28px; height: 28px; border-radius: 50%;
        background: #dcfce7; border: 1px solid #86efac;
        display: flex; align-items: center; justify-content: center;
        font-size: 0.8rem; color: #166634; flex-shrink: 0; font-weight: 700;
    }
    .cq-batch-text {
        font-family: Arial, Helvetica, sans-serif;
        font-size: 0.78rem; font-weight: 700;
        color: #0a2352; text-transform: uppercase; letter-spacing: 0.08em;
    }
    .cq-batch-sub {
        font-family: Arial, Helvetica, sans-serif;
        font-size: 0.7rem; color: #6b7a8d; margin-left: auto;
    }
    
    /* ── FOOTER ── */
    .cq-footer {
        background: #0a2352;
        margin: 4rem -2.5rem -5rem;
        padding: 3rem 2.5rem 2rem;
        color: rgba(255,255,255,0.7);
    }
    .cq-footer-top {
        display: grid;
        grid-template-columns: 2fr 1fr 1fr;
        gap: 2.5rem;
        padding-bottom: 2rem;
        border-bottom: 1px solid rgba(255,255,255,0.1);
        margin-bottom: 1.8rem;
    }
    .cq-footer-brand-name {
        font-family: Arial, Helvetica, sans-serif;
        font-size: 1rem;
        font-weight: 700;
        color: #ffffff;
        margin-bottom: 8px;
        display: flex;
        align-items: center;
        gap: 8px;
    }
    .cq-footer-brand-icon {
        width: 26px;
        height: 26px;
        background: #1a56db;
        border-radius: 5px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 12px;
        font-weight: bold;
        color: white;
        font-family: Arial, sans-serif;
    }
    .cq-footer-brand-desc {
        font-family: Arial, Helvetica, sans-serif;
        font-size: 0.78rem;
        line-height: 1.65;
        color: rgba(255,255,255,0.5);
        max-width: 300px;
        margin-bottom: 14px;
    }
    .cq-footer-col-title {
        font-family: Arial, Helvetica, sans-serif;
        font-size: 0.65rem;
        font-weight: 700;
        letter-spacing: 0.12em;
        text-transform: uppercase;
        color: rgba(255,255,255,0.4);
        margin-bottom: 12px;
    }
    .cq-footer-link {
        display: block;
        font-family: Arial, Helvetica, sans-serif;
        font-size: 0.78rem;
        color: rgba(255,255,255,0.6);
        margin-bottom: 7px;
        line-height: 1.4;
        text-decoration: none;
        cursor: pointer;
        transition: color 0.15s;
    }
    .cq-footer-link:hover { color: #7ab3ff !important; text-decoration: none; }
    .cq-footer-bottom {
        display: flex;
        justify-content: space-between;
        align-items: center;
        flex-wrap: wrap;
        gap: 10px;
    }
    .cq-footer-copyright {
        font-family: Arial, Helvetica, sans-serif;
        font-size: 0.7rem;
        color: rgba(255,255,255,0.35);
    }
    .cq-footer-bottom-links { display: flex; gap: 20px; }
    .cq-footer-bottom-link {
        font-family: Arial, Helvetica, sans-serif;
        font-size: 0.7rem;
        color: rgba(255,255,255,0.5);
        text-decoration: none;
        transition: color 0.15s;
        cursor: pointer;
    }
    .cq-footer-bottom-link:hover { color: #7ab3ff !important; text-decoration: none; }
    .cq-footer-cert-row { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 10px; }
    .cq-footer-cert {
        font-family: Arial, Helvetica, sans-serif;
        font-size: 0.58rem;
        font-weight: 700;
        letter-spacing: 0.08em;
        padding: 3px 8px;
        border: 1px solid rgba(255,255,255,0.15);
        border-radius: 3px;
        color: rgba(255,255,255,0.4);
        text-transform: uppercase;
    }
    </style>
    """, unsafe_allow_html=True)
    
    
    def normalize_target(t):
        return t.replace("https://", "").replace("http://", "").split("/")[0].strip()
    
    def risk_meta(score):
        if score >= 7:   return "Critical Risk", "critical", "score-critical"
        elif score >= 4: return "Moderate Risk", "medium",   "score-medium"
        else:            return "Low Risk",       "safe",     "score-safe"
    
    def build_finding_html(findings):
        if not findings:
            return (
                '<div class="cq-finding-row">'
                '<div class="cq-finding-top">'
                '<span class="cq-sev-badge sev-LOW">PASS</span>'
                '<div class="cq-finding-body">'
                '<div class="cq-finding-cat">All checks passed</div>'
                '<div class="cq-finding-desc">No post-quantum vulnerabilities detected.</div>'
                '</div></div></div>'
            )
    
        html_parts = []
    
        for f in findings:
            sev = f.get("severity", "INFO")
            category = f.get("category", "")
            finding = f.get("finding", "")
            rem = f.get("remediation", "")
    
            block = (
                f'<div class="cq-finding-row">'
                f'<div class="cq-finding-top">'
                f'<span class="cq-sev-badge sev-{sev}">{sev}</span>'
                f'<div class="cq-finding-body">'
                f'<div class="cq-finding-cat">{category}</div>'
                f'<div class="cq-finding-desc">{finding}</div>'
                f'</div></div>'
                f'<div class="cq-remediation">'
                f'<div class="cq-rem-title">Recommended Remediation</div>'
                f'<div class="cq-rem-body">{rem}</div>'
                f'</div></div>'
            )
    
            html_parts.append(block)
    
        return "".join(html_parts)

    def build_remediation_html(remediation):
        if not remediation:
            return (
                '<div class="cq-finding-row">'
                '<div class="cq-finding-top">'
                '<span class="cq-sev-badge sev-LOW">PASS</span>'
                '<div class="cq-finding-body">'
                '<div class="cq-finding-cat">No urgent remediation</div>'
                '<div class="cq-finding-desc">No actionable migration items were generated for this scan.</div>'
                '</div></div></div>'
            )

        html_parts = []
        for item in remediation:
            sev = item.get("priority", "INFO")
            refs = ", ".join(ref.get("id", "") for ref in item.get("nist_references", [])) or "General guidance"
            badge = "HNDL Priority" if item.get("hndl_priority") else sev
            block = (
                f'<div class="cq-finding-row">'
                f'<div class="cq-finding-top">'
                f'<span class="cq-sev-badge sev-{sev}">{badge}</span>'
                f'<div class="cq-finding-body">'
                f'<div class="cq-finding-cat">{item.get("component", "")}</div>'
                f'<div class="cq-finding-desc">{item.get("issue", "")}</div>'
                f'</div></div>'
                f'<div class="cq-remediation">'
                f'<div class="cq-rem-title">Recommended Action</div>'
                f'<div class="cq-rem-body">{item.get("recommended_action", "")}<br><strong>Implementation:</strong> {item.get("implementation_hint", "")}<br><strong>NIST:</strong> {refs}</div>'
                f'</div></div>'
            )
            html_parts.append(block)
        return "".join(html_parts)

    def build_nist_html(references):
        if not references:
            return '<div class="cq-finding-desc">No specific NIST PQC references mapped for this assessment.</div>'

        html_parts = []
        for ref in references:
            html_parts.append(
                f'<div class="cq-finding-row">'
                f'<div class="cq-finding-top">'
                f'<span class="cq-sev-badge sev-INFO">{ref.get("id", "")}</span>'
                f'<div class="cq-finding-body">'
                f'<div class="cq-finding-cat">{ref.get("name", "")}</div>'
                f'<div class="cq-finding-desc">{ref.get("family", "")}<br><a href="{ref.get("url", "#")}" target="_blank">{ref.get("url", "")}</a></div>'
                f'</div></div></div>'
            )
        return "".join(html_parts)

    def build_cbom_html(cbom):
        entries = cbom.get("entries", [])
        summary = cbom.get("summary", {})
        if not entries:
            return '<div class="cq-finding-desc">No CBOM inventory available.</div>'

        rows = [
            f"""
            <tr>
                <td>{entry.get("target", "—")}</td>
                <td>{entry.get("tls_version", "—")}</td>
                <td>{entry.get("cipher_suite", "—")}</td>
                <td>{entry.get("key_exchange", "—")}</td>
                <td>{entry.get("risk_label", "—")}</td>
                <td>{entry.get("pqc_readiness", "—")}</td>
            </tr>
            """
            for entry in entries
        ]

        return f"""
        <div style="padding:1rem 1.4rem 0.4rem;">
            <div style="font-family:Arial,sans-serif;font-size:0.72rem;color:#6b7a8d;margin-bottom:0.8rem;">
                Total Assets: <strong>{summary.get('total_assets', 0)}</strong> ·
                Quantum Safe: <strong>{summary.get('quantum_safe', 0)}</strong> ·
                Not Quantum Safe: <strong>{summary.get('not_quantum_safe', 0)}</strong> ·
                Risk Ratio: <strong>{summary.get('risk_ratio', '0/0')}</strong>
            </div>
            <table class="cq-kv-table">
                <tr>
                    <td>Target</td><td>TLS Version</td><td>Cipher Suite</td><td>Key Exchange</td><td>Risk</td><td>PQC Readiness</td>
                </tr>
                {''.join(rows)}
            </table>
        </div>
        """
    
    
    st.markdown("""
    <div class="cq-header-banner">
        <div class="cq-header-left">
            <div class="cq-header-logo">
                <div class="cq-header-logo-mark">CQ</div>
                <div class="cq-header-title">Cypher<span>Qube</span></div>
            </div>
            <div class="cq-header-divider"></div>
            <div class="cq-header-subtitle">Post-Quantum Cryptography Risk Assessment Platform</div>
        </div>
        <div class="cq-header-right">
            <div class="cq-header-stat">
                <div class="cq-header-stat-label">Standards</div>
                <div class="cq-header-stat-value">NIST FIPS 203–206</div>
            </div>
            <div class="cq-header-stat">
                <div class="cq-header-stat-label">Engine</div>
                <div class="cq-header-stat-value">OpenSSL 3.x</div>
            </div>
            <div class="cq-header-stat">
                <div class="cq-header-stat-label">Version</div>
                <div class="cq-header-stat-value">v2.1.0</div>
            </div>
            <div class="cq-header-stat">
                <div class="cq-header-stat-label">System</div>
                <div class="cq-header-stat-value live"><span class="cq-live-dot"></span>Operational</div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("""
    <div class="cq-nav-strip">
        <div class="cq-nav-breadcrumb">
            <span>Security</span>
            <span class="sep">›</span>
            <span>Cryptography</span>
            <span class="sep">›</span>
            <span class="active">TLS Assessment</span>
        </div>
        <div class="cq-compliance-strip">
            <span style="font-family:Arial,sans-serif;font-size:0.62rem;color:#6b7a8d;margin-right:4px;">Compliant with:</span>
            <div class="cq-compliance-tag">ML-KEM · FIPS 203</div>
            <div class="cq-compliance-tag">ML-DSA · FIPS 204</div>
            <div class="cq-compliance-tag">SLH-DSA · FIPS 205</div>
            <div class="cq-compliance-tag">FN-DSA · FIPS 206</div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("""
    <div class="cq-page-hero">
        <div class="cq-hero-text">
            <div class="cq-hero-badge">
                <div class="cq-hero-badge-dot"></div>
                Enterprise Security Assessment
            </div>
            <div class="cq-hero-title">TLS Post-Quantum Risk Assessment</div>
            <div class="cq-hero-desc">
                Evaluate your organisation's TLS endpoints against emerging post-quantum threats.
                CypherQube performs deep cryptographic analysis to identify vulnerabilities to
                Shor's and Grover's quantum algorithms, and delivers NIST PQC-compliant
                migration guidance to future-proof your infrastructure.
            </div>
        </div>
        <div class="cq-hero-meta">
            <div class="cq-nist-grid">
                <div class="cq-nist-pill">ML-KEM · FIPS 203</div>
                <div class="cq-nist-pill">ML-DSA · FIPS 204</div>
                <div class="cq-nist-pill">SLH-DSA · FIPS 205</div>
                <div class="cq-nist-pill">FN-DSA · FIPS 206</div>
            </div>
            <div class="cq-version-tag">CypherQube v2.1.0 · MIT License</div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    
    st.markdown("""
    <div class="cq-section">
        <div class="cq-section-num">1</div>
        <div class="cq-section-label">Target Configuration</div>
        <div class="cq-section-line"></div>
        <div class="cq-section-tag">Configure Endpoint</div>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("""
    <div class="cq-scan-card">
        <div class="cq-scan-card-top">
            <div class="cq-scan-card-label">TLS Endpoint Scanner</div>
            <div class="cq-scan-hint">Supports domains, IP addresses, and internal hostnames on any port</div>
        </div>
    """, unsafe_allow_html=True)
    
    c1, c2, c3 = st.columns([5, 1, 1])
    with c1:
        raw_target = st.text_input(
            "Host / IP Address",
            placeholder="e.g.  api.yourbank.com   ·   192.168.1.100   ·   secure.internal"
        )
    with c2:
        port = st.number_input("Port", min_value=1, max_value=65535, value=443)
    with c3:
        st.markdown("<br>", unsafe_allow_html=True)
        scan_button = st.button("Run Assessment", use_container_width=True)
    
    if scan_button:
        if not raw_target:
            st.error("Please specify a target host to continue.")
        else:
            if raw_target.startswith("http://") and not raw_target.startswith("https://"):
                st.warning(f"⚠ Input uses http:// — scanning port {port} for TLS anyway. Plain HTTP sites have no TLS and the scan may fail.")
    
            target = normalize_target(raw_target)

            with st.spinner(f"Analysing {target}:{port} — please wait..."):
                report = assess_target(target, port)

            if report:
                inventory    = report.get("inventory", {})
                tls          = inventory.get("tls_version", "—")
                cipher       = inventory.get("cipher_suite", "—")
                key_exchange = inventory.get("key_exchange", "—")
                cert         = inventory.get("certificate", {})
                score        = report.get("summary", {}).get("risk_score", 0)
                findings     = report.get("findings", [])
                remediation  = report.get("remediation", [])
                nist_refs    = report.get("nist_references", [])
                cbom         = report.get("cbom", {})
    
                label, css, score_cls = risk_meta(score)
    
                st.markdown("""
                <div class="cq-section">
                    <div class="cq-section-num">2</div>
                    <div class="cq-section-label">Assessment Results</div>
                    <div class="cq-section-line"></div>
                    <div class="cq-section-tag">Scan Complete</div>
                </div>
                """, unsafe_allow_html=True)
    
                # ── Metrics ──
                st.markdown(f"""
                <div class="cq-metrics-row">
                    <div class="cq-metric-card">
                        <div class="cq-metric-label">TLS Protocol</div>
                        <div class="cq-metric-value">{tls}</div>
                        <div class="cq-metric-sub">Negotiated version</div>
                    </div>
                    <div class="cq-metric-card">
                        <div class="cq-metric-label">Cipher Suite</div>
                        <div class="cq-metric-value" style="font-size:0.82rem;line-height:1.45;">{cipher}</div>
                        <div class="cq-metric-sub">Active cipher</div>
                    </div>
                    <div class="cq-metric-card">
                        <div class="cq-metric-label">Key Exchange</div>
                        <div class="cq-metric-value">{key_exchange}</div>
                        <div class="cq-metric-sub">Algorithm in use</div>
                    </div>
                    <div class="cq-metric-card">
                        <div class="cq-metric-label">Quantum Risk Score</div>
                        <div class="cq-metric-value score {score_cls}">{score}<span style="font-size:1rem;font-weight:400;color:#9aa5b4">/10</span></div>
                        <div class="cq-metric-sub">{label}</div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
    
                alert_icons  = {"critical": "⚠️", "medium": "⚡", "safe": "✅"}
                alert_titles = {
                    "critical": "Critical — Post-Quantum Vulnerabilities Detected",
                    "medium":   "Advisory — Moderate Quantum Exposure Identified",
                    "safe":     "Compliant — No Significant Quantum Vulnerabilities Found",
                }
                alert_descs = {
                    "critical": f"The endpoint <strong>{target}:{port}</strong> uses cryptographic algorithms vulnerable to quantum attacks. Immediate migration to NIST PQC standards is strongly recommended to protect against 'harvest now, decrypt later' threats.",
                    "medium":   f"The endpoint <strong>{target}:{port}</strong> has moderate quantum exposure. A structured migration plan to post-quantum cryptographic standards is recommended within your next refresh cycle.",
                    "safe":     f"The endpoint <strong>{target}:{port}</strong> meets current NIST post-quantum cryptography standards. Continue monitoring as standards evolve.",
                }
                st.markdown(f"""
                <div class="cq-alert {css}">
                    <span class="cq-alert-icon">{alert_icons[css]}</span>
                    <div class="cq-alert-content">
                        <div class="cq-alert-title">{alert_titles[css]}</div>
                        <div class="cq-alert-desc">{alert_descs[css]}</div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
    
                left, right = st.columns([6, 4])
    
                with right:
                    pub_alg  = cert.get("public_key_algorithm", "—")
                    key_size = cert.get("key_size", "—")
                    sig_alg  = cert.get("signature_algorithm", "—")
                    issuer   = cert.get("issuer", "—")
                    expiry   = cert.get("expiry", "—")
    
                st.markdown(f"""
                <div class="cq-cert-panel">
                    <div class="cq-cert-header">
                        <div class="cq-cert-icon-wrap">🔐</div>
                        Certificate Details
                    </div>
                        <table class="cq-kv-table">
                            <tr><td>Public Key Algorithm</td><td>{pub_alg}</td></tr>
                            <tr><td>Key Size</td><td>{key_size} bits</td></tr>
                            <tr><td>Signature Algorithm</td><td>{sig_alg}</td></tr>
                            <tr><td>Issuer</td><td>{issuer}</td></tr>
                            <tr><td>Expiry Date</td><td>{expiry}</td></tr>
                        </table>
                    </div>
                """, unsafe_allow_html=True)
                findings_html = build_finding_html(findings)
    
                st.markdown(f"""
                <div class="cq-findings-panel">
                    <div class="cq-findings-header">
                        <span class="cq-findings-title">Quantum Risk Findings</span>
                        <span class="cq-findings-badge">{len(findings)} findings</span>
                    </div>
                </div>
                """, unsafe_allow_html=True)
                st.markdown(findings_html, unsafe_allow_html=True)

                st.markdown(f"""
                <div class="cq-findings-panel">
                    <div class="cq-findings-header">
                        <span class="cq-findings-title">Actionable Remediation</span>
                        <span class="cq-findings-badge">{len(remediation)} actions</span>
                    </div>
                </div>
                """, unsafe_allow_html=True)
                st.markdown(build_remediation_html(remediation), unsafe_allow_html=True)

                st.markdown(f"""
                <div class="cq-findings-panel">
                    <div class="cq-findings-header">
                        <span class="cq-findings-title">NIST PQC Mapping</span>
                        <span class="cq-findings-badge">{len(nist_refs)} standards</span>
                    </div>
                </div>
                """, unsafe_allow_html=True)
                st.markdown(build_nist_html(nist_refs), unsafe_allow_html=True)

                st.markdown(f"""
                <div class="cq-cert-panel" style="margin-top:1rem;">
                    <div class="cq-cert-header">
                        <div class="cq-cert-icon-wrap">CB</div>
                        CBOM / Crypto Inventory
                    </div>
                    {build_cbom_html(cbom)}
                </div>
                """, unsafe_allow_html=True)
                
    
                # Export section 
                st.markdown("""
                <div class="cq-section">
                    <div class="cq-section-num">3</div>
                    <div class="cq-section-label">Export Report</div>
                    <div class="cq-section-line"></div>
                </div>
                """, unsafe_allow_html=True)
    
                col_json, col_pdf, _ = st.columns([1, 1, 5])
                with col_json:
                    st.download_button(
                        label="⬇ JSON Report",
                        data=json.dumps(report, indent=4),
                        file_name=f"cypherqube_{target.replace(':','_')}.json",
                        mime="application/json",
                        use_container_width=True
                    )
                with col_pdf:
                    pdf_bytes = generate_pdf_report(report)
                    st.download_button(
                        label="⬇ PDF Report",
                        data=pdf_bytes,
                        file_name=f"cypherqube_{target.replace(':','_')}.pdf",
                        mime="application/pdf",
                        use_container_width=True
                    )
    
                with st.expander(" Raw Assessment JSON"):
                    st.json(report)
    
    MAX_BULK = 5
    
    st.markdown("<hr>", unsafe_allow_html=True)
    
    st.markdown("""
    <div class="cq-section">
        <div class="cq-section-num">4</div>
        <div class="cq-section-label">Bulk Target Assessment</div>
        <div class="cq-section-line"></div>
        <div class="cq-section-tag">Batch Mode</div>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown(f"""
    <div style="background:#ffffff;border:1px solid #dde2ea;border-radius:8px;
                padding:1.5rem 2rem;margin-bottom:1.2rem;box-shadow:0 1px 4px rgba(0,0,0,0.05);">
        <div style="font-family:Arial,sans-serif;font-size:0.75rem;font-weight:700;
                    color:#0a2352;text-transform:uppercase;letter-spacing:0.08em;margin-bottom:6px;">
            Batch Endpoint Scanner
        </div>
        <div style="font-family:Arial,sans-serif;font-size:0.8rem;color:#6b7a8d;margin-bottom:0.2rem;">
            Paste up to <strong>{MAX_BULK} URLs</strong>, one per line.
            Accepts plain domains, <code>http://</code> or <code>https://</code> prefixes.
            If more than {MAX_BULK} are provided, only the first {MAX_BULK} will be scanned.
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    bulk_input = st.text_area(
        "Targets — one URL / domain per line",
        placeholder="github.com\nhttps://cloudflare.com\nbank.example.com\ngoogle.com\nexample.org",
        height=160,
        key="bulk_textarea"
    )
    
    bcol1, _ = st.columns([1, 6])
    with bcol1:
        bulk_run = st.button("Run Bulk Assessment", use_container_width=True, key="bulk_run_btn")
    
    if bulk_run:
        raw_lines = [l.strip() for l in bulk_input.splitlines() if l.strip() and not l.strip().startswith("#")]
    
        if not raw_lines:
            st.error("No targets entered. Paste at least one URL or domain above.")
        else:
            total_provided = len(raw_lines)
            targets        = raw_lines[:MAX_BULK]
            trimmed        = total_provided - len(targets)
    
            if trimmed > 0:
                st.warning(f"⚠ {total_provided} URLs provided — limit is {MAX_BULK}. Scanning first {MAX_BULK} only. Ignored: {', '.join(raw_lines[MAX_BULK:])}")
    
            progress = st.progress(0)
            status   = st.empty()

            for i, raw in enumerate(targets):
                domain = normalize_target(raw)
                status.markdown(
                    f'<div style="font-family:Arial,sans-serif;font-size:0.78rem;color:#6b7a8d;">'
                    f'Scanning <strong style="color:#0a2352;">{domain}</strong> [{i+1}/{len(targets)}]</div>',
                    unsafe_allow_html=True
                )
                progress.progress((i + 1) / len(targets))

            batch_report = batch_assess_targets(targets, default_port=443)
            results = batch_report.get("results", [])
            errors = batch_report.get("errors", [])

            status.empty()
            progress.empty()
    
            ok_count  = len(results)
            err_count = len(errors)
            target_word = "targets" if ok_count != 1 else "target"
            failed_html = f"&nbsp;·&nbsp; <span style=\"color:#c81e1e;font-weight:600;\">{err_count} failed</span>" if err_count else ""
            processed_str = f"{len(targets)} of {total_provided} processed"
            st.markdown(f"""
            <div class="cq-batch-complete">
                <div class="cq-batch-icon">✓</div>
                <div>
                    <div class="cq-batch-text">Batch Complete</div>
                    <div style="font-family:Arial,sans-serif;font-size:0.7rem;color:#6b7a8d;margin-top:2px;">
                        {ok_count} {target_word} scanned successfully {failed_html}
                    </div>
                </div>
                <div class="cq-batch-sub">{processed_str}</div>
            </div>
            """, unsafe_allow_html=True)
    
            if errors:
                for e in errors:
                    st.markdown(f"""
                    <div style="background:#fff5f5;border:1px solid #fca5a5;border-left:4px solid #c81e1e;
                                padding:0.65rem 1rem;margin-bottom:0.4rem;border-radius:6px;
                                font-family:Arial,sans-serif;font-size:0.78rem;color:#7f1d1d;">
                        ✗ &nbsp;<strong>{e['target']}</strong>
                        <span style="color:#9aa5b4;margin-left:12px;">{e['error']}</span>
                    </div>
                    """, unsafe_allow_html=True)
    
            if results:
                table = []
                for r in results:
                    s = r["summary"]["risk_score"]
                    lbl, _, _ = risk_meta(s)
                    table.append({
                        "Target":       r["target"],
                        "TLS Version":  r["inventory"]["tls_version"],
                        "Cipher Suite": r["inventory"]["cipher_suite"],
                        "Key Exchange": r["inventory"]["key_exchange"],
                        "Risk Score":   s,
                        "Risk Level":   lbl,
                    })

                st.dataframe(pd.DataFrame(table), use_container_width=True)

                bulk_summary = batch_report.get("summary", {})
                st.markdown(f"""
                <div class="cq-metrics-row">
                    <div class="cq-metric-card">
                        <div class="cq-metric-label">Successful Targets</div>
                        <div class="cq-metric-value">{bulk_summary.get("successful", 0)}</div>
                        <div class="cq-metric-sub">Completed assessments</div>
                    </div>
                    <div class="cq-metric-card">
                        <div class="cq-metric-label">Failed Targets</div>
                        <div class="cq-metric-value">{bulk_summary.get("failed", 0)}</div>
                        <div class="cq-metric-sub">Needs retry</div>
                    </div>
                    <div class="cq-metric-card">
                        <div class="cq-metric-label">Critical Risk</div>
                        <div class="cq-metric-value">{bulk_summary.get("risk_distribution", {}).get("critical", 0)}</div>
                        <div class="cq-metric-sub">Immediate action</div>
                    </div>
                    <div class="cq-metric-card">
                        <div class="cq-metric-label">Quantum Safe</div>
                        <div class="cq-metric-value">{bulk_summary.get("risk_distribution", {}).get("safe", 0)}</div>
                        <div class="cq-metric-sub">Low exposure</div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
    
                st.markdown("""
                <div class="cq-section" style="margin-top:1.2rem;">
                    <div class="cq-section-num">↓</div>
                    <div class="cq-section-label">Per-Target Risk Summary</div>
                    <div class="cq-section-line"></div>
                </div>
                """, unsafe_allow_html=True)
    
                cols = st.columns(min(len(results), 5))
                color_map = {"critical": "#c81e1e", "medium": "#b45309", "safe": "#166634"}
                for idx, r in enumerate(results):
                    s = r["summary"]["risk_score"]
                    lbl, css, _ = risk_meta(s)
                    findings_count = len(r.get("findings", []))
                    color = color_map[css]
                    with cols[idx]:
                        st.markdown(f"""
                        <div style="background:#ffffff;border:1px solid #dde2ea;
                                    border-top:3px solid {color};border-radius:8px;
                                    padding:1rem 1.2rem;text-align:center;
                                    box-shadow:0 1px 4px rgba(0,0,0,0.05);">
                            <div style="font-family:Arial,sans-serif;font-size:0.6rem;font-weight:700;
                                        letter-spacing:0.1em;text-transform:uppercase;color:#6b7a8d;
                                        margin-bottom:6px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">
                                {r["target"].split(":")[0]}
                            </div>
                            <div style="font-family:Arial,sans-serif;font-size:2rem;font-weight:700;color:{color};line-height:1;">
                                {s}<span style="font-size:0.85rem;color:#9aa5b4;font-weight:400">/10</span>
                            </div>
                            <div style="font-family:Arial,sans-serif;font-size:0.65rem;color:#9aa5b4;margin-top:5px;">
                                {lbl} · {findings_count} finding(s)
                            </div>
                        </div>
                        """, unsafe_allow_html=True)

                st.markdown(f"""
                <div class="cq-findings-panel">
                    <div class="cq-findings-header">
                        <span class="cq-findings-title">Bulk Remediation Summary</span>
                        <span class="cq-findings-badge">{len(batch_report.get("remediation_summary", []))} grouped actions</span>
                    </div>
                </div>
                """, unsafe_allow_html=True)
                bulk_remediation_cards = [
                    {
                        "component": item.get("component"),
                        "priority": item.get("priority"),
                        "issue": f"Affects {item.get('affected_targets', 0)} target(s)",
                        "recommended_action": item.get("recommended_action"),
                        "implementation_hint": "Apply this remediation across the impacted endpoints.",
                        "nist_references": [],
                        "hndl_priority": item.get("component") == "Key Exchange",
                    }
                    for item in batch_report.get("remediation_summary", [])[:8]
                ]
                st.markdown(build_remediation_html(bulk_remediation_cards), unsafe_allow_html=True)

                st.markdown(f"""
                <div class="cq-findings-panel">
                    <div class="cq-findings-header">
                        <span class="cq-findings-title">Bulk NIST PQC Mapping</span>
                        <span class="cq-findings-badge">{len(batch_report.get("nist_summary", []))} standards</span>
                    </div>
                </div>
                """, unsafe_allow_html=True)
                st.markdown(build_nist_html(batch_report.get("nist_summary", [])), unsafe_allow_html=True)

                st.markdown(f"""
                <div class="cq-cert-panel" style="margin-top:1rem;">
                    <div class="cq-cert-header">
                        <div class="cq-cert-icon-wrap">CB</div>
                        Bulk CBOM Summary
                    </div>
                    {build_cbom_html(batch_report.get("cbom", {}))}
                </div>
                """, unsafe_allow_html=True)
    
                st.markdown("""
                <div class="cq-section" style="margin-top:1.2rem;">
                    <div class="cq-section-num">5</div>
                    <div class="cq-section-label">Export Bulk Report</div>
                    <div class="cq-section-line"></div>
                </div>
                """, unsafe_allow_html=True)
    
                ecol1, _ = st.columns([1, 6])
                with ecol1:
                    st.download_button(
                        "⬇ Bulk JSON Report",
                        data=json.dumps(batch_report, indent=4),
                        file_name="cypherqube_bulk.json",
                        mime="application/json",
                        use_container_width=True
                    )
    
    
    st.markdown("""
    <div class="cq-footer">
        <div class="cq-footer-top">
            <div>
                <div class="cq-footer-brand-name">
                    <div class="cq-footer-brand-icon">CQ</div>
                    CypherQube
                </div>
                <div class="cq-footer-brand-desc">
                    CypherQube is an enterprise-grade post-quantum cryptography risk assessment
                    platform. Designed for financial institutions, critical infrastructure, and
                    regulated industries navigating the transition to NIST PQC standards.
                </div>
                <div class="cq-footer-cert-row">
                    <div class="cq-footer-cert">FIPS 203</div>
                    <div class="cq-footer-cert">FIPS 204</div>
                    <div class="cq-footer-cert">FIPS 205</div>
                    <div class="cq-footer-cert">FIPS 206</div>
                    <div class="cq-footer-cert">OpenSSL 3.x</div>
                    <div class="cq-footer-cert">MIT License</div>
                </div>
            </div>
            <div>
                <div class="cq-footer-col-title">Threat Coverage</div>
                <a class="cq-footer-link" href="https://en.wikipedia.org/wiki/Shor%27s_algorithm" target="_blank">Shor's Algorithm</a>
                <a class="cq-footer-link" href="https://en.wikipedia.org/wiki/Grover%27s_algorithm" target="_blank">Grover's Algorithm</a>
                <a class="cq-footer-link" href="https://csrc.nist.gov/projects/post-quantum-cryptography" target="_blank">Key Exchange Risk</a>
                <a class="cq-footer-link" href="https://csrc.nist.gov/projects/post-quantum-cryptography" target="_blank">Certificate Analysis</a>
                <a class="cq-footer-link" href="https://csrc.nist.gov/projects/post-quantum-cryptography" target="_blank">Cipher Suite Audit</a>
            </div>
            <div>
                <div class="cq-footer-col-title">NIST PQC Standards</div>
                <a class="cq-footer-link" href="https://csrc.nist.gov/pubs/fips/203/final" target="_blank">ML-KEM (CRYSTALS-Kyber)</a>
                <a class="cq-footer-link" href="https://csrc.nist.gov/pubs/fips/204/final" target="_blank">ML-DSA (CRYSTALS-Dilithium)</a>
                <a class="cq-footer-link" href="https://csrc.nist.gov/pubs/fips/205/final" target="_blank">SLH-DSA (SPHINCS+)</a>
                <a class="cq-footer-link" href="https://csrc.nist.gov/pubs/fips/206/final" target="_blank">FN-DSA (FALCON)</a>
                <a class="cq-footer-link" href="https://csrc.nist.gov/projects/post-quantum-cryptography" target="_blank">Hybrid PQC Schemes</a>
            </div>
        </div>
        <div class="cq-footer-bottom">
            <div class="cq-footer-copyright">
                © 2025 CypherQube. Released under the MIT License. Built for educational and research purposes.
                Not a substitute for a formal cryptographic security audit.
            </div>
            <div class="cq-footer-bottom-links">
                <a class="cq-footer-bottom-link" href="https://github.com/SiddharthRiot/cypherqube#readme" target="_blank">Documentation</a>
                <a class="cq-footer-bottom-link" href="https://github.com/SiddharthRiot/cypherqube" target="_blank">GitHub</a>
                <a class="cq-footer-bottom-link" href="https://csrc.nist.gov/projects/post-quantum-cryptography" target="_blank">NIST PQC Project</a>
                <a class="cq-footer-bottom-link" href="https://github.com/SiddharthRiot/cypherqube/issues/new?labels=bug&title=[Bug]%3A+" target="_blank">Report an Issue</a>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)
