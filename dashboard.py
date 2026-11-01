"""
dashboard.py - PhishGuard Streamlit Dashboard
----------------------------------------------
A beginner-friendly web dashboard to analyze email files for phishing threats.

Run with:
    streamlit run dashboard.py
"""

import os
import pathlib
import csv
from datetime import datetime

import streamlit as st

# Import our own modules
from analyzer import analyze_email, analyze_all_emails
from report_generator import generate_report

# ---------------------------------------------------------------------------
# Page configuration — must be the first Streamlit call
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="PhishGuard – Email Threat Detector",
    page_icon="🛡️",
    layout="wide",
)

# ---------------------------------------------------------------------------
# Helper: base paths
# ---------------------------------------------------------------------------
BASE_DIR   = pathlib.Path(__file__).parent
EMAILS_DIR = BASE_DIR / "emails"
REPORT_PATH = BASE_DIR / "report.csv"


# ---------------------------------------------------------------------------
# Helper: risk level badge styling
# ---------------------------------------------------------------------------
RISK_STYLE = {
    "LOW":    ("🟢", "#1e8a2e", "#d4edda"),
    "MEDIUM": ("🟡", "#856404", "#fff3cd"),
    "HIGH":   ("🔴", "#721c24", "#f8d7da"),
    "ERROR":  ("⚠️", "#555555", "#eeeeee"),
}

def risk_badge(level: str) -> str:
    """Return an HTML badge for the given risk level."""
    icon, color, bg = RISK_STYLE.get(level, RISK_STYLE["ERROR"])
    return (
        f'<span style="background:{bg}; color:{color}; font-weight:bold; '
        f'padding:4px 14px; border-radius:20px; font-size:1rem;">'
        f'{icon} {level}</span>'
    )


# ---------------------------------------------------------------------------
# Sidebar – navigation
# ---------------------------------------------------------------------------
st.sidebar.image("https://img.icons8.com/fluency/96/shield.png", width=80)
st.sidebar.title("PhishGuard")
st.sidebar.caption("Email Threat Detector")
st.sidebar.markdown("---")

page = st.sidebar.radio(
    "Navigate",
    ["🔍 Analyze Single Email", "📊 Analyze All & Report"],
    label_visibility="collapsed",
)

st.sidebar.markdown("---")
st.sidebar.markdown(
    "**How risk levels work:**\n\n"
    "🟢 **LOW** — 0–2 points\n\n"
    "🟡 **MEDIUM** — 3–5 points\n\n"
    "🔴 **HIGH** — 6+ points"
)


# ===========================================================================
# PAGE 1 – Analyze Single Email
# ===========================================================================
if page == "🔍 Analyze Single Email":

    st.title("🛡️ PhishGuard – Email Threat Detector")
    st.markdown("Select an email file below to scan it for phishing indicators.")
    st.markdown("---")

    # List available email files
    email_files = sorted([f for f in os.listdir(EMAILS_DIR) if f.endswith(".txt")])

    if not email_files:
        st.warning("No .txt email files found in the `emails/` folder.")
        st.stop()

    selected_file = st.selectbox("📂 Choose an email file to analyze:", email_files)
    selected_path = EMAILS_DIR / selected_file

    # Analyze on button click (or when selection changes)
    if st.button("🔍 Analyze Email", type="primary") or selected_file:
        result = analyze_email(str(selected_path))

        col1, col2 = st.columns([1, 2])

        # --- Left column: Risk summary ---
        with col1:
            st.subheader("Risk Assessment")
            st.markdown(risk_badge(result["risk_level"]), unsafe_allow_html=True)
            st.markdown(f"**Risk Score:** `{result['score']} points`")
            st.markdown(f"**Indicators Found:** `{len(result['triggered'])}`")
            st.markdown(f"**File:** `{result['filename']}`")

        # --- Right column: Triggered indicators ---
        with col2:
            st.subheader("⚠️ Triggered Indicators")
            if result["triggered"]:
                for t in result["triggered"]:
                    with st.expander(f"🚩 {t['name']}  (+{t['points']} pts)"):
                        st.markdown(f"**Why this matters:** {t['description']}")
            else:
                st.success("✅ No phishing indicators were detected in this email.")

        st.markdown("---")

        # --- Email content preview ---
        st.subheader("📧 Email Content Preview")
        st.text_area(
            label="Raw Email Text",
            value=result["email_text"],
            height=300,
            label_visibility="collapsed",
        )

        # --- Beginner tip ---
        st.markdown("---")
        st.info(
            "💡 **Tip for beginners:** Even a LOW risk email might be suspicious. "
            "Always verify the sender's domain and avoid clicking unfamiliar links."
        )


# ===========================================================================
# PAGE 2 – Analyze All & Report
# ===========================================================================
elif page == "📊 Analyze All & Report":

    st.title("📊 Analyze All Emails & Generate Report")
    st.markdown("Scan every email in the `emails/` folder and export a CSV security report.")
    st.markdown("---")

    if st.button("🚀 Run Full Scan & Generate Report", type="primary"):
        with st.spinner("Scanning all emails…"):
            results = analyze_all_emails(str(EMAILS_DIR))
            generate_report(str(EMAILS_DIR), str(REPORT_PATH))

        st.success(f"✅ Scan complete! {len(results)} email(s) analyzed.")
        st.markdown("---")

        # --- Summary metrics row ---
        high   = sum(1 for r in results if r["risk_level"] == "HIGH")
        medium = sum(1 for r in results if r["risk_level"] == "MEDIUM")
        low    = sum(1 for r in results if r["risk_level"] == "LOW")

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Total Emails", len(results))
        m2.metric("🔴 HIGH Risk",   high)
        m3.metric("🟡 MEDIUM Risk", medium)
        m4.metric("🟢 LOW Risk",    low)

        st.markdown("---")

        # --- Results table ---
        st.subheader("📋 Scan Results")

        for r in results:
            icon, color, bg = RISK_STYLE.get(r["risk_level"], RISK_STYLE["ERROR"])
            indicator_names = ", ".join(t["name"] for t in r["triggered"]) or "None"

            with st.expander(
                f"{icon} {r['filename']}  —  Score: {r['score']}  |  Risk: {r['risk_level']}"
            ):
                st.markdown(risk_badge(r["risk_level"]), unsafe_allow_html=True)
                st.markdown(f"**Score:** `{r['score']}`")
                st.markdown(f"**Indicators:** {indicator_names}")

                if r["triggered"]:
                    st.markdown("**Details:**")
                    for t in r["triggered"]:
                        st.markdown(f"- 🚩 **{t['name']}** (+{t['points']} pts): {t['description']}")

        st.markdown("---")

        # --- CSV download ---
        st.subheader("⬇️ Download Report")
        if REPORT_PATH.exists():
            with open(REPORT_PATH, "r", encoding="utf-8") as f:
                csv_data = f.read()

            st.download_button(
                label="📥 Download report.csv",
                data=csv_data,
                file_name=f"phishguard_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
            )
            st.markdown("*The report is also saved as `phishguard/report.csv` on disk.*")

    else:
        st.info("👆 Click the button above to start the full scan.")
        st.markdown(
            "The scan will:\n"
            "1. Read every `.txt` file in the `emails/` folder\n"
            "2. Check each email for phishing indicators\n"
            "3. Assign a risk level (LOW / MEDIUM / HIGH)\n"
            "4. Save a `report.csv` file you can download"
        )
