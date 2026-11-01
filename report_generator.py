"""
report_generator.py - PhishGuard CSV Report Writer
----------------------------------------------------
Analyzes all emails and writes the findings to a CSV file.

Usage (from terminal):
    python report_generator.py

This will create  phishguard/report.csv  with one row per email analyzed.
"""

import csv
import os
import pathlib
from datetime import datetime

# Import our own analyzer module
from analyzer import analyze_all_emails


# ---------------------------------------------------------------------------
# CSV column names
# ---------------------------------------------------------------------------
CSV_COLUMNS = [
    "Timestamp",
    "Filename",
    "Risk Level",
    "Score",
    "Indicators Found",
    "Indicator Names",
    "File Path",
]


def generate_report(emails_dir: str, output_path: str) -> str:
    """
    Analyze all emails and write results to a CSV file.

    Parameters
    ----------
    emails_dir  : str  - folder containing .txt email files
    output_path : str  - where to save the CSV report

    Returns
    -------
    str - path to the created CSV file
    """
    print(f"\n[PhishGuard] Scanning emails in: {emails_dir}")
    results = analyze_all_emails(emails_dir)

    if not results:
        print("[PhishGuard] No emails found. Nothing to report.")
        return ""

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=CSV_COLUMNS)
        writer.writeheader()

        for r in results:
            # Build a readable list of triggered indicator names
            indicator_names = "; ".join(t["name"] for t in r["triggered"]) if r["triggered"] else "None"
            indicator_count = len(r["triggered"])

            writer.writerow({
                "Timestamp":        timestamp,
                "Filename":         r["filename"],
                "Risk Level":       r["risk_level"],
                "Score":            r["score"],
                "Indicators Found": indicator_count,
                "Indicator Names":  indicator_names,
                "File Path":        r["filepath"],
            })

    print(f"\n[PhishGuard] Report saved to: {output_path}")
    print(f"[PhishGuard] {len(results)} email(s) analyzed.\n")
    return output_path


# ---------------------------------------------------------------------------
# Run directly from terminal
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # Resolve paths relative to this script file
    base_dir    = pathlib.Path(__file__).parent
    emails_dir  = str(base_dir / "emails")
    output_path = str(base_dir / "report.csv")

    generated = generate_report(emails_dir, output_path)

    if generated:
        print("=== Report Preview ===")
        # Print the CSV to terminal for a quick look
        with open(generated, "r", encoding="utf-8") as f:
            print(f.read())
