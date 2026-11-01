"""
analyzer.py - PhishGuard Core Detection Engine
------------------------------------------------
Scans email text files for phishing indicators and assigns a risk level.

Risk Scoring:
  0-2  points  -> LOW
  3-5  points  -> MEDIUM
  6+   points  -> HIGH
"""

import re
import os


# ---------------------------------------------------------------------------
# Indicator definitions
# Each entry is a dict with:
#   name        - short label shown in reports
#   description - plain-English explanation for beginners
#   pattern     - compiled regex OR None (for custom checks)
#   points      - how much this indicator adds to the risk score
# ---------------------------------------------------------------------------

INDICATORS = [
    {
        "name": "IP-Based URL",
        "description": "Links that use raw IP addresses instead of real domain names are a strong phishing sign.",
        "pattern": re.compile(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', re.IGNORECASE),
        "points": 3,
    },
    {
        "name": "Suspicious URL (HTTP, not HTTPS)",
        "description": "Legitimate companies use secure HTTPS links. Plain HTTP links may indicate a fake site.",
        "pattern": re.compile(r'\bhttp://[^\s]+', re.IGNORECASE),
        "points": 2,
    },
    {
        "name": "URL Shortener",
        "description": "Shortened links (bit.ly, tinyurl, etc.) hide the real destination and are often used in phishing.",
        "pattern": re.compile(
            r'https?://(bit\.ly|tinyurl\.com|goo\.gl|t\.co|ow\.ly|is\.gd|buff\.ly|'
            r'adf\.ly|short\.link|rb\.gy|cutt\.ly)/[^\s]+',
            re.IGNORECASE
        ),
        "points": 2,
    },
    {
        "name": "Suspicious Domain Extension",
        "description": "Unusual domain extensions like .ru, .tk, .xyz, .net used for known brands are suspicious.",
        "pattern": re.compile(r'https?://[^\s]+\.(ru|tk|xyz|info|top|click|loan|win|gq|cf|ml|ga)[/\s]', re.IGNORECASE),
        "points": 2,
    },
    {
        "name": "Urgency Language",
        "description": "Phishing emails pressure you to act fast. Words like 'immediately', 'urgent', '24 hours' are red flags.",
        "pattern": re.compile(
            r'\b(urgent|immediately|act now|verify now|account suspended|limited time|'
            r'expires in|will be deleted|will be locked|will be closed|'
            r'last chance|final notice|respond immediately|click now|'
            r'within \d+ hours?|within \d+ minutes?)\b',
            re.IGNORECASE
        ),
        "points": 2,
    },
    {
        "name": "Credential Request",
        "description": "Legitimate companies never ask for passwords, card numbers, or SSNs via email.",
        "pattern": re.compile(
            r'\b(password|credit card|card number|social security|ssn|'
            r'bank account|pin number|date of birth|mother\'?s maiden name)\b',
            re.IGNORECASE
        ),
        "points": 3,
    },
    {
        "name": "Generic Greeting",
        "description": "'Dear Customer' or 'Dear User' instead of your real name suggests a mass phishing campaign.",
        "pattern": re.compile(r'\b(dear (customer|user|valued customer|account holder|member))\b', re.IGNORECASE),
        "points": 1,
    },
    {
        "name": "Excessive Exclamation Marks",
        "description": "Multiple '!!!' is a common tactic to create panic and urgency in phishing emails.",
        "pattern": re.compile(r'!!!+'),
        "points": 1,
    },
    {
        "name": "ALL CAPS Words",
        "description": "Shouting in all caps (e.g. 'CLICK NOW', 'FREE') is used to trigger emotional reactions.",
        "pattern": re.compile(r'\b[A-Z]{4,}\b'),
        "points": 1,
    },
    {
        "name": "Brand Impersonation (Misspelling)",
        "description": "Attackers misspell brand names (paypa1, amaz0n) to create fake-but-similar-looking domains.",
        "pattern": re.compile(
            # Only match when a digit substitution is actually used (1 for l/i, 0 for o)
            r'\b(paypa1[.\-]|amaz0n[.\-]|g00gle[.\-]|micr0s0ft[.\-]|'
            r'app1e[.\-]|faceb00k[.\-]|netfl1x[.\-])',
            re.IGNORECASE
        ),
        "points": 3,
    },
    {
        "name": "Prize / Lottery Scam Language",
        "description": "Claims of winning a prize you never entered are a classic phishing lure.",
        "pattern": re.compile(
            r'\b(you (have |\'ve )?(won|been selected|been chosen)|'
            r'congratulations.{0,30}(winner|prize|reward|selected)|'
            r'free (iphone|ipad|gift card|prize|reward))\b',
            re.IGNORECASE
        ),
        "points": 2,
    },
    {
        "name": "Sender Domain Mismatch",
        "description": "The 'From' domain doesn't match the brand name in the email body.",
        "pattern": None,  # handled by custom check below
        "points": 2,
    },
]

# Brands to check for domain mismatch: brand keyword -> list of legitimate domains
BRAND_DOMAINS = {
    "paypal":    ["paypal.com"],
    "amazon":    ["amazon.com", "amazon.co.uk"],
    "google":    ["google.com", "accounts.google.com"],
    "microsoft": ["microsoft.com", "live.com", "outlook.com"],
    "apple":     ["apple.com", "icloud.com"],
    "facebook":  ["facebook.com", "fb.com"],
    "netflix":   ["netflix.com"],
    "spotify":   ["spotify.com"],
}


def _check_sender_mismatch(text: str) -> bool:
    """
    Returns True if the email body mentions a well-known brand but the
    'From:' header comes from a different (suspicious) domain.
    """
    # Extract the sender domain from the From: line
    from_match = re.search(r'^From:\s*.+@([\w.\-]+)', text, re.IGNORECASE | re.MULTILINE)
    if not from_match:
        return False

    sender_domain = from_match.group(1).lower()

    # Check if any brand appears in the body
    body = text.lower()
    for brand, legit_domains in BRAND_DOMAINS.items():
        if brand in body:
            # If sender domain is NOT one of the legit domains → mismatch
            if not any(sender_domain == legit or sender_domain.endswith("." + legit)
                       for legit in legit_domains):
                return True
    return False


def _score_to_risk(score: int) -> str:
    """Convert a numeric score to a human-readable risk level."""
    if score <= 2:
        return "LOW"
    elif score <= 5:
        return "MEDIUM"
    else:
        return "HIGH"


def analyze_email(filepath: str) -> dict:
    """
    Analyze a single email text file.

    Parameters
    ----------
    filepath : str
        Path to the .txt email file.

    Returns
    -------
    dict with keys:
        filename      - base name of the file
        filepath      - full path
        risk_level    - "LOW", "MEDIUM", or "HIGH"
        score         - integer risk score
        triggered     - list of triggered indicator dicts
        email_text    - raw email content
    """
    filename = os.path.basename(filepath)

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            email_text = f.read()
    except Exception as e:
        return {
            "filename": filename,
            "filepath": filepath,
            "risk_level": "ERROR",
            "score": 0,
            "triggered": [],
            "email_text": f"Could not read file: {e}",
        }

    total_score = 0
    triggered = []

    for indicator in INDICATORS:
        if indicator["pattern"] is not None:
            # Regex-based check
            if indicator["pattern"].search(email_text):
                total_score += indicator["points"]
                triggered.append({
                    "name": indicator["name"],
                    "description": indicator["description"],
                    "points": indicator["points"],
                })
        else:
            # Custom check: sender domain mismatch
            if indicator["name"] == "Sender Domain Mismatch":
                if _check_sender_mismatch(email_text):
                    total_score += indicator["points"]
                    triggered.append({
                        "name": indicator["name"],
                        "description": indicator["description"],
                        "points": indicator["points"],
                    })

    risk_level = _score_to_risk(total_score)

    return {
        "filename": filename,
        "filepath": filepath,
        "risk_level": risk_level,
        "score": total_score,
        "triggered": triggered,
        "email_text": email_text,
    }


def analyze_all_emails(emails_dir: str) -> list:
    """
    Analyze every .txt file found in the given directory.

    Parameters
    ----------
    emails_dir : str
        Path to the folder containing email .txt files.

    Returns
    -------
    list of result dicts (one per email), sorted by score descending.
    """
    results = []

    if not os.path.isdir(emails_dir):
        print(f"[ERROR] Directory not found: {emails_dir}")
        return results

    for fname in sorted(os.listdir(emails_dir)):
        if fname.endswith(".txt"):
            fpath = os.path.join(emails_dir, fname)
            result = analyze_email(fpath)
            results.append(result)
            print(f"  Analyzed: {fname:35s} → Score: {result['score']:2d}  Risk: {result['risk_level']}")

    # Sort highest risk first
    results.sort(key=lambda r: r["score"], reverse=True)
    return results


# ---------------------------------------------------------------------------
# Quick self-test: run this file directly to see results in the terminal
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import pathlib

    script_dir = pathlib.Path(__file__).parent
    emails_dir = script_dir / "emails"

    print("\n=== PhishGuard – Email Threat Detector ===\n")
    print(f"Scanning emails in: {emails_dir}\n")

    results = analyze_all_emails(str(emails_dir))

    print("\n--- Results Summary ---")
    for r in results:
        print(f"  {r['filename']:35s} | Risk: {r['risk_level']:6s} | Score: {r['score']}")
        for t in r["triggered"]:
            print(f"      ⚠  {t['name']} (+{t['points']})")
    print()
