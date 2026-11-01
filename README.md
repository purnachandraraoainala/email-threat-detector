# 🛡️ PhishGuard – Email Threat Detector

A beginner-friendly Python cybersecurity project that analyzes email text files
for phishing indicators and assigns risk levels (LOW / MEDIUM / HIGH).

---

## 📁 Project Structure

```
phishguard/
├── emails/                     # Sample email .txt files
│   ├── safe_email_1.txt        # Safe: Spotify newsletter
│   ├── safe_email_2.txt        # Safe: Amazon order shipped
│   ├── phishing_email_1.txt    # HIGH risk: PayPal suspension scam
│   ├── phishing_email_2.txt    # HIGH risk: Fake Amazon prize
│   └── phishing_email_3.txt    # HIGH risk: Fake IT helpdesk reset
├── analyzer.py                 # Core detection engine
├── report_generator.py         # CSV report writer
├── dashboard.py                # Streamlit web dashboard
├── requirements.txt            # Python dependencies
└── README.md                   # This file
```

---

## 🚀 Quick Start

### 1. Install dependencies
```bash
cd phishguard
pip install -r requirements.txt
```

### 2. Run the terminal analyzer (no dashboard needed)
```bash
python analyzer.py
```

### 3. Generate a CSV report from the terminal
```bash
python report_generator.py
```

### 4. Launch the Streamlit dashboard
```bash
streamlit run dashboard.py
```
Then open **http://localhost:8501** in your browser.

---

## 🔍 Detection Indicators

| Indicator                        | Points | Why It Matters |
|----------------------------------|--------|----------------|
| IP-Based URL                     | +3     | Hides real identity with a raw IP |
| Credential Request               | +3     | Real companies never ask for passwords via email |
| Brand Impersonation (Misspelling)| +3     | Fake domains mimic real brands |
| Suspicious URL (HTTP)            | +2     | Missing HTTPS encryption |
| URL Shortener                    | +2     | Hides the true destination |
| Suspicious Domain Extension      | +2     | .ru, .tk, .xyz, etc. on known brands |
| Urgency Language                 | +2     | Pressures you to act without thinking |
| Sender Domain Mismatch           | +2     | From address doesn't match the brand |
| Prize / Lottery Scam Language    | +2     | Classic lure |
| Generic Greeting                 | +1     | Mass phishing uses "Dear Customer" |
| Excessive Exclamation Marks      | +1     | Creates panic |
| ALL CAPS Words                   | +1     | Emotional manipulation |

### Risk Levels

| Score  | Risk Level |
|--------|------------|
| 0 – 2  | 🟢 LOW     |
| 3 – 5  | 🟡 MEDIUM  |
| 6 +    | 🔴 HIGH    |

---

## 📊 CSV Report

Running `report_generator.py` or clicking **Run Full Scan** in the dashboard
creates a `report.csv` file with these columns:

- `Timestamp` – when the scan was run
- `Filename` – email file name
- `Risk Level` – LOW / MEDIUM / HIGH
- `Score` – numeric risk score
- `Indicators Found` – count of triggered indicators
- `Indicator Names` – names of all triggered indicators
- `File Path` – full path to the email file

---

## 🧪 Adding Your Own Test Emails

1. Create a plain `.txt` file inside the `emails/` folder.
2. Write (or paste) an email in this format:
   ```
   From: sender@example.com
   To: recipient@example.com
   Subject: Your Subject Here

   Email body goes here...
   ```
3. Run the analyzer — PhishGuard will pick it up automatically.

---

## 🧠 How It Works (Beginner Explanation)

1. **`analyzer.py`** reads each email `.txt` file and runs it through a list of
   regular-expression patterns (regex). Each pattern looks for a specific
   phishing trick (e.g., IP addresses in links, words like "verify now").

2. Every matched pattern adds points to a **risk score**.

3. The score is converted to a **risk level** (LOW / MEDIUM / HIGH).

4. **`report_generator.py`** collects all results and writes them to a
   structured CSV file.

5. **`dashboard.py`** wraps everything in a Streamlit web app so you can
   browse and download results with a clean interface.

---

## 📦 Dependencies

| Library    | Purpose             | Standard Library? |
|------------|---------------------|-------------------|
| `streamlit`| Web dashboard UI    | No (pip install)  |
| `re`       | Regex pattern matching | Yes ✅           |
| `csv`      | CSV file writing    | Yes ✅            |
| `os`       | File system access  | Yes ✅            |
| `pathlib`  | Path handling       | Yes ✅            |
| `datetime` | Timestamps          | Yes ✅            |
