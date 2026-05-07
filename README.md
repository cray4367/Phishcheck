# PhishCheck 🎣
**Advanced Email Phishing Forensic Analyzer**

PhishCheck is a powerful, local-first Python CLI tool designed to perform deep forensic analysis on `.eml` (email) files. It automatically extracts, scans, and scores emails against modern phishing tactics—including homograph attacks, tracking pixels, URL obfuscation, and embedded malicious attachments.

---

## 🌟 Key Features

* **Advanced Header Forensics**: Validates SPF/DKIM/DMARC records, detects Reply-To mismatches, and flags suspicious `X-Mailer` agents (e.g., automated scripts spoofing humans).
* **URL Reputation & Unshortening**: Unrolls shortened links (`bit.ly`, `tinyurl`) to their true destination, checks for Typosquatting (brand impersonation), and queries the VirusTotal API for domain reputation.
* **Homograph (Punycode) Detection**: Detects `xn--` domains and zero-width characters used to trick users into thinking a link is legitimate (e.g., `аррӏе.com` vs `apple.com`).
* **Quishing (QR Code) Detection**: Extracts embedded images and scans them for hidden QR codes containing malicious URLs.
* **HTML Evasion Detection**: Flags 1x1 tracking pixels and off-screen text rendering (`left: -9999px`) used by attackers to bypass spam filters.
* **Urgency & Tone Analysis**: Highlights high-pressure social engineering tactics in the email body.
* **Attachment Extraction & Scanning**: Extracts files, dumps readable strings, and scans file hashes against VirusTotal.

---

## ⚙️ Installation & Setup

PhishCheck requires Python 3.8 or higher.

### 1. Clone the repository and create a Virtual Environment
It's highly recommended to run this tool inside a Python Virtual Environment to avoid dependency conflicts.
```bash
git clone https://github.com/cray4367/Phishcheck.git
cd Phishcheck

# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate
```

### 2. Install System Dependencies (For QR Code Scanning)
To enable "Quishing" (QR code) detection, you must have the `zbar` shared library installed on your system:
* **Ubuntu/Debian**: `sudo apt-get install libzbar0`
* **macOS**: `brew install zbar`
* **Arch Linux**: `sudo pacman -S zbar`

### 3. Install Python Requirements
```bash
pip install -r requirements.txt
```

---

## 🔑 Setting up the VirusTotal API Key

PhishCheck uses VirusTotal to score the reputation of extracted URLs and file attachments. **You need a free VirusTotal API key to use this feature.**

### How to get a free API Key:
1. Go to [VirusTotal.com](https://www.virustotal.com/) and click **Sign Up** in the top right corner.
2. Create a free account and verify your email address.
3. Once logged in, click on your profile icon in the top right and select **API key**.
4. Copy the long alphanumeric string displayed on that page.

### Adding the key to PhishCheck:
1. In the root directory of the PhishCheck project, create a new file named exactly **`.env`** (or rename the provided `.env.example`).
2. Open the `.env` file and paste your API key like this:
```ini
VIRUSTOTAL_API_KEY=your_copied_api_key_here
```
*Note: The `.env` file is ignored by Git, so your API key will remain private.*

---

## 🚀 Usage Guide

Once installed and configured, you run the analyzer by passing an `.eml` file to `main.py`.

### Basic Analysis
Run a standard analysis. The tool will print an ANSI-colored forensic report directly to your terminal.
```bash
python main.py --file path/to/suspicious_email.eml
```

### Verbose Mode
Prints exactly which URLs and Attachments were extracted and scanned.
```bash
python main.py --file path/to/suspicious_email.eml --verbose
```

### Skip VirusTotal
If you don't have an API key yet, or want to run an offline/air-gapped scan without reaching out to external servers, use the `--no-vt` flag.
```bash
python main.py --file path/to/suspicious_email.eml --no-vt
```

### Export to Text File
Saves the clean (color-code stripped) report to a text file for sharing or archiving.
```bash
python main.py --file path/to/suspicious_email.eml --output report.txt
```

### JSON Output (For Automation)
If you want to pipe the results into another tool or SIEM, use the JSON flag.
```bash
python main.py --file path/to/suspicious_email.eml --json
```

---

## 📊 Understanding the Score

PhishCheck evaluates the email across multiple vectors and assigns penalty points. The final score ranges from 0 to 100:

* 🟢 **SAFE (0 - 39)**: No major red flags detected. 
* 🟡 **SUSPICIOUS (40 - 69)**: Multiple minor anomalies or a single major red flag (like a Typosquatted URL). Treat with caution.
* 🔴 **MALICIOUS (70 - 100)**: Definite phishing indicators found, such as failed DMARC paired with urgency, or a VirusTotal-flagged attachment. Do not interact with the email contents.
