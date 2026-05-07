# PhishCheck: Advanced Email Phishing Forensic Analyzer

## Overview

PhishCheck is a robust, local-first Python command-line interface (CLI) tool designed for deep forensic analysis of `.eml` (email) files. It serves as an automated first-pass triage tool for security operations centers (SOC) and incident responders. PhishCheck parses emails to extract, analyze, and score potential indicators of compromise (IoCs) across modern phishing tactics, including homograph attacks, tracking pixels, URL obfuscation, WHOIS anomalies, and malicious attachments.

---

## Capabilities and Features

### 1. Header Forensics and Authentication Analysis
* **Authentication Validation**: Validates SPF, DKIM, and DMARC records. Failures are heavily penalized as they are primary indicators of spoofing.
* **Domain Mismatch Detection**: Flags inconsistencies between the `From`, `Reply-To`, and `Message-ID` header domains.
* **Mailer Agent Analysis**: Identifies suspicious `X-Mailer` and `User-Agent` strings (e.g., detecting automated scripts like `PHPMailer` or `Python-urllib` spoofing corporate entities).
* **Routing Path Anomalies**: Scans the `Received` chain for RFC-1918 internal IP addresses indicating forged routing hops.

### 2. Advanced URL Reputation and Intelligence
* **URL Unshortening**: Automatically resolves shortened links (e.g., `bit.ly`, `tinyurl.com`) to their true destination prior to analysis.
* **Homograph and Punycode Detection**: Identifies `xn--` domains and zero-width characters utilized to trick users via visual spoofing.
* **Typosquatting Detection**: Uses Levenshtein distance algorithms to calculate proximity to known high-value targets (e.g., financial institutions, tech giants).
* **VirusTotal API Integration**: Queries the VirusTotal API to determine the external reputation of extracted URLs.

### 3. WHOIS Domain Intelligence
* **Domain Age**: Performs WHOIS lookups on extracted domains. Domains registered within the last 30 days are flagged as high risk (temporary phishing infrastructure).
* **Domain Expiration**: Flags domains expiring within 30 days, a common trait of short-lived malicious campaigns.
* **WHOIS Privacy Checks**: Detects the use of WHOIS privacy protection proxies, which attackers frequently use to obscure their identities.

### 4. Body Content and Evasion Detection
* **HTML Evasion Detection**: Flags CSS attributes designed to bypass textual spam filters, including off-screen rendering (`left: -9999px`), zero-font sizes, and 1x1 tracking pixels.
* **Urgency and Tone Analysis**: Highlights high-pressure social engineering keywords within the email body.
* **Unicode Inconsistencies**: Detects the mixing of disparate character scripts (e.g., Cyrillic characters mixed within Latin text) used for homoglyph evasion.

### 5. Attachment Extraction and Quishing Detection
* **QR Code (Quishing) Scanning**: Extracts embedded images and utilizes the `zbar` library to scan for hidden QR codes containing malicious URLs.
* **File Hashing and Reputation**: Hashes all extracted attachments (SHA-256) and queries the VirusTotal API for known malware signatures.
* **Embedded Strings Analysis**: Dumps readable ASCII strings from binary attachments to extract hidden URLs.

---

## Installation and Setup Requirements

PhishCheck requires **Python 3.8 or higher**.

### 1. Repository Configuration
It is recommended to run this tool inside a Python Virtual Environment to maintain isolated dependencies.

```bash
git clone https://github.com/cray4367/Phishcheck.git
cd Phishcheck

# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate
```

### 2. System Level Dependencies
To enable the QR code scanning module, the `zbar` shared library must be installed on your host operating system:

* **Ubuntu/Debian**: `sudo apt-get install libzbar0`
* **macOS**: `brew install zbar`
* **Arch Linux**: `sudo pacman -S zbar`

### 3. Python Package Installation
Install the required Python modules via `pip`:
```bash
pip install -r requirements.txt
```

---

## Configuration: VirusTotal API Integration

PhishCheck leverages the VirusTotal API for external reputation scoring. An API key is required to utilize this functionality.

### Provisioning the API Key:
1. Navigate to [VirusTotal](https://www.virustotal.com/) and register for a free account.
2. Access your profile settings and navigate to the **API key** section.
3. Copy the provided alphanumeric API key.

### Implementing the Key:
1. In the root directory of the PhishCheck project, create a new file named exactly **`.env`** (you may also rename the provided `.env.example`).
2. Populate the `.env` file with the following variable:
```ini
VIRUSTOTAL_API_KEY=your_copied_api_key_here
```
*Note: The `.env` file is explicitly ignored by version control to ensure operational security.*

---

## Usage Documentation

Execute the analyzer by passing a target `.eml` file to the main script.

### Standard Execution
Performs a full forensic analysis and outputs an ANSI-colored report to stdout.
```bash
python main.py --file path/to/suspicious_email.eml
```

### Verbose Mode
Appends detailed extraction data to the report, including the specific URLs and Attachments processed.
```bash
python main.py --file path/to/suspicious_email.eml --verbose
```

### Offline / Air-Gapped Mode
Bypasses the VirusTotal API integration. Useful for rapid execution or when operating in restrictive network environments.
```bash
python main.py --file path/to/suspicious_email.eml --no-vt
```

### JSON Data Export
Outputs the raw forensic data and scoring matrices as a structured JSON object, suitable for ingestion into SIEM platforms or automation pipelines.
```bash
python main.py --file path/to/suspicious_email.eml --json
```

### Plain Text Export
Strips ANSI color codes and writes the assessment to a specified text file for archival.
```bash
python main.py --file path/to/suspicious_email.eml --output assessment_report.txt
```

---

## Threat Scoring Matrix

PhishCheck aggregates penalties across all analysis modules to determine a final confidence score, capped at 100 points.

* **SAFE (0 - 39)**: Standard communication. No significant indicators of compromise detected.
* **SUSPICIOUS (40 - 69)**: Multiple minor anomalies or a single major red flag (e.g., Typosquatted URL, WHOIS age < 30 days) detected. Requires manual analyst review.
* **MALICIOUS (70 - 100)**: Critical threat indicators identified (e.g., failed DMARC paired with urgency, malicious QR code, VirusTotal-flagged payload). High confidence of phishing attempt.
