import argparse
import json
import sys

from phishcheck.config import get_vt_api_key
from phishcheck.parser import parse_eml, extract_body
from phishcheck.header_analysis import analyze_headers
from phishcheck.body_analysis import analyze_body
from phishcheck.url_analysis import analyze_urls
from phishcheck.attachments import extract_and_scan_attachments

def print_banner():
    banner = """\033[1m\033[36m
 ____  _     _     _      ____  _     ____  ____  _  __
/  __\/ \ /|/ \   / \__/|/  __\/ \ /|/  _ \/   _\/ |/ /
|  \/|| |_||| |   | |\/|||  \/|| |_||| / \||  /  |   / 
|  __/| | ||| |   | |  |||    /| | ||| |-|||  \_ |   \ 
\_/   \_/ \|\_/   \_/  \|\_/\_\\_/ \|\_/ \|\____/\_|\_\\
                                                       
    Email Phishing Forensic Analyzer
\033[0m"""
    print(banner)

def main():
    parser = argparse.ArgumentParser(description="Deep Forensic Analysis of .eml files for Phishing Indicators.")
    parser.add_argument("--file", "-f", required=True, help="Path to the .eml file to analyze")
    parser.add_argument("--verbose", "-v", action="store_true", help="Print detailed extraction data")
    parser.add_argument("--json", "-j", action="store_true", help="Output results in JSON format")
    parser.add_argument("--output", "-o", help="Save text report to specified file")
    parser.add_argument("--no-vt", action="store_true", help="Skip VirusTotal attachment scanning")
    args = parser.parse_args()

    api_key = get_vt_api_key()
    if not api_key and not args.no_vt:
        sys.stderr.write("\033[33m[!] Warning: VIRUSTOTAL_API_KEY not found in .env. Attachment scanning will skip VT.\033[0m\n")

    if not args.json:
        print_banner()

    msg = parse_eml(args.file)
    if not msg:
        sys.exit(1)

    text_body, html_body = extract_body(msg)
    
    # Run all phases
    all_penalties = []
    
    header_penalties = analyze_headers(msg)
    all_penalties.extend(header_penalties)
    
    body_penalties = analyze_body(text_body, html_body)
    all_penalties.extend(body_penalties)
    
    url_penalties, urls = analyze_urls(text_body, html_body, api_key, args.no_vt)
    all_penalties.extend(url_penalties)
    
    attachment_penalties, attachments = extract_and_scan_attachments(msg, api_key, args.no_vt)
    all_penalties.extend(attachment_penalties)
    
    # Calculate Final Score
    total_points = sum(p["points"] for p in all_penalties)
    final_score = min(100, total_points)
    
    if final_score < 40:
        trust_level = "SAFE"
        color = "\033[32m" # Green
    elif final_score < 70:
        trust_level = "SUSPICIOUS"
        color = "\033[33m" # Yellow
    else:
        trust_level = "MALICIOUS"
        color = "\033[31m" # Red

    # JSON Output
    if args.json:
        report = {
            "score": final_score,
            "trust_level": trust_level,
            "penalties": all_penalties,
            "urls_found": urls,
            "attachments_found": attachments
        }
        print(json.dumps(report, indent=2))
        return 0

    # Text Output
    output_lines = []
    output_lines.append(f"{color}\033[1m=== FINAL ASSESSMENT ===\033[0m")
    output_lines.append(f"{color}Score: {final_score}/100\033[0m")
    output_lines.append(f"{color}Status: {trust_level}\033[0m\n")

    if all_penalties:
        output_lines.append("\033[1m--- Red Flags Detected ---\033[0m")
        for p in all_penalties:
            output_lines.append(f"  [\033[31m+{p['points']} pts\033[0m] {p['reason']}")
    else:
         output_lines.append("\033[32m  No red flags detected.\033[0m")
         
    output_lines.append("\n\033[1m--- Extracted Indicators ---\033[0m")
    output_lines.append(f"  URLs Found: {len(urls)}")
    if args.verbose and urls:
         for u in urls:
             output_lines.append(f"    - {u['url']} | VT: {u['virustotal']}")
             
    output_lines.append(f"  Attachments Found: {len(attachments)}")
    if args.verbose and attachments:
         for a in attachments:
             output_lines.append(f"    - {a['filename']} | SHA256: {a['hash'][:16]}... | VT: {a['virustotal']}")

    report_text = "\n".join(output_lines)
    print(report_text)
    print("\n\033[1mAnalysis Complete.\033[0m")

    if args.output:
        # Strip ANSI codes for file output
        clean_text = report_text.replace("\033[1m", "").replace("\033[31m", "").replace("\033[32m", "").replace("\033[33m", "").replace("\033[36m", "").replace("\033[0m", "")
        try:
            with open(args.output, "w") as f:
                f.write("Email Phishing Forensic Analyzer Report\n\n")
                f.write(clean_text)
            print(f"\n[+] Report saved to {args.output}")
        except Exception as e:
            print(f"\033[31m[!] Error saving report: {e}\033[0m")

    return 0
