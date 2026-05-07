import os
import re
import json
import hashlib
import urllib.request
import threading
import sys
import time
from pathlib import Path

def extract_and_scan_attachments(msg, api_key=None, skip_vt=False):
    """
    Extracts attachments, runs a basic strings analysis for URLs, and
    optionally queries VirusTotal if an API key is provided.
    Returns a list of penalty dictionaries and a list of attachment info dicts.
    """
    penalties = []
    attachments = []
    
    # Create attachments directory
    attachments_dir = Path("./attachments")
    attachments_dir.mkdir(exist_ok=True)
    
    if not msg.is_multipart():
        return penalties, attachments
        
    for part in msg.walk():
        if part.get_content_maintype() == 'multipart':
            continue
        if part.get('Content-Disposition') is None:
            continue
            
        filename = part.get_filename()
        if not filename:
             continue
             
        filepath = attachments_dir / filename
        data = part.get_payload(decode=True)
        if not data:
            continue
            
        # Write attachment to disk
        with open(filepath, "wb") as f:
            f.write(data)
            
        file_hash = hashlib.sha256(data).hexdigest()
        
        # Strings scan
        printable_strings = re.findall(rb'[\x20-\x7e]{6,}', data)
        embedded_urls = []
        for s in printable_strings:
            try:
                decoded = s.decode('ascii')
                if re.search(r'https?://\S+', decoded):
                    embedded_urls.append(decoded)
            except Exception:
                pass
                
        if embedded_urls:
            penalties.append({
                "reason": f"Attachment '{filename}' contains embedded URLs", 
                "points": 15
            })

        vt_results_str = "Skipped"
        if api_key and not skip_vt:
            vt_results = _query_virustotal(file_hash, api_key, filename)
            if isinstance(vt_results, dict):
                positives = vt_results.get("positives", 0)
                if positives > 0:
                    penalties.append({
                        "reason": f"VirusTotal flagged '{filename}' ({positives} positives)",
                        "points": 50 # Heavy penalty for malware
                    })
                vt_results_str = f"Positives: {positives}/{vt_results.get('total', 'Unknown')}"
            else:
                 vt_results_str = vt_results
        else:
            if not api_key and not skip_vt:
                 vt_results_str = "Skipped (No API Key)"
                 
        attachments.append({
            "filename": filename,
            "hash": file_hash,
            "embedded_urls": embedded_urls,
            "virustotal": vt_results_str
        })
        
    return penalties, attachments

def _spinner_task(stop_event, filename):
    sys.stdout.write(f"\r\033[36m[*] Scanning {filename} with VirusTotal... \033[0m")
    sys.stdout.flush()
    spinner_chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    i = 0
    while not stop_event.is_set():
        sys.stdout.write(f"\r\033[36m[*] Scanning {filename} with VirusTotal... {spinner_chars[i%len(spinner_chars)]}\033[0m")
        sys.stdout.flush()
        time.sleep(0.1)
        i += 1
    sys.stdout.write("\r\033[K") # Clear line
    sys.stdout.flush()

def _query_virustotal(file_hash, api_key, filename):
    """
    Queries VirusTotal API v3 (or v2) for the file hash.
    Using v2 here as it's simpler for basic file reports.
    """
    url = f"https://www.virustotal.com/vtapi/v2/file/report?apikey={api_key}&resource={file_hash}"
    req = urllib.request.Request(url, headers={'User-Agent': 'PhishCheck CLI'})
    
    stop_event = threading.Event()
    spinner = threading.Thread(target=_spinner_task, args=(stop_event, filename))
    spinner.start()
    
    try:
        with urllib.request.urlopen(req) as response:
             data = json.loads(response.read().decode())
             stop_event.set()
             spinner.join()
             if data.get("response_code") == 1:
                 return {"positives": data.get("positives", 0), "total": data.get("total", 0)}
             else:
                 return "Not Found in VT Database"
    except Exception as e:
        stop_event.set()
        spinner.join()
        return f"API Error: {str(e)}"
