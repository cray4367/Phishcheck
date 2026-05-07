import re
from html.parser import HTMLParser
from urllib.parse import urlparse
import socket

# Common target brands for typosquatting checks
BRAND_LIST = ["paypal", "apple", "microsoft", "amazon", "google", "facebook", "netflix", "bankofamerica", "chase", "wellsfargo"]
SUSPICIOUS_TLDS = {".xyz", ".top", ".tk", ".ru", ".cn", ".club", ".work", ".info"}

class URLExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.urls = set()

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            for attr, value in attrs:
                if attr == "href" and value.startswith("http"):
                    self.urls.add(value)

def get_edit_distance(s1, s2):
    """Simple Levenshtein distance implementation."""
    if len(s1) < len(s2):
        return get_edit_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

import urllib.request
import urllib.parse
import json
import threading
import sys
import time

def _spinner_task(stop_event, url):
    sys.stdout.write(f"\r\033[36m[*] Scanning URL with VirusTotal... \033[0m")
    sys.stdout.flush()
    spinner_chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    i = 0
    while not stop_event.is_set():
        sys.stdout.write(f"\r\033[36m[*] Scanning URL with VirusTotal... {spinner_chars[i%len(spinner_chars)]}\033[0m")
        sys.stdout.flush()
        time.sleep(0.1)
        i += 1
    sys.stdout.write("\r\033[K")
    sys.stdout.flush()

def _query_virustotal_url(url, api_key):
    encoded_url = urllib.parse.quote(url, safe='')
    vt_url = f"https://www.virustotal.com/vtapi/v2/url/report?apikey={api_key}&resource={encoded_url}"
    req = urllib.request.Request(vt_url, headers={'User-Agent': 'PhishCheck CLI'})
    
    stop_event = threading.Event()
    spinner = threading.Thread(target=_spinner_task, args=(stop_event, url))
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

def analyze_urls(text_body, html_body, api_key=None, skip_vt=False):
    """
    Extracts URLs from HTML and text bodies and scores them for trust.
    Returns a list of penalty dictionaries and a list of extracted URLs with info.
    """
    penalties = []
    urls = set()
    url_info_list = []
    
    # Extract from HTML
    if html_body:
        parser = URLExtractor()
        parser.feed(html_body)
        urls.update(parser.urls)
        
    # Extract from plain text
    if text_body:
        text_urls = re.findall(r'https?://\S+', text_body)
        urls.update(text_urls)
        
    for url in urls:
        vt_results_str = "Skipped"
        try:
            parsed = urlparse(url)
            netloc = parsed.netloc.lower()
            path = parsed.path
            
            # Remove port if present for domain checks
            domain = netloc.split(":")[0]
            
            # 0. URL Unshortening (Synchronous HEAD request)
            shortener_domains = ["bit.ly", "tinyurl.com", "t.co", "is.gd", "goo.gl", "ow.ly", "buff.ly"]
            if domain in shortener_domains:
                try:
                    req = urllib.request.Request(url, method="HEAD", headers={'User-Agent': 'Mozilla/5.0'})
                    with urllib.request.urlopen(req, timeout=3) as response:
                        actual_url = response.geturl()
                        if actual_url != url:
                            penalties.append({"reason": f"URL Shortener resolved to hidden destination: {actual_url}", "points": 10})
                            # Update variables to analyze the resolved URL
                            url = actual_url
                            parsed = urlparse(url)
                            netloc = parsed.netloc.lower()
                            path = parsed.path
                            domain = netloc.split(":")[0]
                except Exception:
                    pass
            
            # 1. IP-only Host
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
                penalties.append({"reason": f"IP-based URL detected ({url})", "points": 30})
                
            # 2. Non-standard Port
            if ":" in netloc:
                port = netloc.split(":")[1]
                if port not in ["80", "443"]:
                    penalties.append({"reason": f"Non-standard port ({port}) in URL ({url})", "points": 10})
                    
            # 3. Suspicious TLD
            if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
                penalties.append({"reason": f"Suspicious TLD in URL ({url})", "points": 15})
                
            # 4. Long Path (Obfuscation)
            if len(path) > 100:
                 penalties.append({"reason": f"Unusually long URL path (>100 chars) in ({url[:50]}...)", "points": 10})
                 
            # 5. Typosquatting Check & Punycode
            if domain.startswith("xn--"):
                penalties.append({"reason": f"Punycode (IDN homograph) domain detected in URL ({url})", "points": 35})
            else:
                domain_parts = domain.split(".")
                for part in domain_parts:
                    for brand in BRAND_LIST:
                        if part != brand: # Not an exact match
                            dist = get_edit_distance(part, brand)
                            if dist == 1 or (dist == 2 and len(brand) > 5):
                                penalties.append({"reason": f"Possible Typosquatting: '{part}' is similar to brand '{brand}' in URL ({url})", "points": 20})
                            
            # 6. Homograph Attacks (Zero-width characters)
            if re.search(r'[\u200B-\u200D\uFEFF]', url):
                penalties.append({"reason": f"Zero-width character detected in URL (Homograph attack) ({url})", "points": 25})

            # 7. VirusTotal URL Reputation
            if api_key and not skip_vt:
                vt_results = _query_virustotal_url(url, api_key)
                if isinstance(vt_results, dict):
                    positives = vt_results.get("positives", 0)
                    if positives > 0:
                        penalties.append({
                            "reason": f"VirusTotal flagged URL as malicious ({positives} positives): {url}",
                            "points": 50
                        })
                    vt_results_str = f"Positives: {positives}/{vt_results.get('total', 'Unknown')}"
                else:
                    vt_results_str = vt_results
            elif not api_key and not skip_vt:
                vt_results_str = "Skipped (No API Key)"
                
        except Exception as e:
            pass # Ignore malformed URLs
            
        url_info_list.append({"url": url, "virustotal": vt_results_str})

    return penalties, url_info_list
