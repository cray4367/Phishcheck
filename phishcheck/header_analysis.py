import re

# Common freemail domains that shouldn't be sending corporate emails
FREEMAIL_DOMAINS = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com", "protonmail.com"}

def analyze_headers(msg):
    """
    Analyzes email headers for anomalies.
    Returns a list of penalty dictionaries: {"reason": str, "points": int}
    """
    penalties = []
    
    # 1. Authentication Results (SPF, DKIM, DMARC)
    auth_results = msg.get("Authentication-Results", "")
    if auth_results:
        auth_results_lower = auth_results.lower()
        if "spf=" in auth_results_lower and "spf=pass" not in auth_results_lower:
            penalties.append({"reason": "SPF Check Failed", "points": 40})
        if "dkim=" in auth_results_lower and "dkim=pass" not in auth_results_lower:
            penalties.append({"reason": "DKIM Check Failed", "points": 40})
        if "dmarc=" in auth_results_lower and "dmarc=pass" not in auth_results_lower:
            penalties.append({"reason": "DMARC Check Failed", "points": 40})
    else:
        penalties.append({"reason": "Missing Authentication-Results Header", "points": 20})

    # Domain Extraction Helper
    def extract_domain(email_str):
        if not email_str: return None
        match = re.search(r'@([\w.\-]+)', str(email_str))
        return match.group(1).lower() if match else None

    from_header = msg.get("From", "")
    reply_to_header = msg.get("Reply-To", "")
    msg_id_header = msg.get("Message-ID", "")
    
    from_domain = extract_domain(from_header)
    reply_to_domain = extract_domain(reply_to_header)
    msg_id_domain = extract_domain(msg_id_header)

    # 2. From vs Reply-To Mismatch
    if from_domain and reply_to_domain and from_domain != reply_to_domain:
        penalties.append({"reason": f"From ({from_domain}) differs from Reply-To ({reply_to_domain})", "points": 15})
        
    # 3. Message-ID Mismatch
    if from_domain and msg_id_domain and from_domain != msg_id_domain:
        penalties.append({"reason": f"Message-ID domain ({msg_id_domain}) differs from From domain ({from_domain})", "points": 10})

    # 4. Freemail Spoofing Check
    # Look for corporate keywords in the From name, but a freemail domain
    if from_domain in FREEMAIL_DOMAINS:
        from_name = str(from_header).split("<")[0].lower()
        corporate_keywords = ["support", "admin", "billing", "service", "paypal", "bank", "apple", "microsoft", "amazon", "security", "update"]
        if any(keyword in from_name for keyword in corporate_keywords):
            penalties.append({"reason": f"Corporate/Bank display name used with freemail address ({from_domain})", "points": 20})

    # 5. Received Chain IP Hops (RFC-1918 internal IPs)
    received_headers = msg.get_all("Received", [])
    internal_ip_regex = re.compile(r'\[(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)\]')
    
    internal_hop_count = 0
    for header in received_headers:
        if internal_ip_regex.search(str(header)):
            internal_hop_count += 1
    
    if internal_hop_count > 0:
        penalties.append({"reason": f"Found {internal_hop_count} internal (RFC-1918) IP(s) in Received headers", "points": 5})

    # 6. Subject Anomalies
    subject = msg.get("Subject", "")
    if subject:
        re_fwd_count = len(re.findall(r'(?i)(re:|fwd:)', str(subject)))
        if re_fwd_count > 1:
            penalties.append({"reason": f"Subject anomaly: Multiple Re:/Fwd: to create false trust", "points": 5})

    # 7. Encryption/PGP Check
    content_type = msg.get("Content-Type", "")
    pgp_header = msg.get("X-PGP-Universal", "")
    if "application/pgp" in content_type or pgp_header:
        penalties.append({"reason": "Crypto/PGP headers found. Treat with caution.", "points": 5})

    return penalties
