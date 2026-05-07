import re
import unicodedata

URGENCY_KEYWORDS = [
    "urgent", "act now", "immediately", "expire", "verify now",
    "suspend", "account locked", "24 hours", "click here", "limited time",
    "your account", "confirm your identity"
]

def analyze_body(text_body, html_body):
    """
    Analyzes the email body (text and HTML) for urgency, hidden text, and Unicode inconsistencies.
    Returns a list of penalty dictionaries.
    """
    penalties = []
    combined_body = text_body + "\n" + html_body
    body_lower = combined_body.lower()

    # 1. Urgency Detection
    urgency_hits = []
    for keyword in URGENCY_KEYWORDS:
        if keyword in body_lower:
            urgency_hits.append(keyword)
    
    if urgency_hits:
        # 5 pts per keyword, max 30 pts.
        points = min(30, 5 * len(urgency_hits))
        penalties.append({
            "reason": f"Urgency keywords detected ({', '.join(urgency_hits)})",
            "points": points
        })

    # 2. Hidden Text / CSS Evasion Analysis
    if html_body:
        # Look for font-size: 0, display: none, visibility: hidden
        hidden_styles = re.findall(r'(?i)(font-size\s*:\s*0|display\s*:\s*none|visibility\s*:\s*hidden)', html_body)
        if hidden_styles:
            penalties.append({
                "reason": "HTML Hidden Text detected (CSS evasion techniques)",
                "points": 15
            })
            
        # Look for off-screen text (e.g. left: -9999px)
        offscreen_styles = re.findall(r'(?i)(left\s*:\s*-\d{3,}px|top\s*:\s*-\d{3,}px)', html_body)
        if offscreen_styles:
            penalties.append({
                "reason": "HTML Off-screen Text detected (CSS evasion techniques)",
                "points": 20
            })
            
        # Look for 1x1 tracking pixels
        tracking_pixels = re.findall(r'(?i)<img[^>]+width\s*=\s*["\']?1["\']?[^>]+height\s*=\s*["\']?1["\']?', html_body)
        if tracking_pixels:
            penalties.append({
                "reason": "1x1 Tracking pixel detected (surveillance/reconnaissance)",
                "points": 10
            })
            
    # 3. Unicode/UTF Inconsistencies (Mixed Scripts)
    # Check for Cyrillic or Greek characters mixed in primarily Latin text
    cyrillic_or_greek_regex = re.compile(r'[\u0400-\u04FF\u0370-\u03FF]')
    latin_regex = re.compile(r'[a-zA-Z]')
    
    has_cyrillic_or_greek = bool(cyrillic_or_greek_regex.search(combined_body))
    has_latin = bool(latin_regex.search(combined_body))
    
    if has_cyrillic_or_greek and has_latin:
         penalties.append({
             "reason": "Unicode Inconsistency: Mixed scripts (e.g. Cyrillic/Greek with Latin) detected. Possible homoglyph evasion.",
             "points": 20
         })

    return penalties
