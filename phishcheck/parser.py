import email
from email import policy

def parse_eml(filepath):
    """
    Parses an EML file and returns the email Message object.
    Uses email.policy.default to handle headers and structure cleanly.
    """
    try:
        with open(filepath, "rb") as f:
            msg = email.message_from_binary_file(f, policy=policy.default)
        return msg
    except Exception as e:
        print(f"\033[31m[!] Error parsing EML file {filepath}: {e}\033[0m")
        return None

def extract_body(msg):
    """
    Extracts the plain text and html body parts from the email message.
    Returns a tuple (text_body, html_body).
    """
    text_body = ""
    html_body = ""
    
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))
            
            if content_type == "text/plain" and "attachment" not in content_disposition:
                text_body += part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8', errors="ignore")
            elif content_type == "text/html" and "attachment" not in content_disposition:
                html_body += part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8', errors="ignore")
    else:
        # Not multipart
        content_type = msg.get_content_type()
        payload = msg.get_payload(decode=True).decode(msg.get_content_charset() or 'utf-8', errors="ignore")
        if content_type == "text/html":
            html_body = payload
        else:
            text_body = payload
            
    return text_body, html_body
