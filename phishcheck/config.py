import os
from dotenv import load_dotenv

# Load variables from .env if present
load_dotenv()

def get_vt_api_key():
    """Returns the VirusTotal API key from the environment, or None if not set."""
    return os.getenv("VIRUSTOTAL_API_KEY")
