"""
EduSecure — VirusTotal integration.

Adapted from urlcheckerapi.py.  Provides two functions used by the
submissions upload view:
  • scan_url()  — check a URL against 70+ AV engines
  • scan_file() — upload and analyse an uploaded file object

The API key is loaded from Django settings so it never lives in source code.
"""

import base64
import time
import requests
from django.conf import settings


VT_BASE = "https://www.virustotal.com/api/v3"


def _headers() -> dict:
    return {"x-apikey": settings.VIRUSTOTAL_API_KEY}


def scan_url(url: str) -> dict:
    """
    Check *url* via the VirusTotal v3 /urls endpoint.

    Returns a dict:
      safe        : bool
      malicious   : int
      suspicious  : int
      message     : str  (human-readable summary)
    """
    # VT v3 requires the URL encoded as base64url without padding
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    response = requests.get(f"{VT_BASE}/urls/{url_id}", headers=_headers(), timeout=15)

    if response.status_code != 200:
        return {"safe": None, "malicious": 0, "suspicious": 0,
                "message": f"VT API error {response.status_code}"}

    stats = response.json()["data"]["attributes"]["last_analysis_stats"]
    malicious  = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    safe       = malicious == 0 and suspicious == 0

    return {
        "safe":       safe,
        "malicious":  malicious,
        "suspicious": suspicious,
        "message":    "URL appears safe." if safe
                      else f"ALERT: {malicious} malicious, {suspicious} suspicious detections.",
    }


def scan_file(file_obj, filename: str) -> dict:
    """
    Upload *file_obj* (a Django InMemoryUploadedFile or similar) to VirusTotal
    and poll until the analysis completes.

    Returns the same dict shape as scan_url().
    Polls every 15 seconds; gives up after 10 attempts (~2.5 minutes).
    """
    # Upload the file
    upload_resp = requests.post(
        f"{VT_BASE}/files",
        headers=_headers(),
        files={"file": (filename, file_obj)},
        timeout=60,
    )
    if upload_resp.status_code != 200:
        return {"safe": None, "malicious": 0, "suspicious": 0,
                "message": f"VT upload error {upload_resp.status_code}"}

    analysis_id = upload_resp.json()["data"]["id"]

    # Poll for completion
    for _ in range(10):
        time.sleep(15)
        report = requests.get(
            f"{VT_BASE}/analyses/{analysis_id}",
            headers=_headers(),
            timeout=15,
        ).json()

        status = report["data"]["attributes"]["status"]
        if status == "completed":
            stats      = report["data"]["attributes"]["stats"]
            malicious  = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            safe       = malicious == 0 and suspicious == 0
            return {
                "safe":       safe,
                "malicious":  malicious,
                "suspicious": suspicious,
                "message":    "File appears safe." if safe
                              else f"ALERT: {malicious} malicious, {suspicious} suspicious detections.",
            }

    return {"safe": None, "malicious": 0, "suspicious": 0,
            "message": "VT analysis timed out — treat with caution."}
