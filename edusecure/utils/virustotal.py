import hashlib
import time
import requests
from django.conf import settings


VT_BASE = "https://www.virustotal.com/api/v3"


def scan_file(file_obj, filename):
    raw_bytes = file_obj.read()
    file_obj.seek(0)
    sha256 = hashlib.sha256(raw_bytes).hexdigest()
    headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}

    # check if VT already has a result for this hash
    resp = requests.get(f"{VT_BASE}/files/{sha256}", headers=headers, timeout=15)
    if resp.status_code == 200:
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        safe = malicious == 0 and suspicious == 0
        return {
            "safe": safe,
            "malicious": malicious,
            "suspicious": suspicious,
            "message": "File appears safe." if safe else f"ALERT: {malicious} malicious, {suspicious} suspicious detections.",
        }

    upload_resp = requests.post(
        f"{VT_BASE}/files",
        headers=headers,
        files={"file": (filename, raw_bytes)},
        timeout=60,
    )
    if upload_resp.status_code != 200:
        return {"safe": None, "malicious": 0, "suspicious": 0,
                "message": f"VT upload error {upload_resp.status_code}"}

    analysis_id = upload_resp.json()["data"]["id"]

    # poll until done, give up after ~5 minutes
    # TODO: could add exponential backoff here if we start hitting rate limits
    for _ in range(30):
        time.sleep(10)
        report = requests.get(
            f"{VT_BASE}/analyses/{analysis_id}", headers=headers, timeout=15,
        ).json()

        if report["data"]["attributes"]["status"] == "completed":
            stats = report["data"]["attributes"]["stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            safe = malicious == 0 and suspicious == 0
            return {
                "safe": safe,
                "malicious": malicious,
                "suspicious": suspicious,
                "message": "File appears safe." if safe else f"ALERT: {malicious} malicious, {suspicious} suspicious detections.",
            }

    return {"safe": None, "malicious": 0, "suspicious": 0,
            "message": "VT analysis timed out — treat with caution."}
