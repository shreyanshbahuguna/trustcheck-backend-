import httpx
from app.core.config import settings

VT_URL = "https://www.virustotal.com/api/v3/urls"
VT_DOMAIN = "https://www.virustotal.com/api/v3/domains/"

headers = {
    "x-apikey": settings.VIRUSTOTAL_API_KEY
}


def vt_check_url(url: str) -> dict:
    """
    Submits or retrieves a URL scan from VirusTotal.
    Returns detection stats and reputation.
    """
    try:
        # First: submit URL to get analysis ID
        submit = httpx.post(VT_URL, headers=headers, data={"url": url}, timeout=10)

        if submit.status_code not in (200, 201):
            return {"error": f"VT URL submission failed ({submit.status_code})"}

        analysis_id = submit.json()["data"]["id"]

        # Retrieve analysis results
        report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        result = httpx.get(report_url, headers=headers, timeout=10)

        if result.status_code != 200:
            return {"error": "VT analysis fetch failed"}

        stats = result.json()["data"]["attributes"]["stats"]

        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "harmless": stats.get("harmless", 0),
            "source": "virustotal_url"
        }

    except Exception as e:
        return {"error": str(e)}


def vt_check_domain(domain: str) -> dict:
    """
    Retrieves domain reputation from VirusTotal.
    """
    try:
        url = VT_DOMAIN + domain
        result = httpx.get(url, headers=headers, timeout=10)

        if result.status_code != 200:
            return {"error": f"VT domain check failed ({result.status_code})"}

        data = result.json().get("data", {}).get("attributes", {})

        return {
            "reputation": data.get("reputation"),
            "malicious": data.get("last_analysis_stats", {}).get("malicious", 0),
            "suspicious": data.get("last_analysis_stats", {}).get("suspicious", 0),
            "harmless": data.get("last_analysis_stats", {}).get("harmless", 0),
            "undetected": data.get("last_analysis_stats", {}).get("undetected", 0),
            "categories": data.get("categories", {}),
            "source": "virustotal_domain"
        }

    except Exception as e:
        return {"error": str(e)}
