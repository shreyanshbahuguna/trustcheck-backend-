import httpx
import datetime
from app.core.config import settings

def domain_whois_info(domain: str) -> dict:
    """
    Uses WHOISXML API to fetch accurate WHOIS data.
    """
    try:
        params = {
            "apiKey": settings.WHOIS_API_KEY,
            "domainName": domain,
            "outputFormat": "JSON"
        }

        response = httpx.get(settings.WHOIS_API_URL, params=params, timeout=10)

        if response.status_code != 200:
            return {"error": f"WHOIS API error {response.status_code}"}

        record = response.json().get("WhoisRecord", {})

        registrar = record.get("registrarName")
        registry_data = record.get("registryData", {})
        created_raw = registry_data.get("createdDate") or record.get("createdDate")

        creation_date = None
        age_days = None

        if created_raw:
            creation_date = datetime.datetime.strptime(created_raw[:10], "%Y-%m-%d")
            age_days = (datetime.datetime.utcnow() - creation_date).days

        return {
            "domain": domain,
            "registrar": registrar,
            "creation_date": creation_date.isoformat() if creation_date else None,
            "age_days": age_days,
            "organization": record.get("registrant", {}).get("organization"),
            "country": record.get("registrant", {}).get("country"),
        }

    except Exception as e:
        return {"error": str(e)}
