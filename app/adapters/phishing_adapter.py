import httpx
from app.core.config import settings


def check_phishing_blacklist(domain: str) -> dict:
    """
    Unified phishing / malware blacklist check.

    Currently implemented as a safe stub that always returns
    'not found'. You can later plug in real services such as
    PhishTank, OpenPhish, URLScan, etc., using PHISHTANK_API_KEY
    in app.core.config.settings.
    """

    # Example structure that real integrations should also return:
    return {
        "found": False,           # True if any blacklist flags this domain
        "blacklist_hit": False,   # Backwards-compatible key
        "source": "stub_phishing_service",
        "risk": 0,
    }


def check_phishing_lists(domain: str) -> dict:
    """
    Backwards-compatibility wrapper for older code that may still
    import check_phishing_lists. Delegates to check_phishing_blacklist.
    """
    return check_phishing_blacklist(domain)
