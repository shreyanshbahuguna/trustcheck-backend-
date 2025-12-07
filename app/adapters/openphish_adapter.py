import httpx

OPENPHISH_FEED = "https://openphish.com/feed.txt"

# Local cache to avoid downloading feed repeatedly
openphish_cache = {
    "domains": set(),
    "last_updated": None
}

def load_openphish_feed() -> set:
    """
    Downloads OpenPhish feed (latest phishing URLs) and caches domains.
    """
    global openphish_cache

    try:
        response = httpx.get(OPENPHISH_FEED, timeout=10)
        if response.status_code != 200:
            return openphish_cache["domains"]

        urls = response.text.splitlines()
        domains = set()

        for url in urls:
            try:
                # Extract domain cleanly
                if "://" in url:
                    url = url.split("://")[1]
                domain = url.split("/")[0]
                domains.add(domain.lower().strip())
            except:
                continue

        openphish_cache["domains"] = domains
        return domains

    except:
        return openphish_cache["domains"]


def check_openphish(domain: str) -> dict:
    """
    Checks if a domain appears in OpenPhish active phishing list.
    """
    domain = domain.lower().strip()

    try:
        domains = load_openphish_feed()

        if domain in domains:
            return {
                "found": True,
                "source": "openphish",
                "risk": 80
            }
        else:
            return {
                "found": False,
                "source": "openphish",
                "risk": 0
            }
    except Exception as e:
        return {"error": str(e)}
