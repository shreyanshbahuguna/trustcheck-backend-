import httpx
from app.core.config import settings

STRONG_SCAM_KEYWORDS = [
    "scam", "fraud", "ponzi", "fake", "phishing",
    "cheat", "cheating", "money laundering", "scam alert",
    "fraud case", "fraudster", "fake investment"
]

def search_news(entity: str) -> dict:
    """
    Searches NewsAPI for scam/fraud related reports
    about a company or domain, with stricter filtering.
    """
    entity = (entity or "").strip()
    if not entity:
        return {"total_articles": 0, "scam_related": 0, "scam_articles": []}

    try:
        params = {
            "q": entity,  # broad search, we filter locally
            "apiKey": settings.NEWS_API_KEY,
            "language": "en",
            "sortBy": "relevancy",
            "pageSize": 20,
        }

        resp = httpx.get(settings.NEWS_API_URL, params=params, timeout=10)
        if resp.status_code != 200:
            return {"error": f"NewsAPI error {resp.status_code}"}

        data = resp.json()
        articles = data.get("articles", [])

        scam_hits = []
        entity_l = entity.lower()

        for art in articles:
            title = (art.get("title") or "").lower()
            desc = (art.get("description") or "").lower()
            text = f"{title} {desc}"

            # entity MUST appear in the text
            if entity_l not in text:
                continue

            # and at least ONE strong scam keyword
            if any(kw in text for kw in STRONG_SCAM_KEYWORDS):
                scam_hits.append(art)

        return {
            "total_articles": len(articles),
            "scam_related": len(scam_hits),
            "scam_articles": scam_hits[:3],
        }

    except Exception as e:
        return {"error": str(e), "total_articles": 0, "scam_related": 0, "scam_articles": []}
