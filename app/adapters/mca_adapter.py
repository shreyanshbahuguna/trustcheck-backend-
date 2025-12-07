import httpx
from bs4 import BeautifulSoup

def search_mca_company(name: str) -> dict:
    """
    Lightweight MCA company check using Google search.
    Does NOT access MCA directly (because it requires CAPTCHA).
    Works for most Indian registered companies.
    """

    try:
        query = f'site:mca.gov.in "{name}" "Master Data"'
        url = f"https://www.google.com/search?q={query}"

        headers = {"User-Agent": "Mozilla/5.0"}

        r = httpx.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(r.text, "html.parser")

        links = soup.find_all("a")

        for link in links:
            href = link.get("href", "")
            if "viewCompanyMasterData" in href:
                return {
                    "found": True,
                    "name": name,
                    "mca_link": href
                }

        return {"found": False, "name": name}

    except Exception as e:
        return {"found": False, "error": str(e)}
