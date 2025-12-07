import re
import socket
from urllib.parse import urlparse

from app.adapters.mca_adapter import search_mca_company
from app.adapters.rbi_adapter import check_rbi_nbfc
from app.adapters.whois_adapter import domain_whois_info
from app.adapters.phishing_adapter import check_phishing_blacklist
from app.adapters.virustotal_adapter import vt_check_url, vt_check_domain
from app.adapters.news_adapter import search_news
from app.adapters.openphish_adapter import check_openphish


STRICT_FINANCIAL_KEYWORDS = [
    "finance", "capital", "nbfc", "bank", "credit", "loan", "securities",
    "asset", "fund", "mutual", "nidhi"
]


def detect_type(query: str) -> str:
    q = query.strip().lower()

    if q.startswith("http://") or q.startswith("https://"):
        return "url"

    if "." in q:
        return "domain"

    if "@" in q:
        return "email"

    if q.replace("+", "").replace(" ", "").isdigit():
        return "phone"

    return "company"


def _normalize_domain(value: str) -> str:
    if value.startswith("http://") or value.startswith("https://"):
        parsed = urlparse(value)
        return parsed.hostname or value
    return value


def _init_response(artifact_type: str, artifact_value: str):
    return {
        "artifact_type": artifact_type,
        "artifact_value": artifact_value,
        "metadata": {},
        "evidences": [],
        "scoring": {
            "score": 0,
            "label": "low",
            "reasons": []
        }
    }


def _add_reason(reasons, message: str, points: int):
    reasons.append({"message": message, "points": points})
    return points


def guess_domain(company: str):
    candidate = company.lower().replace(" ", "") + ".com"
    try:
        socket.gethostbyname(candidate)
        return candidate
    except:
        return None


def run_verification(query: str, qtype: str = "auto") -> dict:
    q = query.strip()

    if not q:
        return {"error": "Empty query"}

    if qtype == "auto":
        qtype = detect_type(q)

    response = _init_response(qtype, q)
    evidences = response["evidences"]
    reasons = []
    total_score = 0

    # ======================================================
    # URL / DOMAIN ANALYSIS
    # ======================================================
    if qtype in ("url", "domain"):
        domain = _normalize_domain(q)

        # ----------------------------------------------------------
        # VIRUSTOTAL URL SCAN
        # ----------------------------------------------------------
        if qtype == "url":
            vt_url_report = vt_check_url(q)
            evidences.append({"source": "virustotal_url", "data": vt_url_report})

            if vt_url_report.get("malicious", 0) > 0:
                total_score += _add_reason(
                    reasons,
                    f"URL flagged malicious by {vt_url_report['malicious']} VT engines.",
                    60,
                )
            elif vt_url_report.get("suspicious", 0) > 0:
                total_score += _add_reason(
                    reasons,
                    f"URL flagged suspicious by {vt_url_report['suspicious']} VT engines.",
                    30,
                )
            else:
                total_score += _add_reason(
                    reasons, "VirusTotal URL scan clean.", 0
                )

        # ----------------------------------------------------------
        # NEWS API
        # ----------------------------------------------------------
        news = search_news(domain)
        evidences.append({"source": "news_api", "data": news})

        if news.get("scam_related", 0) > 0:
            total_score += _add_reason(
                reasons,
                f"News reports indicate scam/fraud ({news['scam_related']} articles).",
                50
            )
        else:
            total_score += _add_reason(reasons, "No scam news detected.", 0)

        # ----------------------------------------------------------
        # WHOIS LOOKUP
        # ----------------------------------------------------------
        whois = domain_whois_info(domain) or {}
        raw_whois = whois.get("raw", "") or ""
        age_days = whois.get("age_days")
        registrar = whois.get("registrar")

        clean_whois = {
            "domain": whois.get("domain") or domain,
            "registrar": registrar,
            "creation_date": whois.get("creation_date"),
            "age_days": age_days,
        }
        evidences.append({"source": "whois", "data": clean_whois})

        if age_days is None:
            total_score += _add_reason(reasons, "Cannot determine domain age.", 25)
        else:
            if age_days < 30:
                total_score += _add_reason(reasons, "Domain <30 days old.", 40)
            elif age_days < 90:
                total_score += _add_reason(reasons, "Domain <3 months old.", 30)
            elif age_days < 365:
                total_score += _add_reason(reasons, "Domain <1 year old.", 20)
            elif age_days < 365 * 5:
                total_score += _add_reason(reasons, "Domain <5 years old.", 10)
            else:
                total_score += _add_reason(reasons, "Domain >5 years old (safe).", 0)

        if not registrar:
            total_score += _add_reason(reasons, "Registrar missing.", 10)

        if whois.get("error"):
            total_score += _add_reason(reasons, f"WHOIS error: {whois['error']}", 15)

        # ----------------------------------------------------------
        # PHISHING BLACKLIST
        # ----------------------------------------------------------
        ph = check_phishing_blacklist(domain) or {}
        evidences.append({"source": "phishing", "data": ph})

        if ph.get("found") or ph.get("blacklist_hit"):
            total_score += _add_reason(reasons, "Phishing blacklist match!", 70)
        else:
            total_score += _add_reason(reasons, "No phishing blacklist hits.", 0)

        # ----------------------------------------------------------
        # OPENPHISH FEED
        # ----------------------------------------------------------
        op = check_openphish(domain)
        evidences.append({"source": "openphish", "data": op})

        if op.get("found"):
            total_score += _add_reason(
                reasons,
                "Domain appears in OpenPhish feed (confirmed phishing).",
                80
            )
        else:
            total_score += _add_reason(reasons, "Not found in OpenPhish.", 0)

        # ----------------------------------------------------------
        # VIRUSTOTAL DOMAIN REPUTATION
        # ----------------------------------------------------------
        vt = vt_check_domain(domain)
        evidences.append({"source": "virustotal_domain", "data": vt})

        if vt.get("malicious", 0) > 0:
            total_score += _add_reason(
                reasons,
                f"Domain flagged malicious by {vt['malicious']} VT engines.",
                60
            )
        elif vt.get("suspicious", 0) > 0:
            total_score += _add_reason(
                reasons,
                f"Domain suspicious according to {vt['suspicious']} VT engines.",
                30
            )
        else:
            total_score += _add_reason(reasons, "VirusTotal clean.", 0)

        # Finish domain response
        total_score = max(0, min(100, total_score))
        response["scoring"]["score"] = total_score
        response["scoring"]["label"] = risk_label(total_score)
        response["scoring"]["reasons"] = [
            {"rule_id": idx, "points": r["points"], "message": r["message"]}
            for idx, r in enumerate(reasons)
        ]
        return response

    # ======================================================
    # COMPANY ANALYSIS
    # ======================================================
    if qtype == "company":

        guessed = guess_domain(q)
        if guessed:
            return run_verification(guessed, "domain")

        is_fin = any(i in q.lower() for i in STRICT_FINANCIAL_KEYWORDS)

        mca = search_mca_company(q) or {}
        evidences.append({"source": "mca", "data": mca})

        if mca.get("found"):
            total_score += _add_reason(reasons, "Company found in MCA.", -10)
        else:
            total_score += _add_reason(reasons, "Company not found in MCA.", 30)

        if is_fin:
            rbi = check_rbi_nbfc(q) or {}
            evidences.append({"source": "rbi", "data": rbi})

            if rbi.get("authorized"):
                total_score += _add_reason(reasons, "Listed in RBI registry.", -15)
            else:
                total_score += _add_reason(reasons, "Not in RBI registry.", 40)

        news = search_news(q)
        evidences.append({"source": "news_api", "data": news})

        if news.get("scam_related", 0) > 0:
            total_score += _add_reason(reasons, "Scam-related news detected.", 50)
        else:
            total_score += _add_reason(reasons, "No scam-related news.", 0)

        total_score = max(0, min(100, total_score))
        response["scoring"]["score"] = total_score
        response["scoring"]["label"] = risk_label(total_score)
        response["scoring"]["reasons"] = [
            {"rule_id": idx, "points": r["points"], "message": r["message"]}
            for idx, r in enumerate(reasons)
        ]
        return response

    # For unsupported types, just return base response
    response["scoring"]["score"] = 0
    response["scoring"]["label"] = "low"
    response["scoring"]["reasons"] = [
        {"rule_id": 0, "points": 0, "message": f"Type '{qtype}' not supported"}
    ]
    return response


def risk_label(score: int) -> str:
    if score >= 75:
        return "high"
    if score >= 40:
        return "medium"
    return "low"
