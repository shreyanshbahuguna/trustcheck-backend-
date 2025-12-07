def compute_risk_score(signals: dict):
    """
    Compute a meaningful scam risk score using real rules.
    Output:
        score: 0–100
        label: low / medium / high
        reasons: list of reasons
    """

    score = 0
    reasons = []

    # -----------------------------------------
    # 1. Domain age score
    # -----------------------------------------
    age = signals.get("domain_age_days")
    if age is None:
        score += 10
        reasons.append({
            "rule_id": "domain_age_missing",
            "points": 10,
            "message": "Domain age could not be determined."
        })
    elif age < 30:
        score += 40
        reasons.append({
            "rule_id": "domain_too_new",
            "points": 40,
            "message": "Domain is less than 30 days old — high scam risk."
        })
    elif age < 180:
        score += 20
        reasons.append({
            "rule_id": "domain_recent",
            "points": 20,
            "message": "Domain is less than 6 months old — moderately risky."
        })

    # -----------------------------------------
    # 2. MCA company verification
    # -----------------------------------------
    if signals.get("mca_found") is False:
        score += 25
        reasons.append({
            "rule_id": "mca_not_found",
            "points": 25,
            "message": "Company not found in MCA database."
        })

    # -----------------------------------------
    # 3. RBI NBFC validation
    # -----------------------------------------
    if signals.get("rbi_authorized") is False:
        score += 15
        reasons.append({
            "rule_id": "rbi_not_authorized",
            "points": 15,
            "message": "Company is NOT on RBI's authorized NBFC list."
        })

    # -----------------------------------------
    # 4. Phishing blacklist
    # -----------------------------------------
    if signals.get("phishing_hit") is True:
        score += 50
        reasons.append({
            "rule_id": "phishing_blacklist",
            "points": 50,
            "message": "Domain appears on phishing blacklists."
        })

    # -----------------------------------------
    # 5. Free email domain usage
    # -----------------------------------------
    if signals.get("uses_free_email"):
        score += 10
        reasons.append({
            "rule_id": "free_email_detected",
            "points": 10,
            "message": "Free email provider detected — lower trust factor."
        })

    # -----------------------------------------
    # Final label
    # -----------------------------------------
    if score < 30:
        label = "low"
    elif score < 70:
        label = "medium"
    else:
        label = "high"

    return {
        "score": score,
        "label": label,
        "reasons": reasons
    }
