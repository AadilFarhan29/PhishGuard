import re
from urllib.parse import urlparse


KEYWORD_WEIGHTS = {
    "login": 14,
    "logon": 14,
    "signin": 14,
    "sign-in": 14,
    "verify": 14,
    "verification": 14,
    "secure": 7,
    "security": 7,
    "account": 8,
    "update": 10,
    "confirm": 10,
    "password": 16,
    "billing": 12,
    "payment": 12,
    "bank": 10,
    "wallet": 10,
    "invoice": 8,
    "suspended": 15,
    "unlock": 12,
    "recover": 11,
    "reset": 12,
    "support": 7,
    "auth": 10,
    "authentication": 10,
    "session": 8,
    "expired": 14,
    "alert": 11,
    "urgent": 13,
    "limited": 9,
    "claim": 8,
    "gift": 7,
    "reward": 7,
    "bonus": 7,
    "free": 6,
    "promo": 6,
    "win": 8,
    "prize": 8
}

SUSPICIOUS_KEYWORDS = set(KEYWORD_WEIGHTS.keys())

BRAND_KEYWORDS = {
    "paypal", "amazon", "apple", "microsoft", "google", "facebook",
    "instagram", "whatsapp", "netflix", "bank", "stripe", "openai",
    "github", "telegram", "linkedin", "dropbox", "adobe", "dhl",
    "aramax", "fedex", "ups", "noon", "careem", "emirates", "etisalat"
}

LOGIN_INTENT_KEYWORDS = {
    "login", "signin", "sign", "verify", "password", "account", "auth",
    "authentication", "reset", "confirm"
}

URGENT_KEYWORDS = {
    "urgent", "alert", "expired", "suspended", "limited"
}


def tokenize_url(url: str):
    if not isinstance(url, str):
        url = str(url)

    normalized_url = url.strip().lower()

    parsed = urlparse(normalized_url)
    if not parsed.netloc:
        parsed = urlparse("http://" + normalized_url)

    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    query = parsed.query.lower()

    text = f"{domain} {path} {query}"

    # Base split
    tokens = re.split(r"[^a-zA-Z0-9]+", text)
    tokens = [token for token in tokens if token]

    return tokens


def analyze_url_nlp(url: str):
    tokens = tokenize_url(url)
    unique_tokens = set(tokens)

    suspicious_hits = sorted({token for token in tokens if token in SUSPICIOUS_KEYWORDS})
    brand_hits = sorted({token for token in tokens if token in BRAND_KEYWORDS})
    login_hits = sorted({token for token in tokens if token in LOGIN_INTENT_KEYWORDS})

    token_count = len(tokens)
    suspicious_count = len(suspicious_hits)
    brand_count = len(brand_hits)
    login_intent = len(login_hits) > 0

    risk_score = 0

    # Weighted suspicious keywords
    risk_score += sum(KEYWORD_WEIGHTS.get(token, 0) for token in suspicious_hits)

    # Brand presence alone should not be too aggressive
    if brand_count > 0:
        risk_score += min(brand_count * 6, 12)

    # Combo logic
    if suspicious_count > 0 and brand_count > 0:
        risk_score += 18

    if login_intent and brand_count > 0:
        risk_score += 14

    if any(word in unique_tokens for word in URGENT_KEYWORDS) and login_intent:
        risk_score += 12

    if suspicious_count >= 3:
        risk_score += 10

    if suspicious_count >= 2 and brand_count > 0:
        risk_score += 10

    # Long token-heavy URLs can be more suspicious, but keep it light
    if token_count > 8:
        risk_score += 6

    if token_count > 12:
        risk_score += 6

    risk_score = min(risk_score, 100)

    if suspicious_count >= 3 and brand_count > 0:
        summary = "The URL mixes brand language with multiple suspicious credential or urgency terms."
    elif login_intent and brand_count > 0:
        summary = "The URL combines brand references with account or login-related wording."
    elif suspicious_count >= 2:
        summary = "The URL contains multiple phishing-oriented keywords that increase risk."
    elif suspicious_count > 0:
        summary = "The URL contains phishing-oriented keywords that increase risk."
    elif brand_count > 0:
        summary = "Brand references were detected, but there is limited suspicious language."
    else:
        summary = "The URL text does not contain strong phishing-related wording."

    return {
        "tokens": tokens,
        "token_count": token_count,
        "suspicious_keywords": suspicious_hits,
        "brand_keywords": brand_hits,
        "login_keywords": login_hits,
        "suspicious_count": suspicious_count,
        "brand_count": brand_count,
        "login_intent_detected": login_intent,
        "nlp_risk_score": risk_score,
        "nlp_summary": summary
    }