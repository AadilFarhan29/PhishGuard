import re
from urllib.parse import urlparse


SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification", "update",
    "secure", "security", "account", "bank", "confirm", "password",
    "billing", "payment", "wallet", "crypto", "urgent", "limited",
    "offer", "bonus", "gift", "claim", "support", "recovery",
    "alert", "suspended", "unlock", "token", "invoice", "auth"
]

BRAND_KEYWORDS = [
    "paypal", "amazon", "apple", "microsoft", "google", "gmail",
    "outlook", "facebook", "instagram", "netflix", "whatsapp",
    "telegram", "bank", "visa", "mastercard", "aliexpress",
    "linkedin", "openai", "chatgpt", "github", "discord",
    "adobe", "dropbox", "zoom", "slack", "spotify"
]

LOGIN_INTENT_KEYWORDS = {
    "login", "signin", "sign", "verify", "password", "account", "auth"
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
    tokens = re.split(r"[^a-zA-Z0-9]+", text)
    tokens = [token for token in tokens if token]

    return tokens


def analyze_url_nlp(url: str):
    tokens = tokenize_url(url)

    suspicious_hits = [token for token in tokens if token in SUSPICIOUS_KEYWORDS]
    brand_hits = [token for token in tokens if token in BRAND_KEYWORDS]
    login_hits = [token for token in tokens if token in LOGIN_INTENT_KEYWORDS]

    unique_suspicious_hits = sorted(set(suspicious_hits))
    unique_brand_hits = sorted(set(brand_hits))
    unique_login_hits = sorted(set(login_hits))

    token_count = len(tokens)
    suspicious_count = len(unique_suspicious_hits)
    brand_count = len(unique_brand_hits)
    login_intent = len(unique_login_hits) > 0

    risk_score = 0
    risk_score += suspicious_count * 16
    risk_score += brand_count * 14

    if suspicious_count > 0 and brand_count > 0:
        risk_score += 20

    if login_intent and brand_count > 0:
        risk_score += 12

    if token_count > 8:
        risk_score += 8

    risk_score = min(risk_score, 100)

    if suspicious_count >= 3 and brand_count > 0:
        summary = "The URL mixes brand language with multiple suspicious credential or urgency terms."
    elif suspicious_count > 0:
        summary = "The URL contains phishing-oriented keywords that increase risk."
    elif brand_count > 0:
        summary = "Brand references were detected, but there is limited suspicious language."
    else:
        summary = "The URL text does not contain strong phishing-related wording."

    return {
        "tokens": tokens,
        "token_count": token_count,
        "suspicious_keywords": unique_suspicious_hits,
        "brand_keywords": unique_brand_hits,
        "login_keywords": unique_login_hits,
        "suspicious_count": suspicious_count,
        "brand_count": brand_count,
        "login_intent_detected": login_intent,
        "nlp_risk_score": risk_score,
        "nlp_summary": summary
    }
