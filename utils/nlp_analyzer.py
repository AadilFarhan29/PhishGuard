import re
from urllib.parse import urlparse


SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account", "bank",
    "signin", "confirm", "password", "billing", "payment",
    "wallet", "crypto", "urgent", "limited", "offer", "bonus",
    "gift", "claim", "support", "security", "recovery", "alert"
]

BRAND_KEYWORDS = [
    "paypal", "amazon", "apple", "microsoft", "google",
    "facebook", "instagram", "netflix", "whatsapp", "telegram",
    "bank", "visa", "mastercard", "aliexpress", "linkedin"
]


def tokenize_url(url: str):
    if not isinstance(url, str):
        url = str(url)

    url = url.strip().lower()

    parsed = urlparse(url)
    if not parsed.netloc:
        parsed = urlparse("http://" + url)

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

    unique_suspicious_hits = sorted(list(set(suspicious_hits)))
    unique_brand_hits = sorted(list(set(brand_hits)))

    token_count = len(tokens)
    suspicious_count = len(unique_suspicious_hits)
    brand_count = len(unique_brand_hits)

    risk_score = 0

    # Suspicious keywords
    risk_score += suspicious_count * 20

    # Brand impersonation
    risk_score += brand_count * 15

    # If both brand + suspicious terms appear together, boost risk
    if suspicious_count > 0 and brand_count > 0:
        risk_score += 20

    # Very long tokenized URLs can be suspicious
    if token_count > 8:
        risk_score += 10

    # Cap score
    risk_score = min(risk_score, 100)

    return {
        "tokens": tokens,
        "token_count": token_count,
        "suspicious_keywords": unique_suspicious_hits,
        "brand_keywords": unique_brand_hits,
        "suspicious_count": suspicious_count,
        "brand_count": brand_count,
        "nlp_risk_score": risk_score
    }