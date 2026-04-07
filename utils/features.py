"""
PhishGuard — URL Feature Extractor v2
Extracts the same features used to train the v2 model (Kaggle dataset).
All features are derived from the URL string only — no external API calls.
"""

import re
from urllib.parse import urlparse


SHORTENING_SERVICES = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "rb.gy", "cutt.ly",
    "shorte.st", "tiny.cc", "bc.vc", "clck.ru"
]

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account", "bank",
    "signin", "confirm", "password", "paypal", "free", "bonus",
    "win", "urgent", "limited", "offer", "click", "gift", "claim",
    "suspend", "alert", "recover", "billing", "checkout", "ebayisapi"
]

COMMON_BRANDS = [
    "paypal", "amazon", "apple", "microsoft", "google", "facebook",
    "instagram", "netflix", "whatsapp", "telegram", "bank", "visa",
    "mastercard", "linkedin", "adobe", "dropbox", "zoom", "slack",
    "spotify", "ebay", "alibaba", "aliexpress"
]

SUSPICIOUS_TLDS = [
    "xyz", "tk", "ml", "ga", "cf", "gq", "buzz", "top",
    "club", "work", "date", "faith", "review", "stream", "gdn"
]


def _tokenize(text: str):
    """Split URL text into word tokens."""
    return [t for t in re.split(r"[^a-zA-Z0-9]+", text.lower()) if t]


def extract_url_features(url: str) -> dict:
    if not isinstance(url, str):
        url = str(url)

    url = url.strip()
    parsed = urlparse(url)
    if not parsed.netloc:
        parsed = urlparse("http://" + url)

    full_url   = url
    scheme     = parsed.scheme.lower()
    domain     = parsed.netloc.lower().split(":")[0]
    path       = parsed.path or ""
    query      = parsed.query or ""
    full_text  = full_url.lower()

    domain_parts = [p for p in domain.split(".") if p]
    tld          = domain_parts[-1] if len(domain_parts) > 1 else ""
    subdomain    = ".".join(domain_parts[:-2]) if len(domain_parts) > 2 else ""

    # ── length_url ──────────────────────────────────────────────────────────
    length_url = len(full_url)

    # ── length_hostname ─────────────────────────────────────────────────────
    length_hostname = len(domain)

    # ── ip ──────────────────────────────────────────────────────────────────
    ip = 1 if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", domain) else 0

    # ── nb_dots ─────────────────────────────────────────────────────────────
    nb_dots = full_url.count(".")

    # ── nb_hyphens ──────────────────────────────────────────────────────────
    nb_hyphens = full_url.count("-")

    # ── nb_at ───────────────────────────────────────────────────────────────
    nb_at = full_url.count("@")

    # ── nb_qm ───────────────────────────────────────────────────────────────
    nb_qm = full_url.count("?")

    # ── nb_and ──────────────────────────────────────────────────────────────
    nb_and = full_url.count("&")

    # ── nb_eq ───────────────────────────────────────────────────────────────
    nb_eq = full_url.count("=")

    # ── nb_underscore ───────────────────────────────────────────────────────
    nb_underscore = full_url.count("_")

    # ── nb_percent ──────────────────────────────────────────────────────────
    nb_percent = full_url.count("%")

    # ── nb_slash ────────────────────────────────────────────────────────────
    nb_slash = full_url.count("/")

    # ── nb_subdomains ───────────────────────────────────────────────────────
    nb_subdomains = max(0, len(domain_parts) - 2)

    # ── prefix_suffix ───────────────────────────────────────────────────────
    # Hyphen in the domain name itself (excluding subdomains)
    root_domain = domain_parts[-2] if len(domain_parts) >= 2 else domain
    prefix_suffix = 1 if "-" in root_domain else 0

    # ── shortening_service ──────────────────────────────────────────────────
    shortening_service = 1 if any(s in domain for s in SHORTENING_SERVICES) else 0

    # ── ratio_digits_url ────────────────────────────────────────────────────
    digits_in_url = sum(c.isdigit() for c in full_url)
    ratio_digits_url = round(digits_in_url / length_url, 4) if length_url > 0 else 0

    # ── https_token ─────────────────────────────────────────────────────────
    # 1 = HTTPS used properly, 0 = no HTTPS
    # Also flag if "https" appears in the domain itself (deceptive)
    if scheme == "https" and "https" not in domain:
        https_token = 1
    else:
        https_token = 0

    # ── tld_in_subdomain ────────────────────────────────────────────────────
    common_tlds = {"com", "net", "org", "gov", "edu", "co", "io"}
    tld_in_subdomain = 1 if subdomain and any(t in subdomain.split(".") for t in common_tlds) else 0

    # ── abnormal_subdomain ──────────────────────────────────────────────────
    # Flags subdomains that look like they're mimicking a brand domain
    # e.g. "paypal.com.malicious.site" — paypal.com appears as subdomain
    abnormal_subdomain = 0
    if subdomain:
        for brand in COMMON_BRANDS:
            if brand in subdomain:
                abnormal_subdomain = 1
                break

    # ── phish_hints ─────────────────────────────────────────────────────────
    tokens = _tokenize(path + " " + query)
    phish_hint_count = sum(1 for t in tokens if t in SUSPICIOUS_KEYWORDS)
    phish_hints = min(phish_hint_count, 5)  # cap at 5 same as dataset

    # ── nb_redirection ──────────────────────────────────────────────────────
    # Count "//" occurrences after scheme — indicates embedded redirects
    url_after_scheme = full_url[len(scheme) + 3:] if scheme else full_url
    nb_redirection = url_after_scheme.count("//")

    # ── length_words_raw ────────────────────────────────────────────────────
    all_tokens = _tokenize(full_url)
    length_words_raw = len(all_tokens)

    # ── longest_words_raw ───────────────────────────────────────────────────
    longest_words_raw = max((len(t) for t in all_tokens), default=0)

    # ── nb_www ──────────────────────────────────────────────────────────────
    nb_www = 1 if "www" in domain_parts else 0

    # ── nb_com ──────────────────────────────────────────────────────────────
    nb_com = full_text.count("com")

    return {
        "length_url":          length_url,
        "length_hostname":     length_hostname,
        "ip":                  ip,
        "nb_dots":             nb_dots,
        "nb_hyphens":          nb_hyphens,
        "nb_at":               nb_at,
        "nb_qm":               nb_qm,
        "nb_and":              nb_and,
        "nb_eq":               nb_eq,
        "nb_underscore":       nb_underscore,
        "nb_percent":          nb_percent,
        "nb_slash":            nb_slash,
        "nb_subdomains":       nb_subdomains,
        "prefix_suffix":       prefix_suffix,
        "shortening_service":  shortening_service,
        "ratio_digits_url":    ratio_digits_url,
        "https_token":         https_token,
        "tld_in_subdomain":    tld_in_subdomain,
        "abnormal_subdomain":  abnormal_subdomain,
        "phish_hints":         phish_hints,
        "nb_redirection":      nb_redirection,
        "length_words_raw":    length_words_raw,
        "longest_words_raw":   longest_words_raw,
        "nb_www":              nb_www,
        "nb_com":              nb_com,
    }
