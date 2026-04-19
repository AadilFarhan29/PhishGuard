import re
from urllib.parse import urlparse


SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account", "bank",
    "signin", "confirm", "password", "paypal", "free", "bonus",
    "win", "urgent", "limited", "offer", "click", "gift", "claim"
]

SHORTENING_SERVICES = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "rb.gy", "cutt.ly"
]


def extract_url_features(url):
    if not isinstance(url, str):
        url = str(url)

    url = url.strip()

    parsed = urlparse(url)
    if not parsed.netloc:
        parsed = urlparse("http://" + url)

    full_url = url.strip()
    domain = parsed.netloc.lower()
    path = parsed.path or ""
    query = parsed.query or ""
    scheme = parsed.scheme.lower()

    domain_only = domain.split(":")[0]
    domain_parts = [part for part in domain_only.split(".") if part]
    tld = domain_parts[-1] if len(domain_parts) > 1 else ""

    total_length = len(full_url)
    domain_length = len(domain_only)
    tld_length = len(tld)

    no_of_letters = sum(c.isalpha() for c in full_url)
    no_of_digits = sum(c.isdigit() for c in full_url)

    no_of_equals = full_url.count("=")
    no_of_qmark = full_url.count("?")
    no_of_ampersand = full_url.count("&")

    special_chars = re.findall(r"[^a-zA-Z0-9]", full_url)
    no_of_other_special = len([
        ch for ch in special_chars if ch not in [".", "/", ":", "?", "&", "="]
    ])

    has_obfuscation = 1 if "%" in full_url or "@" in full_url else 0
    no_of_obfuscated_char = full_url.count("%") + full_url.count("@")
    obfuscation_ratio = no_of_obfuscated_char / total_length if total_length > 0 else 0

    is_domain_ip = 1 if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", domain_only) else 0
    is_https = 1 if scheme == "https" else 0
    no_of_subdomain = max(0, len(domain_parts) - 2)

    letter_ratio = no_of_letters / total_length if total_length > 0 else 0
    digit_ratio = no_of_digits / total_length if total_length > 0 else 0
    special_ratio = no_of_other_special / total_length if total_length > 0 else 0

    uses_shortener = 1 if any(service in domain_only for service in SHORTENING_SERVICES) else 0

    text_to_check = (path + " " + query).lower()
    has_suspicious_keyword = 1 if any(word in text_to_check for word in SUSPICIOUS_KEYWORDS) else 0

    return {
        "URLLength": total_length,
        "DomainLength": domain_length,
        "TLDLength": tld_length,
        "IsHTTPS": is_https,
        "IsDomainIP": is_domain_ip,
        "NoOfSubDomain": no_of_subdomain,
        "HasObfuscation": has_obfuscation,
        "NoOfObfuscatedChar": no_of_obfuscated_char,
        "ObfuscationRatio": obfuscation_ratio,
        "NoOfLettersInURL": no_of_letters,
        "LetterRatioInURL": letter_ratio,
        "NoOfDegitsInURL": no_of_digits,
        "DegitRatioInURL": digit_ratio,
        "NoOfEqualsInURL": no_of_equals,
        "NoOfQMarkInURL": no_of_qmark,
        "NoOfAmpersandInURL": no_of_ampersand,
        "NoOfOtherSpecialCharsInURL": no_of_other_special,
        "SpacialCharRatioInURL": special_ratio,
        "UsesShortener": uses_shortener,
        "HasSuspiciousKeyword": has_suspicious_keyword
    }