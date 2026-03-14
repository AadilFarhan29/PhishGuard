from urllib.parse import urlparse


TRUSTED_BRAND_DOMAINS = {
    "google": [
        "google.com",
        "accounts.google.com",
        "mail.google.com",
        "drive.google.com",
        "docs.google.com",
        "youtube.com",
        "google.ae"
    ],
    "youtube": [
        "youtube.com",
        "music.youtube.com"
    ],
    "gmail": [
        "gmail.com",
        "mail.google.com"
    ],
    "microsoft": [
        "microsoft.com",
        "login.microsoftonline.com",
        "office.com",
        "office365.com",
        "live.com",
        "outlook.com",
        "account.microsoft.com"
    ],
    "outlook": [
        "outlook.com",
        "live.com",
        "office.com",
        "office365.com"
    ],
    "apple": [
        "apple.com",
        "icloud.com",
        "idmsa.apple.com",
        "appleid.apple.com"
    ],
    "icloud": [
        "icloud.com",
        "apple.com"
    ],
    "paypal": [
        "paypal.com"
    ],
    "amazon": [
        "amazon.com",
        "amazon.ae",
        "amazon.co.uk",
        "amazon.de",
        "amazon.in",
        "amazon.co.jp"
    ],
    "facebook": [
        "facebook.com",
        "fb.com",
        "meta.com"
    ],
    "instagram": [
        "instagram.com"
    ],
    "whatsapp": [
        "whatsapp.com"
    ],
    "linkedin": [
        "linkedin.com"
    ],
    "adobe": [
        "adobe.com"
    ],
    "github": [
        "github.com",
        "github.io"
    ],
    "chatgpt": [
        "chatgpt.com",
        "openai.com",
        "chat.openai.com"
    ],
    "openai": [
        "openai.com",
        "chatgpt.com",
        "chat.openai.com"
    ],
    "netflix": [
        "netflix.com"
    ],
    "x": [
        "x.com",
        "twitter.com"
    ],
    "twitter": [
        "twitter.com",
        "x.com"
    ],
    "reddit": [
        "reddit.com"
    ],
    "discord": [
        "discord.com",
        "discord.gg"
    ],
    "telegram": [
        "telegram.org",
        "t.me"
    ],
    "tiktok": [
        "tiktok.com"
    ],
    "snapchat": [
        "snapchat.com"
    ],
    "dropbox": [
        "dropbox.com"
    ],
    "zoom": [
        "zoom.us"
    ],
    "slack": [
        "slack.com"
    ],
    "notion": [
        "notion.so",
        "notion.site"
    ],
    "canva": [
        "canva.com"
    ],
    "spotify": [
        "spotify.com"
    ],
    "samsung": [
        "samsung.com"
    ],
    "ebay": [
        "ebay.com"
    ],
    "booking": [
        "booking.com"
    ],
    "etsy": [
        "etsy.com"
    ],
    "walmart": [
        "walmart.com"
    ],
    "aliexpress": [
        "aliexpress.com"
    ],
    "shein": [
        "shein.com"
    ],
    "roblox": [
        "roblox.com"
    ],
    "yahoo": [
        "yahoo.com",
        "yahoo.co.jp"
    ],
    "bing": [
        "bing.com"
    ],
    "duckduckgo": [
        "duckduckgo.com"
    ],
    "bbc": [
        "bbc.com",
        "bbc.co.uk"
    ],
    "cnn": [
        "cnn.com"
    ],
    "bank": [],
    "visa": [
        "visa.com"
    ],
    "mastercard": [
        "mastercard.com"
    ]
}


POPULAR_TRUSTED_DOMAINS = {
    "google.com",
    "youtube.com",
    "facebook.com",
    "instagram.com",
    "chatgpt.com",
    "openai.com",
    "x.com",
    "twitter.com",
    "reddit.com",
    "wikipedia.org",
    "whatsapp.com",
    "bing.com",
    "tiktok.com",
    "amazon.com",
    "amazon.ae",
    "linkedin.com",
    "netflix.com",
    "live.com",
    "office.com",
    "microsoft.com",
    "canva.com",
    "telegram.org",
    "t.me",
    "discord.com",
    "github.com",
    "bbc.com",
    "bbc.co.uk",
    "apple.com",
    "paypal.com",
    "adobe.com",
    "zoom.us",
    "dropbox.com",
    "slack.com",
    "spotify.com",
    "samsung.com",
    "ebay.com",
    "booking.com",
    "etsy.com",
    "walmart.com",
    "aliexpress.com",
    "yahoo.com",
    "duckduckgo.com",
    "cnn.com"
}


COMMON_SECOND_LEVEL_SUFFIXES = {
    "co.uk", "org.uk", "gov.uk", "ac.uk",
    "co.jp", "com.au", "com.sg", "com.my",
    "co.in", "com.br", "com.mx", "com.tr"
}


def get_hostname(url: str) -> str:
    parsed = urlparse(url.strip())
    if not parsed.netloc:
        parsed = urlparse("https://" + url.strip())
    return parsed.netloc.lower().split(":")[0]


def get_root_domain(hostname: str) -> str:
    parts = [p for p in hostname.split(".") if p]

    if len(parts) <= 2:
        return hostname

    last_two = ".".join(parts[-2:])
    last_three = ".".join(parts[-3:])

    if last_two in COMMON_SECOND_LEVEL_SUFFIXES and len(parts) >= 3:
        return last_three

    if ".".join(parts[-2:]) in {"co.uk", "co.jp", "com.au", "co.in"} and len(parts) >= 3:
        return ".".join(parts[-3:])

    return ".".join(parts[-2:])


def domain_matches(hostname: str, trusted_domain: str) -> bool:
    return hostname == trusted_domain or hostname.endswith("." + trusted_domain)


def validate_domain(url: str, brand_keywords=None):
    if brand_keywords is None:
        brand_keywords = []

    hostname = get_hostname(url)
    root_domain = get_root_domain(hostname)

    result = {
        "hostname": hostname,
        "root_domain": root_domain,
        "trusted_domain": False,
        "trusted_match_domain": None,
        "brand_domain_match": False,
        "brand_spoofing_suspected": False,
        "matched_brands": [],
        "domain_risk_score": 0,
        "domain_reasons": []
    }

    for trusted in POPULAR_TRUSTED_DOMAINS:
        if domain_matches(hostname, trusted):
            result["trusted_domain"] = True
            result["trusted_match_domain"] = trusted
            result["domain_risk_score"] -= 25
            result["domain_reasons"].append(
                f"The URL belongs to a recognized trusted domain: {trusted}."
            )
            break

    for brand in brand_keywords:
        if brand not in TRUSTED_BRAND_DOMAINS:
            continue

        result["matched_brands"].append(brand)
        trusted_domains = TRUSTED_BRAND_DOMAINS[brand]

        if not trusted_domains:
            result["domain_risk_score"] += 6
            result["domain_reasons"].append(
                f"The URL contains a sensitive brand/category term ('{brand}'), but it does not have a strict trusted-domain mapping."
            )
            continue

        matched = any(domain_matches(hostname, d) for d in trusted_domains)

        if matched:
            result["brand_domain_match"] = True
            result["trusted_domain"] = True
            result["domain_risk_score"] -= 30
            result["domain_reasons"].append(
                f"Brand term '{brand}' matches an official trusted domain."
            )
        else:
            result["brand_spoofing_suspected"] = True
            result["domain_risk_score"] += 35
            result["domain_reasons"].append(
                f"Brand term '{brand}' appears in the URL, but the domain does not match an official trusted domain."
            )

    result["domain_risk_score"] = max(0, min(100, result["domain_risk_score"] + 25))

    return result