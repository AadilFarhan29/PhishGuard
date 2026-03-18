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
    parsed = urlparse((url or "").strip())
    if not parsed.netloc:
        parsed = urlparse("https://" + (url or "").strip())
    return parsed.netloc.lower().split(":")[0]


def get_root_domain(hostname: str) -> str:
    parts = [part for part in (hostname or "").split(".") if part]

    if len(parts) <= 2:
        return hostname

    last_two = ".".join(parts[-2:])
    last_three = ".".join(parts[-3:])

    if last_two in COMMON_SECOND_LEVEL_SUFFIXES and len(parts) >= 3:
        return last_three

    return last_two


def domain_matches(hostname: str, trusted_domain: str) -> bool:
    return hostname == trusted_domain or hostname.endswith("." + trusted_domain)


def get_trusted_domains_for_brand(brand: str):
    return TRUSTED_BRAND_DOMAINS.get((brand or "").lower(), [])


def find_trusted_match(hostname: str):
    for trusted_domain in sorted(POPULAR_TRUSTED_DOMAINS, key=len, reverse=True):
        if domain_matches(hostname, trusted_domain):
            return trusted_domain
    return None


def is_trusted_hostname(hostname: str) -> bool:
    return find_trusted_match(hostname) is not None


def _append_reason(reasons, reason):
    if reason and reason not in reasons:
        reasons.append(reason)


def validate_domain(url: str, brand_keywords=None, final_url: str = None):
    if brand_keywords is None:
        brand_keywords = []

    hostname = get_hostname(url)
    root_domain = get_root_domain(hostname)

    final_hostname = get_hostname(final_url) if final_url else hostname
    final_root_domain = get_root_domain(final_hostname)

    original_trusted_match = find_trusted_match(hostname)
    final_trusted_match = find_trusted_match(final_hostname)

    result = {
        "hostname": hostname,
        "root_domain": root_domain,
        "final_hostname": final_hostname,
        "final_root_domain": final_root_domain,
        "original_trusted_domain": original_trusted_match is not None,
        "final_trusted_domain": final_trusted_match is not None,
        "trusted_domain": final_trusted_match is not None or original_trusted_match is not None,
        "trusted_match_domain": final_trusted_match or original_trusted_match,
        "brand_domain_match": False,
        "brand_spoofing_suspected": False,
        "matched_brands": [],
        "final_domain_matches_original": final_root_domain == root_domain,
        "domain_risk_score": 25,
        "domain_reasons": []
    }

    if original_trusted_match:
        result["domain_risk_score"] -= 12
        _append_reason(
            result["domain_reasons"],
            f"The submitted hostname is a recognized trusted domain: {original_trusted_match}."
        )

    if final_trusted_match:
        result["domain_risk_score"] -= 16
        if final_hostname == hostname:
            _append_reason(
                result["domain_reasons"],
                f"The resolved hostname is a recognized trusted domain: {final_trusted_match}."
            )
        else:
            _append_reason(
                result["domain_reasons"],
                f"The final resolved hostname belongs to a trusted domain: {final_trusted_match}."
            )

    if final_root_domain != root_domain:
        result["domain_risk_score"] += 10
        _append_reason(
            result["domain_reasons"],
            "The original hostname and the final resolved hostname belong to different registered domains."
        )
    elif final_hostname != hostname:
        _append_reason(
            result["domain_reasons"],
            "The URL redirects within the same registered domain, which is less suspicious than a cross-domain redirect."
        )

    brand_matches = []
    original_only_brand_matches = []
    unmatched_brands = []

    for brand in sorted(set(brand_keywords)):
        trusted_domains = get_trusted_domains_for_brand(brand)
        result["matched_brands"].append(brand)

        if not trusted_domains:
            unmatched_brands.append((brand, False))
            continue

        original_brand_match = any(domain_matches(hostname, domain) for domain in trusted_domains)
        final_brand_match = any(domain_matches(final_hostname, domain) for domain in trusted_domains)

        if final_brand_match:
            brand_matches.append(brand)
        elif original_brand_match:
            original_only_brand_matches.append(brand)
        else:
            unmatched_brands.append((brand, True))

    if brand_matches:
        result["brand_domain_match"] = True
        result["trusted_domain"] = True
        result["domain_risk_score"] -= 26
        _append_reason(
            result["domain_reasons"],
            f"Detected brand context aligns with an official trusted final domain: {', '.join(brand_matches)}."
        )

    if original_only_brand_matches:
        if final_root_domain != root_domain:
            result["brand_spoofing_suspected"] = True
            result["domain_risk_score"] += 12
            _append_reason(
                result["domain_reasons"],
                f"The original hostname matched brand context ({', '.join(original_only_brand_matches)}), but the final destination moved away from that trusted domain."
            )
        else:
            result["domain_risk_score"] -= 12
            _append_reason(
                result["domain_reasons"],
                f"Detected brand context remains on the expected domain: {', '.join(original_only_brand_matches)}."
            )

    if unmatched_brands and not brand_matches:
        mapped_unmatched = [brand for brand, has_mapping in unmatched_brands if has_mapping]
        unmapped_brands = [brand for brand, has_mapping in unmatched_brands if not has_mapping]

        if mapped_unmatched:
            result["brand_spoofing_suspected"] = True
            result["domain_risk_score"] += 34
            _append_reason(
                result["domain_reasons"],
                f"Brand terms appear in the URL context, but neither the original nor final domain matches the official domain for: {', '.join(mapped_unmatched)}."
            )

        for brand in unmapped_brands:
            result["domain_risk_score"] += 6
            _append_reason(
                result["domain_reasons"],
                f"The URL contains the sensitive brand/category term '{brand}', but it does not have a strict trusted-domain mapping."
            )

    if result["trusted_domain"] and result["brand_domain_match"] and not result["brand_spoofing_suspected"]:
        result["domain_risk_score"] -= 8

    result["domain_risk_score"] = max(0, min(100, result["domain_risk_score"]))

    if not result["domain_reasons"]:
        _append_reason(
            result["domain_reasons"],
            "No strong domain trust or spoofing indicators were found from hostname analysis."
        )

    return result
