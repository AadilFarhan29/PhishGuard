import requests

from utils.domain_validator import (
    domain_matches,
    find_trusted_match,
    get_hostname,
    get_root_domain,
    get_trusted_domains_for_brand,
)
from utils.page_analyzer import HEADERS


def _append_reason(reasons, reason):
    if reason and reason not in reasons:
        reasons.append(reason)


def analyze_redirects(url: str, brand_keywords=None):
    if brand_keywords is None:
        brand_keywords = []

    original_hostname = get_hostname(url)
    original_root_domain = get_root_domain(original_hostname)

    result = {
        "redirect_checked": False,
        "redirect_hops": 0,
        "redirect_chain": [],
        "original_url": url,
        "final_url": url,
        "original_hostname": original_hostname,
        "final_hostname": original_hostname,
        "original_root_domain": original_root_domain,
        "final_root_domain": original_root_domain,
        "final_domain_differs": False,
        "final_domain_trusted": False,
        "final_trusted_match_domain": None,
        "brand_mismatch_detected": False,
        "final_brand_match": False,
        "redirect_risk_score": 0,
        "redirect_reasons": [],
        "status_code": None,
        "error": None
    }

    try:
        with requests.Session() as session:
            response = session.get(
                url,
                headers=HEADERS,
                timeout=8,
                allow_redirects=True,
                stream=True
            )

            history = list(response.history) + [response]
            final_url = response.url or url
            final_hostname = get_hostname(final_url)
            final_root_domain = get_root_domain(final_hostname)
            final_trusted_match = find_trusted_match(final_hostname)

            result["redirect_checked"] = True
            result["redirect_hops"] = max(0, len(history) - 1)
            result["final_url"] = final_url
            result["final_hostname"] = final_hostname
            result["final_root_domain"] = final_root_domain
            result["final_domain_differs"] = final_root_domain != original_root_domain
            result["final_domain_trusted"] = final_trusted_match is not None
            result["final_trusted_match_domain"] = final_trusted_match
            result["status_code"] = response.status_code

            for hop in history:
                hop_url = hop.url or final_url
                hop_hostname = get_hostname(hop_url)
                result["redirect_chain"].append({
                    "url": hop_url,
                    "hostname": hop_hostname,
                    "status_code": hop.status_code,
                    "trusted_domain": find_trusted_match(hop_hostname)
                })

            if result["redirect_hops"] > 0:
                result["redirect_risk_score"] += min(20, result["redirect_hops"] * 6)
                _append_reason(
                    result["redirect_reasons"],
                    f"The URL redirected {result['redirect_hops']} time(s) before loading the final destination."
                )
            else:
                _append_reason(
                    result["redirect_reasons"],
                    "No redirect chain was observed before the page loaded."
                )

            if result["final_domain_differs"]:
                result["redirect_risk_score"] += 24
                _append_reason(
                    result["redirect_reasons"],
                    "The final destination belongs to a different registered domain than the submitted URL."
                )
            elif final_hostname != original_hostname:
                result["redirect_risk_score"] += 4
                _append_reason(
                    result["redirect_reasons"],
                    "The link redirected within the same registered domain."
                )

            if result["redirect_hops"] >= 3 and result["final_domain_differs"]:
                result["redirect_risk_score"] += 10
                _append_reason(
                    result["redirect_reasons"],
                    "Multiple redirect hops combined with a destination change can be used to hide the real landing page."
                )

            matched_brands = []
            unmatched_brands = []

            for brand in sorted(set(brand_keywords)):
                trusted_domains = get_trusted_domains_for_brand(brand)
                if not trusted_domains:
                    continue

                if any(domain_matches(final_hostname, trusted_domain) for trusted_domain in trusted_domains):
                    matched_brands.append(brand)
                else:
                    unmatched_brands.append(brand)

            if matched_brands:
                result["final_brand_match"] = True
                result["redirect_risk_score"] -= 20
                _append_reason(
                    result["redirect_reasons"],
                    f"The redirect chain resolved to the official trusted domain for brand context: {', '.join(matched_brands)}."
                )

            if unmatched_brands and not matched_brands:
                result["brand_mismatch_detected"] = True
                result["redirect_risk_score"] += 28
                _append_reason(
                    result["redirect_reasons"],
                    f"Detected brand context does not match the final redirect destination for: {', '.join(unmatched_brands)}."
                )

            if result["final_domain_trusted"] and not result["brand_mismatch_detected"]:
                result["redirect_risk_score"] -= 8
                _append_reason(
                    result["redirect_reasons"],
                    f"The final destination is a recognized trusted domain: {final_trusted_match}."
                )

            if (
                result["final_domain_trusted"]
                and result["final_domain_differs"]
                and any(
                    domain_matches(final_hostname, trusted_domain)
                    for brand in brand_keywords
                    for trusted_domain in get_trusted_domains_for_brand(brand)
                )
            ):
                result["redirect_risk_score"] -= 6

            result["redirect_risk_score"] = max(0, min(100, result["redirect_risk_score"]))

    except Exception as exc:
        result["error"] = str(exc)
        _append_reason(
            result["redirect_reasons"],
            "Redirect inspection could not be completed, so the result relies more heavily on the other engines."
        )

    return result
