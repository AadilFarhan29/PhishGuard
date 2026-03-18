import re
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from utils.domain_validator import get_hostname, get_root_domain


HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "keep-alive",
}


SUSPICIOUS_FORM_KEYWORDS = {
    "verify", "validate", "token", "session", "auth",
    "cmd", "gate", "process", "update", "secure",
    "signin", "login", "password", "account", "wallet"
}


def _append_reason(reasons, reason):
    if reason and reason not in reasons:
        reasons.append(reason)


def _looks_random_segment(segment: str) -> bool:
    cleaned = re.sub(r"[^a-z0-9]", "", (segment or "").lower())
    if len(cleaned) < 12:
        return False

    digit_count = sum(char.isdigit() for char in cleaned)
    vowel_count = sum(char in "aeiou" for char in cleaned)
    has_letters = any(char.isalpha() for char in cleaned)

    return has_letters and digit_count >= 3 and vowel_count <= max(1, len(cleaned) // 6)


def _is_suspicious_form_path(parsed_action) -> bool:
    path = (parsed_action.path or "").lower()
    segments = [segment for segment in path.split("/") if segment]

    if path.endswith(".php"):
        return True

    if any(keyword in path for keyword in SUSPICIOUS_FORM_KEYWORDS):
        return True

    return any(_looks_random_segment(segment) for segment in segments)


def analyze_webpage(url):
    results = {
        "page_accessible": False,
        "analyzed_url": url,
        "page_hostname": get_hostname(url),
        "forms": 0,
        "password_fields": 0,
        "iframes": 0,
        "external_scripts": 0,
        "external_links": 0,
        "has_favicon": False,
        "same_domain_form_actions": 0,
        "external_form_actions": 0,
        "blank_form_actions": 0,
        "suspicious_form_actions": 0,
        "password_form_external_actions": 0,
        "form_action_details": [],
        "form_risk_score": 0,
        "page_risk_score": 24,
        "page_reasons": [],
        "status_code": None,
        "errors": None
    }

    try:
        response = requests.get(
            url,
            headers=HEADERS,
            timeout=8,
            allow_redirects=True
        )

        results["status_code"] = response.status_code
        results["analyzed_url"] = response.url or url
        results["page_hostname"] = get_hostname(results["analyzed_url"])

        if response.status_code != 200:
            results["errors"] = f"HTTP status {response.status_code}"
            results["page_reasons"].append(
                f"Webpage inspection returned HTTP status {response.status_code}."
            )
            return results

        soup = BeautifulSoup(response.text, "html.parser")
        page_root_domain = get_root_domain(results["page_hostname"])

        results["page_accessible"] = True
        results["page_risk_score"] = 0

        forms = soup.find_all("form")
        results["forms"] = len(forms)

        password_fields = soup.find_all("input", {"type": "password"})
        results["password_fields"] = len(password_fields)

        iframes = soup.find_all("iframe")
        results["iframes"] = len(iframes)

        scripts = soup.find_all("script", src=True)
        links = soup.find_all("a", href=True)

        external_scripts = 0
        for script in scripts:
            src = script.get("src", "")
            if src.startswith("http"):
                script_host = get_hostname(src)
                if get_root_domain(script_host) != page_root_domain:
                    external_scripts += 1

        external_links = 0
        for link in links:
            href = link.get("href", "")
            if href.startswith("http"):
                link_host = get_hostname(href)
                if get_root_domain(link_host) != page_root_domain:
                    external_links += 1

        results["external_scripts"] = external_scripts
        results["external_links"] = external_links

        favicon = soup.find("link", rel=lambda value: value and "icon" in str(value).lower())
        results["has_favicon"] = favicon is not None

        for form in forms:
            action = (form.get("action") or "").strip()
            resolved_action = results["analyzed_url"]
            relationship = "Inline / current page"
            action_hostname = results["page_hostname"]

            if action in {"", "#"}:
                results["blank_form_actions"] += 1
                results["same_domain_form_actions"] += 1
                relationship = "Same domain"
            elif action.lower().startswith(("javascript:", "mailto:", "tel:")):
                relationship = "Unusual handler"
                resolved_action = action
                action_hostname = None
            else:
                resolved_action = urljoin(results["analyzed_url"], action)
                action_hostname = get_hostname(resolved_action)
                action_root_domain = get_root_domain(action_hostname)

                if action_root_domain == page_root_domain:
                    relationship = "Same domain"
                    results["same_domain_form_actions"] += 1
                else:
                    relationship = "External domain"
                    results["external_form_actions"] += 1

            parsed_action = urlparse(resolved_action if resolved_action.startswith("http") else "")
            suspicious_action = _is_suspicious_form_path(parsed_action) if parsed_action.netloc else relationship == "Unusual handler"
            has_password_field = form.find("input", {"type": "password"}) is not None

            if suspicious_action:
                results["suspicious_form_actions"] += 1

            if relationship == "External domain" and has_password_field:
                results["password_form_external_actions"] += 1

            if len(results["form_action_details"]) < 4:
                results["form_action_details"].append({
                    "action": action or "(blank action)",
                    "resolved_action": resolved_action,
                    "destination_hostname": action_hostname,
                    "relationship": relationship,
                    "suspicious": suspicious_action,
                    "has_password_field": has_password_field
                })

        form_risk_score = 0
        if results["external_form_actions"] > 0:
            form_risk_score += 26
            _append_reason(
                results["page_reasons"],
                "At least one form submits data to an external domain."
            )

        if results["suspicious_form_actions"] > 0:
            form_risk_score += 18
            _append_reason(
                results["page_reasons"],
                "A form action uses a suspicious endpoint, script handler, or random-looking path."
            )

        if results["password_form_external_actions"] > 0:
            form_risk_score += 28
            _append_reason(
                results["page_reasons"],
                "A password-collecting form submits to an external destination."
            )

        if results["same_domain_form_actions"] > 0 and results["external_form_actions"] == 0:
            form_risk_score -= 6
            _append_reason(
                results["page_reasons"],
                "Observed forms submit back to the same domain, which is a healthier sign."
            )

        results["form_risk_score"] = max(0, min(100, form_risk_score))

        if results["password_fields"] > 0:
            results["page_risk_score"] += 28
            _append_reason(
                results["page_reasons"],
                "The page contains password input fields."
            )

        if results["forms"] > 2:
            results["page_risk_score"] += 8

        if results["iframes"] > 0:
            results["page_risk_score"] += 10
            _append_reason(
                results["page_reasons"],
                "The page contains iframe elements."
            )

        if results["external_scripts"] > 40:
            results["page_risk_score"] += 10
            _append_reason(
                results["page_reasons"],
                "The page loads a large number of scripts from external domains."
            )
        elif results["external_scripts"] > 15:
            results["page_risk_score"] += 4

        if results["external_links"] > 30:
            results["page_risk_score"] += 8
        elif results["external_links"] > 12:
            results["page_risk_score"] += 4

        if results["has_favicon"]:
            results["page_risk_score"] -= 4

        results["page_risk_score"] += round(results["form_risk_score"] * 0.55)
        results["page_risk_score"] = max(0, min(100, results["page_risk_score"]))

        if not results["page_reasons"]:
            _append_reason(
                results["page_reasons"],
                "The inspected page structure did not expose strong phishing-specific webpage indicators."
            )

    except Exception as exc:
        results["errors"] = str(exc)
        results["page_reasons"].append(
            "Webpage inspection could not be completed, so webpage-specific evidence is limited."
        )

    return results
