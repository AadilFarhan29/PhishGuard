import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse


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


def analyze_webpage(url):
    results = {
        "page_accessible": False,
        "forms": 0,
        "password_fields": 0,
        "iframes": 0,
        "external_scripts": 0,
        "external_links": 0,
        "has_favicon": False,
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

        if response.status_code != 200:
            results["errors"] = f"HTTP status {response.status_code}"
            return results

        html = response.text
        soup = BeautifulSoup(html, "html.parser")

        results["page_accessible"] = True

        # Forms
        forms = soup.find_all("form")
        results["forms"] = len(forms)

        # Password fields
        password_fields = soup.find_all("input", {"type": "password"})
        results["password_fields"] = len(password_fields)

        # Iframes
        iframes = soup.find_all("iframe")
        results["iframes"] = len(iframes)

        # External scripts
        scripts = soup.find_all("script", src=True)
        domain = urlparse(url).netloc
        external_scripts = 0

        for script in scripts:
            src = script.get("src", "")
            if src.startswith("http") and domain not in src:
                external_scripts += 1

        results["external_scripts"] = external_scripts

        # External links
        links = soup.find_all("a", href=True)
        external_links = 0

        for link in links:
            href = link["href"]
            if href.startswith("http") and domain not in href:
                external_links += 1

        results["external_links"] = external_links

        # Favicon
        favicon = soup.find("link", rel=lambda x: x and "icon" in str(x).lower())
        if favicon:
            results["has_favicon"] = True

    except Exception as e:
        results["errors"] = str(e)

    return results