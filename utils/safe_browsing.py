import os
import requests

SAFE_BROWSING_API_KEY = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY")
SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


def check_url_safe_browsing(url: str) -> dict:
    """
    Checks a URL against Google Safe Browsing API.

    Returns a dict with:
        - checked (bool): Whether the API call was made
        - is_threat (bool): True if URL is flagged
        - threat_type (str|None): e.g. 'MALWARE', 'SOCIAL_ENGINEERING'
        - threat_platform (str|None): e.g. 'ANY_PLATFORM'
        - error (str|None): Error message if API call failed
        - api_available (bool): False if key is missing or API is down
    """

    result = {
        "checked": False,
        "is_threat": False,
        "threat_type": None,
        "threat_platform": None,
        "error": None,
        "api_available": False
    }

    if not SAFE_BROWSING_API_KEY:
        result["error"] = "Google Safe Browsing API key not configured."
        return result

    payload = {
        "client": {
            "clientId": "phishguard",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        response = requests.post(
            SAFE_BROWSING_URL,
            params={"key": SAFE_BROWSING_API_KEY},
            json=payload,
            timeout=5
        )

        result["checked"] = True
        result["api_available"] = True

        if response.status_code == 200:
            data = response.json()
            matches = data.get("matches", [])

            if matches:
                result["is_threat"] = True
                result["threat_type"] = matches[0].get("threatType")
                result["threat_platform"] = matches[0].get("platformType")
            # Empty response = URL is clean according to Google
        else:
            result["error"] = f"API returned status {response.status_code}"
            result["api_available"] = False

    except requests.exceptions.Timeout:
        result["error"] = "Safe Browsing API request timed out."
    except requests.exceptions.RequestException as e:
        result["error"] = f"Safe Browsing API request failed: {str(e)}"

    return result