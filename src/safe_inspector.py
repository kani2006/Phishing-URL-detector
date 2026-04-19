"""
safe_inspector.py
Safely fetches and inspects content of a potentially malicious URL.

Safety measures:
  - Spoofed bot user-agent (won't trigger browser exploits)
  - No JavaScript execution (plain HTTP request only)
  - Redirects tracked but limited to 3 hops
  - No cookies stored or sent
  - Response size capped at 500 KB
  - Timeout of 8 seconds
  - Only text/html content parsed
  - Private/local IP ranges blocked
"""

import re
import socket
import ipaddress
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin


MAX_RESPONSE_BYTES = 500 * 1024   # 500 KB cap
MAX_REDIRECTS      = 3
REQUEST_TIMEOUT    = 8            # seconds

SAFE_HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Accept": "text/html,application/xhtml+xml",
    "Accept-Language": "en-US,en;q=0.5",
}

# Private/reserved IP ranges that should never be fetched
BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
]

# HTML form input types that suggest credential harvesting
CREDENTIAL_INPUT_TYPES = {"password", "email", "tel", "text"}

SUSPICIOUS_FORM_KEYWORDS = re.compile(
    r'(password|passwd|credit.?card|cvv|ssn|social.?security|bank|account|pin\b)',
    re.IGNORECASE
)


def _is_safe_host(hostname: str) -> tuple[bool, str]:
    """Block requests to private/local IP ranges."""
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(hostname))
        for network in BLOCKED_NETWORKS:
            if ip in network:
                return False, f"Blocked: {ip} is in private range {network}"
        return True, ""
    except Exception as e:
        return False, f"DNS resolution failed: {e}"


def _extract_signals(soup: BeautifulSoup, base_url: str) -> dict:
    """Extract phishing-relevant signals from parsed HTML."""

    # All visible text
    for tag in soup(["script", "style", "meta", "head"]):
        tag.decompose()
    visible_text = soup.get_text(separator=" ", strip=True)
    visible_text = re.sub(r'\s+', ' ', visible_text)[:3000]  # cap at 3000 chars

    # Page title
    title = soup.title.string.strip() if soup.title and soup.title.string else "N/A"

    # External links
    links = []
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if href.startswith("http"):
            links.append(href)
        elif href.startswith("/"):
            links.append(urljoin(base_url, href))
    external_links = [l for l in links if urlparse(l).netloc != urlparse(base_url).netloc]

    # Forms and input fields
    forms = soup.find_all("form")
    form_details = []
    for form in forms:
        action = form.get("action", "")
        inputs = form.find_all("input")
        input_types = [i.get("type", "text").lower() for i in inputs]
        input_names = [i.get("name", "") for i in inputs]
        form_details.append({
            "action": action,
            "input_types": input_types,
            "input_names": input_names,
        })

    # Suspicious signals
    has_password_field   = any(
        i.get("type", "").lower() == "password"
        for form in forms for i in form.find_all("input")
    )
    has_suspicious_form  = bool(SUSPICIOUS_FORM_KEYWORDS.search(str(soup)))
    has_hidden_iframe    = any(
        (f.get("width") in ("0", "1") or f.get("height") in ("0", "1") or
         f.get("style", "").replace(" ", "") in ("display:none", "visibility:hidden"))
        for f in soup.find_all("iframe")
    )
    external_form_action = any(
        urlparse(f.get("action", "")).netloc not in ("", urlparse(base_url).netloc)
        for f in forms
    )
    brand_impersonation  = bool(re.search(
        r'(paypal|amazon|apple|microsoft|google|netflix|bank\s*of|chase|wellsfargo|citibank)',
        visible_text, re.IGNORECASE
    ))

    return {
        "title": title,
        "visible_text_preview": visible_text[:500],
        "external_links_count": len(external_links),
        "external_links_sample": external_links[:5],
        "forms": form_details,
        "signals": {
            "has_password_field":    has_password_field,
            "has_suspicious_form":   has_suspicious_form,
            "has_hidden_iframe":     has_hidden_iframe,
            "external_form_action":  external_form_action,
            "brand_impersonation":   brand_impersonation,
        }
    }


def inspect(url: str) -> dict:
    """
    Safely fetch and inspect a URL.

    Returns:
        {
            "url": str,
            "safe_to_fetch": bool,
            "blocked_reason": str | None,
            "status_code": int | None,
            "content_type": str | None,
            "redirect_chain": list[str],
            "final_url": str,
            "page_size_bytes": int,
            "title": str,
            "visible_text_preview": str,
            "external_links_count": int,
            "external_links_sample": list[str],
            "forms": list[dict],
            "signals": dict,
            "error": str | None
        }
    """
    result = {
        "url": url,
        "safe_to_fetch": False,
        "blocked_reason": None,
        "status_code": None,
        "content_type": None,
        "redirect_chain": [],
        "final_url": url,
        "page_size_bytes": 0,
        "title": None,
        "visible_text_preview": None,
        "external_links_count": 0,
        "external_links_sample": [],
        "forms": [],
        "signals": {},
        "error": None,
    }

    # Validate host before making any request
    hostname = urlparse(url).hostname or ""
    safe, reason = _is_safe_host(hostname)
    if not safe:
        result["blocked_reason"] = reason
        return result

    result["safe_to_fetch"] = True

    try:
        session = requests.Session()
        session.max_redirects = MAX_REDIRECTS

        # Disable cookies entirely
        session.cookies.clear()
        session.cookies.set_policy(BlockAll())

        response = session.get(
            url,
            headers=SAFE_HEADERS,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            stream=True,          # stream so we can cap size
            verify=False,         # don't fail on bad certs (phishing sites often have them)
        )

        # Track redirect chain
        result["redirect_chain"] = [r.url for r in response.history]
        result["final_url"]      = response.url
        result["status_code"]    = response.status_code
        result["content_type"]   = response.headers.get("Content-Type", "")

        # Only parse HTML
        if "text/html" not in result["content_type"]:
            result["error"] = f"Non-HTML content type: {result['content_type']}"
            return result

        # Cap response size
        content = b""
        for chunk in response.iter_content(chunk_size=8192):
            content += chunk
            if len(content) > MAX_RESPONSE_BYTES:
                content = content[:MAX_RESPONSE_BYTES]
                break

        result["page_size_bytes"] = len(content)

        soup = BeautifulSoup(content, "html.parser")
        signals = _extract_signals(soup, result["final_url"])
        result.update(signals)

    except requests.exceptions.TooManyRedirects:
        result["error"] = "Too many redirects (> 3) — common phishing evasion tactic"
    except requests.exceptions.SSLError:
        result["error"] = "SSL certificate error"
    except requests.exceptions.ConnectionError as e:
        result["error"] = f"Connection error: {e}"
    except requests.exceptions.Timeout:
        result["error"] = "Request timed out after 8s"
    except Exception as e:
        result["error"] = str(e)

    return result


class BlockAll(requests.cookies.RequestsCookieJar):
    """Cookie jar that silently drops all cookies."""
    def set(self, *args, **kwargs):
        pass
    def set_cookie(self, *args, **kwargs):
        pass
