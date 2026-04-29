import re
import tldextract
from urllib.parse import urlparse


# Regex to match URLs in plain text and HTML
URL_PATTERN = re.compile(
    r'https?://[^\s<>"\']+|www\.[^\s<>"\']+',
    re.IGNORECASE
)


def extract_urls(text: str) -> list[str]:
    return URL_PATTERN.findall(text)


def parse_url_features(url: str) -> dict:
    """
    Extract lexical/structural features from a single URL.
    These features feed into the URL classifier.
    """
    parsed = urlparse(url)
    ext = tldextract.extract(url)

    hostname = parsed.netloc or ""
    path = parsed.path or ""
    full_url = url

    return {
        "url_length": len(full_url),
        "hostname_length": len(hostname),
        "path_length": len(path),
        "num_dots": full_url.count("."),
        "num_hyphens": full_url.count("-"),
        "num_at": full_url.count("@"),
        "num_digits": sum(c.isdigit() for c in full_url),
        "num_subdomains": len(ext.subdomain.split(".")) if ext.subdomain else 0,
        "has_ip": int(bool(re.match(r'\d+\.\d+\.\d+\.\d+', hostname))),
        "has_https": int(parsed.scheme == "https"),
        "has_suspicious_words": int(
            bool(re.search(r'login|verify|secure|account|update|banking|paypal|ebay', full_url, re.I))
        ),
        "tld": ext.suffix or "unknown",
    }
