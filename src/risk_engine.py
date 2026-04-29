from url_extractor import extract_urls
from url_classifier import predict as url_predict
from email_classifier import predict as email_predict


EMAIL_WEIGHT = 0.45
URL_WEIGHT = 0.55

RISK_THRESHOLDS = {
    "low":    (0.0,  0.35),
    "medium": (0.35, 0.65),
    "high":   (0.65, 1.01),
}


def _url_score(email_text: str) -> float:
    """
    Extract URLs from email and return the max phishing probability
    across all found URLs. Returns 0.0 if no URLs found.
    """
    urls = extract_urls(email_text)
    if not urls:
        return 0.0
    scores = [url_predict(u) for u in urls]
    return max(scores)


def _risk_label(score: float) -> str:
    for label, (low, high) in RISK_THRESHOLDS.items():
        if low <= score < high:
            return label
    return "high"


def analyze(email_text: str) -> dict:
    email_score = email_predict(email_text)
    url_score = _url_score(email_text)
    urls_found = extract_urls(email_text)

    if not urls_found:
        final_score = email_score
    else:
        final_score = (EMAIL_WEIGHT * email_score) + (URL_WEIGHT * url_score)

    return {
        "email_score": round(email_score, 4),
        "url_score": round(url_score, 4),
        "urls_found": urls_found,
        "final_score": round(final_score, 4),
        "risk_level": _risk_label(final_score),
        "is_phishing": final_score >= 0.5,
    }
