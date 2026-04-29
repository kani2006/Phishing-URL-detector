import requests
import json

BASE = "http://localhost:5000"

test_cases = [
    {
        "name": "Obvious phishing",
        "email_text": (
            "Dear customer, your PayPal account has been suspended. "
            "Verify your identity immediately at http://paypal-secure-login.xyz/verify "
            "or your account will be permanently closed."
        ),
        "expect": "high",
    },
    {
        "name": "Phishing with IP URL",
        "email_text": (
            "URGENT: Your bank account is at risk. Login at http://192.168.1.1/banking/login "
            "to confirm your details and avoid suspension."
        ),
        "expect": "high",
    },
    {
        "name": "Benign email",
        "email_text": (
            "Hi team, just a reminder that the sprint review is tomorrow at 10am. "
            "Please have your updates ready. Thanks."
        ),
        "expect": "low",
    },
    {
        "name": "Benign with legit URL",
        "email_text": (
            "Here are the docs you asked for: https://docs.python.org/3/library/re.html "
            "Let me know if you need anything else."
        ),
        "expect": "low",
    },
    {
        "name": "Suspicious keywords, no URL",
        "email_text": (
            "Verify your account now. Your password has expired. "
            "Update your banking credentials immediately to avoid losing access."
        ),
        "expect": "medium",
    },
]


def run_tests():
    # Health check first
    try:
        r = requests.get(f"{BASE}/health", timeout=5)
        r.raise_for_status()
        print("✓ API is up\n")
    except Exception as e:
        print(f"✗ API not reachable: {e}")
        print("  Make sure app.py is running: python3 app.py")
        return

    passed = 0
    for i, case in enumerate(test_cases, 1):
        r = requests.post(
            f"{BASE}/analyze",
            json={"email_text": case["email_text"]},
            timeout=10,
        )
        result = r.json()

        status = "✓" if result["risk_level"] == case["expect"] else "~"
        if result["risk_level"] == case["expect"]:
            passed += 1

        print(f"[{i}] {case['name']}")
        print(f"     Expected : {case['expect']}")
        print(f"     Got      : {result['risk_level']}  (score={result['final_score']}, phishing={result['is_phishing']})")
        print(f"     Email score: {result['email_score']}  |  URL score: {result['url_score']}")
        if result["urls_found"]:
            print(f"     URLs: {result['urls_found']}")
        print(f"     {status}\n")

    print(f"Results: {passed}/{len(test_cases)} matched expected risk level")


if __name__ == "__main__":
    run_tests()


def test_inspect():
    """Test the safe URL inspector on a known safe public URL."""
    print("\n=== Testing Safe URL Inspector ===\n")

    # Use a real benign URL to verify the inspector works
    test_url = "https://example.com"
    r = requests.post(f"{BASE}/inspect", json={"url": test_url}, timeout=15)
    result = r.json()

    print(f"URL        : {result['url']}")
    print(f"Safe fetch : {result['safe_to_fetch']}")
    print(f"Status     : {result.get('status_code')}")
    print(f"Title      : {result.get('title')}")
    print(f"Redirects  : {result.get('redirect_chain')}")
    print(f"Page size  : {result.get('page_size_bytes')} bytes")
    print(f"Signals    : {result.get('signals')}")
    print(f"Text preview: {result.get('visible_text_preview', '')[:200]}")

    # Test blocked private IP
    print("\n--- Testing private IP block ---")
    r2 = requests.post(f"{BASE}/inspect", json={"url": "http://192.168.1.1/login"}, timeout=10)
    r2_json = r2.json()
    blocked = not r2_json.get("safe_to_fetch", True)
    print(f"Private IP blocked: {'✓' if blocked else '✗'}  reason={r2_json.get('blocked_reason')}")

    # Test full pipeline
    print("\n=== Testing analyze_and_inspect ===\n")
    r3 = requests.post(f"{BASE}/analyze_and_inspect", json={
        "email_text": (
            "Your account is suspended. Verify now at https://example.com to restore access."
        )
    }, timeout=20)
    r3_json = r3.json()
    print(f"Risk level     : {r3_json['analysis']['risk_level']}")
    print(f"Is phishing    : {r3_json['analysis']['is_phishing']}")
    print(f"URLs inspected : {len(r3_json['url_inspections'])}")
    for insp in r3_json["url_inspections"]:
        print(f"  → {insp['url']}  title={insp.get('title')}  signals={insp.get('signals')}")


if __name__ == "__main__":
    run_tests()
    test_inspect()
