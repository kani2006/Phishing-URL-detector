import os
import sys
import requests
import pandas as pd
import random
import string

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
os.makedirs(DATA_DIR, exist_ok=True)


ENRON_URL = (
    "https://raw.githubusercontent.com/MWiechmann/enron_spam_data/master/enron_spam_data.csv"
)

PHISHING_URLS_URL = (
    "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt"
)

BENIGN_URLS_URL = (
    "https://raw.githubusercontent.com/nicktindall/cyclon.p2p/master/test/data/urls.txt"
)

def download(url: str, label: str) -> bytes | None:
    print(f"  Downloading {label}...")
    try:
        r = requests.get(url, timeout=30)
        r.raise_for_status()
        print(f"  ✓ {label} ({len(r.content) // 1024} KB)")
        return r.content
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        return None


def prepare_emails():
    out_path = os.path.join(DATA_DIR, "emails.csv")
    if os.path.exists(out_path):
        print(f"  emails.csv already exists, skipping.")
        return

    raw = download(ENRON_URL, "Enron spam/ham emails")
    if raw:
        df = pd.read_csv(pd.io.common.BytesIO(raw))
        print(f"  Columns: {list(df.columns)}")

        # Enron dataset has: Message ID, Subject, Message, Spam/Ham
        # Normalise to: text, label
        text_col = next((c for c in df.columns if "message" in c.lower()), df.columns[0])
        label_col = next((c for c in df.columns if "spam" in c.lower() or "label" in c.lower()), df.columns[-1])

        df = df[[text_col, label_col]].dropna()
        df.columns = ["text", "spam_label"]

        # Map spam/ham → 1/0
        df["label"] = df["spam_label"].apply(
            lambda x: 1 if str(x).strip().lower() in ("spam", "1", "true") else 0
        )
        df = df[["text", "label"]]

        # Balance classes (max 5000 each)
        spam = df[df["label"] == 1].sample(min(5000, len(df[df["label"] == 1])), random_state=42)
        ham  = df[df["label"] == 0].sample(min(5000, len(df[df["label"] == 0])), random_state=42)
        df = pd.concat([spam, ham]).sample(frac=1, random_state=42).reset_index(drop=True)

        df.to_csv(out_path, index=False)
        print(f"  ✓ Saved {len(df)} emails → data/emails.csv  (spam={len(spam)}, ham={len(ham)})")
    else:
        _generate_synthetic_emails(out_path)


def _generate_synthetic_emails(out_path: str):
    """Fallback: generate a small synthetic email dataset."""
    print("  Generating synthetic email dataset as fallback...")
    phishing_templates = [
        "Dear customer, your account has been suspended. Verify immediately at http://secure-login-{}.xyz/verify",
        "URGENT: Your PayPal account needs verification. Click http://paypal-{}.com/update now.",
        "Your bank account is at risk. Login at http://banking-secure-{}.net to confirm.",
        "Congratulations! You won a prize. Claim at http://prize-claim-{}.com/winner",
        "Your password expires today. Reset at http://account-reset-{}.xyz/password",
    ]
    benign_templates = [
        "Hi, please find the meeting notes attached. Let me know if you have questions.",
        "The quarterly report is ready for review. I've uploaded it to the shared drive.",
        "Reminder: team standup tomorrow at 10am. Agenda: sprint review and planning.",
        "Thanks for your order! Your package will arrive in 3-5 business days.",
        "Your subscription has been renewed. Receipt attached for your records.",
    ]

    rows = []
    for i in range(2000):
        if i % 2 == 0:
            t = random.choice(phishing_templates).format(''.join(random.choices(string.ascii_lowercase, k=6)))
            rows.append({"text": t, "label": 1})
        else:
            rows.append({"text": random.choice(benign_templates), "label": 0})

    df = pd.DataFrame(rows).sample(frac=1, random_state=42).reset_index(drop=True)
    df.to_csv(out_path, index=False)
    print(f"  ✓ Saved {len(df)} synthetic emails → data/emails.csv")


def prepare_urls():
    out_path = os.path.join(DATA_DIR, "urls.csv")
    if os.path.exists(out_path):
        print(f"  urls.csv already exists, skipping.")
        return

    phishing_urls = []
    benign_urls = []

    # Phishing URLs
    raw = download(PHISHING_URLS_URL, "Phishing domains list")
    if raw:
        domains = raw.decode("utf-8", errors="ignore").strip().splitlines()
        domains = [d.strip() for d in domains if d.strip() and not d.startswith("#")]
        phishing_urls = [f"http://{d}" for d in domains[:5000]]
        print(f"  ✓ Got {len(phishing_urls)} phishing URLs")

    # Benign URLs — use Alexa/common well-known domains as fallback
    benign_domains = [
        "google.com", "youtube.com", "facebook.com", "amazon.com", "wikipedia.org",
        "twitter.com", "instagram.com", "linkedin.com", "reddit.com", "github.com",
        "stackoverflow.com", "microsoft.com", "apple.com", "netflix.com", "spotify.com",
        "bbc.com", "cnn.com", "nytimes.com", "theguardian.com", "medium.com",
        "dropbox.com", "slack.com", "zoom.us", "notion.so", "trello.com",
    ]
    # Expand with path variations
    paths = ["/", "/about", "/login", "/home", "/contact", "/products", "/services"]
    for domain in benign_domains:
        for path in paths:
            benign_urls.append(f"https://{domain}{path}")
    # Pad to match phishing count
    while len(benign_urls) < len(phishing_urls):
        d = random.choice(benign_domains)
        p = ''.join(random.choices(string.ascii_lowercase, k=5))
        benign_urls.append(f"https://{d}/{p}")

    benign_urls = benign_urls[:len(phishing_urls)]

    if not phishing_urls:
        _generate_synthetic_urls(out_path)
        return

    rows = (
        [{"url": u, "label": 1} for u in phishing_urls] +
        [{"url": u, "label": 0} for u in benign_urls]
    )
    df = pd.DataFrame(rows).sample(frac=1, random_state=42).reset_index(drop=True)
    df.to_csv(out_path, index=False)
    print(f"  ✓ Saved {len(df)} URLs → data/urls.csv  (phishing={len(phishing_urls)}, benign={len(benign_urls)})")


def _generate_synthetic_urls(out_path: str):
    """Fallback: generate synthetic URL dataset."""
    print("  Generating synthetic URL dataset as fallback...")
    phishing_patterns = [
        "http://paypal-secure-{}.xyz/login/verify",
        "http://account-update-{}.com/banking/confirm",
        "http://192.168.{}.{}/phish/login",
        "http://secure-{}.tk/update/password",
        "http://login-verify-{}.ml/account",
    ]
    benign_patterns = [
        "https://google.com/search?q={}",
        "https://github.com/{}/repo",
        "https://stackoverflow.com/questions/{}",
        "https://wikipedia.org/wiki/{}",
        "https://amazon.com/product/{}",
    ]

    rows = []
    for i in range(3000):
        rand = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        if i % 2 == 0:
            url = random.choice(phishing_patterns).format(rand, rand)
            rows.append({"url": url, "label": 1})
        else:
            url = random.choice(benign_patterns).format(rand)
            rows.append({"url": url, "label": 0})

    df = pd.DataFrame(rows).sample(frac=1, random_state=42).reset_index(drop=True)
    df.to_csv(out_path, index=False)
    print(f"  Saved {len(df)} synthetic URLs → data/urls.csv")

if __name__ == "__main__":
    print("\n=== Preparing Email Dataset ===")
    prepare_emails()

    print("\n=== Preparing URL Dataset ===")
    prepare_urls()

    print("\n=== Done ===")
    print("Now train the models:")
    print("  python3 train.py")
