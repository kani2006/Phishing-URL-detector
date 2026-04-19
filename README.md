# Phishing Hybrid Detector

A hybrid phishing detection engine combining URL feature analysis and email NLP signals.

## Architecture

```
Email Text
    │
    ├──► URL Extractor ──► URL Classifier (Random Forest)  ──► URL Score
    │                                                              │
    └──► Email NLP Classifier (TF-IDF + Logistic Regression) ──► Email Score
                                                                   │
                                                          Risk Engine (weighted fusion)
                                                                   │
                                                          Final Phishing Score + Label
```

## Setup

```bash
pip install -r requirements.txt
```

## Training

Prepare two CSVs in `data/`:

`data/urls.csv`
```
url,label
https://paypal-login.xyz/verify,1
https://google.com,0
```

`data/emails.csv`
```
text,label
"Dear user, verify your account now at http://...",1
"Hi, your invoice is attached.",0
```

Then train via the API:
```bash
curl -X POST http://localhost:5000/train \
  -H "Content-Type: application/json" \
  -d '{"url_data": "data/urls.csv", "email_data": "data/emails.csv"}'
```

Or directly from Python:
```python
from src.url_classifier import train as train_url
from src.email_classifier import train as train_email

train_url("data/urls.csv")
train_email("data/emails.csv")
```

## Running the API

```bash
python app.py
```

## Analyzing an Email

```bash
curl -X POST http://localhost:5000/analyze \
  -H "Content-Type: application/json" \
  -d '{"email_text": "Your account has been suspended. Verify now at http://paypal-secure.xyz/login"}'
```

Response:
```json
{
  "email_score": 0.87,
  "url_score": 0.93,
  "urls_found": ["http://paypal-secure.xyz/login"],
  "final_score": 0.90,
  "risk_level": "high",
  "is_phishing": true
}
```

## Scoring Logic

| Signal       | Weight |
|--------------|--------|
| Email NLP    | 45%    |
| URL features | 55%    |

Risk levels: `low` (< 0.35), `medium` (0.35–0.65), `high` (> 0.65)

## URL Features Used

- URL/hostname/path length
- Count of dots, hyphens, `@` symbols, digits
- Number of subdomains
- IP address in hostname
- HTTPS presence
- Suspicious keyword match (login, verify, secure, etc.)
- TLD encoding
