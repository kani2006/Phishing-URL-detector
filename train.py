import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

import url_classifier
import email_classifier

URL_DATA   = os.path.join(os.path.dirname(__file__), "data/urls.csv")
EMAIL_DATA = os.path.join(os.path.dirname(__file__), "data/emails.csv")

print("\n=== Training URL Classifier ===")
url_classifier.train(URL_DATA)

print("\n=== Training Email Classifier ===")
email_classifier.train(EMAIL_DATA)

print("\n=== All models trained. Run: python3 app.py ===")
