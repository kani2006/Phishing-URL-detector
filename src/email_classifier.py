"""
email_classifier.py
NLP-based classifier for email body text using TF-IDF + Logistic Regression.
"""

import os
import re
import joblib
import nltk
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

nltk.download("stopwords", quiet=True)
nltk.download("punkt", quiet=True)
from nltk.corpus import stopwords

MODEL_PATH = os.path.join(os.path.dirname(__file__), "../models/email_model.pkl")
STOP_WORDS = set(stopwords.words("english"))


def preprocess(text: str) -> str:
    """Lowercase, strip HTML tags, remove punctuation, drop stopwords."""
    text = re.sub(r'<[^>]+>', ' ', text)           # strip HTML
    text = re.sub(r'https?://\S+|www\.\S+', ' ', text)  # remove URLs
    text = re.sub(r'[^a-zA-Z\s]', ' ', text)       # keep only letters
    tokens = text.lower().split()
    tokens = [t for t in tokens if t not in STOP_WORDS and len(t) > 2]
    return " ".join(tokens)


def train(data_path: str):
    """
    Train the email classifier from a CSV with columns: text, label (0=benign, 1=phishing).
    Saves pipeline to models/.
    """
    df = pd.read_csv(data_path)
    df["clean"] = df["text"].apply(preprocess)

    X_train, X_test, y_train, y_test = train_test_split(
        df["clean"], df["label"], test_size=0.2, random_state=42
    )

    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(max_features=10000, ngram_range=(1, 2))),
        ("clf", LogisticRegression(max_iter=1000, C=1.0)),
    ])

    pipeline.fit(X_train, y_train)
    print(classification_report(y_test, pipeline.predict(X_test)))

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(pipeline, MODEL_PATH)
    print(f"Email model saved to {MODEL_PATH}")


def predict(email_text: str) -> float:
    """
    Returns phishing probability [0.0 - 1.0] for email body text.
    """
    pipeline = joblib.load(MODEL_PATH)
    clean = preprocess(email_text)
    prob = pipeline.predict_proba([clean])[0]
    classes = list(pipeline.classes_)
    return float(prob[classes.index(1)]) if 1 in classes else 0.0
