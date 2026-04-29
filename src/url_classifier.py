import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

from url_extractor import parse_url_features

MODEL_PATH = os.path.join(os.path.dirname(__file__), "../models/url_model.pkl")
ENCODER_PATH = os.path.join(os.path.dirname(__file__), "../models/url_tld_encoder.pkl")

FEATURE_COLS = [
    "url_length", "hostname_length", "path_length", "num_dots",
    "num_hyphens", "num_at", "num_digits", "num_subdomains",
    "has_ip", "has_https", "has_suspicious_words", "tld_encoded"
]


def _encode_features(df: pd.DataFrame, encoder: LabelEncoder = None):
    """Encode the TLD categorical feature."""
    if encoder is None:
        encoder = LabelEncoder()
        df["tld_encoded"] = encoder.fit_transform(df["tld"].astype(str))
    else:
        # Handle unseen TLDs gracefully
        known = set(encoder.classes_)
        df["tld_encoded"] = df["tld"].apply(
            lambda x: encoder.transform([x])[0] if x in known else -1
        )
    return df, encoder


def train(data_path: str):
    """
    Train the URL classifier from a CSV with columns: url, label (0=benign, 1=phishing).
    Saves model and encoder to models/.
    """
    df = pd.read_csv(data_path)
    features = pd.DataFrame([parse_url_features(u) for u in df["url"]])
    features, encoder = _encode_features(features)

    X = features[FEATURE_COLS]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)

    print(classification_report(y_test, clf.predict(X_test)))

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(clf, MODEL_PATH)
    joblib.dump(encoder, ENCODER_PATH)
    print(f"URL model saved to {MODEL_PATH}")


def predict(url: str) -> float:
    clf = joblib.load(MODEL_PATH)
    encoder = joblib.load(ENCODER_PATH)

    features = pd.DataFrame([parse_url_features(url)])
    features, _ = _encode_features(features, encoder)

    X = features[FEATURE_COLS]
    prob = clf.predict_proba(X)[0]

    # Return probability of class 1 (phishing)
    classes = list(clf.classes_)
    return float(prob[classes.index(1)]) if 1 in classes else 0.0
