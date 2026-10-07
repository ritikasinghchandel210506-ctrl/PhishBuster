"""ML/NLP Detection Agent — loads the trained TF-IDF + classifier pipeline
and produces class probabilities for legitimate / spam / phishing."""
from __future__ import annotations

import os
from dataclasses import dataclass, field

import joblib

from utils.text_cleaner import clean_for_ml

MODELS_DIR = os.path.join(os.path.dirname(__file__), "..", "ml", "models")
MODEL_PATH = os.path.join(MODELS_DIR, "svm_model.pkl")
WORD_PATH = os.path.join(MODELS_DIR, "word_vectorizer.pkl")
CHAR_PATH = os.path.join(MODELS_DIR, "char_vectorizer.pkl")
SCALER_PATH = os.path.join(MODELS_DIR, "scaler.pkl")


@dataclass
class MLResult:
    available: bool
    predicted_label: str = "unknown"
    probabilities: dict = field(default_factory=dict)
    phishing_probability: float = 0.0
    message: str = ""


class MLAgent:
    name = "ML/NLP Detection Agent"

    def __init__(self):
        self.model = None
        self.word_vectorizer = None
        self.char_vectorizer = None
        self.scaler = None
        self.load_error = None
        self._load()

    def _load(self):
        if not all(os.path.exists(path) for path in [MODEL_PATH, WORD_PATH, CHAR_PATH, SCALER_PATH]):
            self.load_error = (
                "No trained model found. Run `python ml/train_model.py` "
                "to train it."
            )
            return
        try:
            self.model = joblib.load(MODEL_PATH)
            self.word_vectorizer = joblib.load(WORD_PATH)
            self.char_vectorizer = joblib.load(CHAR_PATH)
            self.scaler = joblib.load(SCALER_PATH)
        except Exception as exc:
            self.load_error = f"Failed to load ML model: {exc}"

    @property
    def is_ready(self) -> bool:
        return all([
            self.model is not None,
            self.word_vectorizer is not None,
            self.char_vectorizer is not None,
            self.scaler is not None
        ])

    def run(self, text: str) -> MLResult:
        if not self.is_ready:
            return MLResult(available=False, message=self.load_error or "ML model unavailable.")

        cleaned = clean_for_ml(text)
        if not cleaned:
            return MLResult(
                available=True, predicted_label="unknown", probabilities={},
                phishing_probability=0.0, message="Not enough text content to classify.",
            )

        word_features = self.word_vectorizer.transform([cleaned])
        char_features = self.char_vectorizer.transform([cleaned])

        import pandas as pd
        from scipy.sparse import hstack

        numeric_features = pd.DataFrame([{
            "body_length": len(text),
            "subject_length": 0,
            "url_length": 0,
            "word_count": len(text.split()),
            "url_count": 0,
            "has_url": 0,
            "exclamation_count": text.count("!"),
            "question_count": text.count("?"),
            "uppercase_count": sum(char.isupper() for char in text),
            "phishing_keyword_count": sum(
                cleaned.count(word)
                for word in [
                    "urgent", "verify", "verification", "account",
                    "password", "login", "click", "suspended",
                    "blocked", "security", "confirm", "update",
                    "bank", "payment", "invoice", "winner",
                    "prize", "refund", "limited", "alert"
                ]
            )
        }])

        numeric_features = self.scaler.transform(numeric_features).astype("float32")

        X = hstack(
            [word_features, char_features, numeric_features],
            format="csr",
            dtype="float32"
        )

        predicted = int(self.model.predict(X)[0])
        predicted_label = "phishing" if predicted == 1 else "legitimate"

        score = float(self.model.decision_function(X)[0])

        phishing_probability = 1.0 / (1.0 + __import__("math").exp(-score))

        probabilities = {
            "legitimate": round(1.0 - phishing_probability, 4),
            "phishing": round(phishing_probability, 4)
        }

        return MLResult(
            available=True,
            predicted_label=predicted_label,
            probabilities=probabilities,
            phishing_probability=round(phishing_probability, 4),
            message=""
        )