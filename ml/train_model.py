import os
import re
import joblib
import pandas as pd

from scipy.sparse import hstack
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.svm import LinearSVC
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATA_PATH = os.path.join(BASE_DIR, "data", "phishing.csv")

MODEL_DIR = os.path.join(BASE_DIR, "ml", "models")

MODEL_PATH = os.path.join(MODEL_DIR, "svm_model.pkl")
WORD_PATH = os.path.join(MODEL_DIR, "word_vectorizer.pkl")
CHAR_PATH = os.path.join(MODEL_DIR, "char_vectorizer.pkl")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.pkl")


PHISHING_WORDS = [
    "urgent",
    "verify",
    "verification",
    "account",
    "password",
    "login",
    "click",
    "suspended",
    "blocked",
    "security",
    "confirm",
    "update",
    "bank",
    "payment",
    "invoice",
    "winner",
    "prize",
    "refund",
    "limited",
    "alert"
]


def clean_text(text):
    text = str(text or "").lower()

    text = re.sub(r"http\S+|www\S+", " URL ", text)
    text = re.sub(r"\S+@\S+", " EMAIL ", text)
    text = re.sub(r"\d+", " NUMBER ", text)
    text = re.sub(r"[^a-zA-Z\s]", " ", text)
    text = re.sub(r"\s+", " ", text)

    return text.strip()


def prepare_dataset(df):

    df = df.copy()

    required_columns = [
        "subject",
        "receiver",
        "sender",
        "label",
        "body",
        "urls",
        "date"
    ]

    missing_columns = [
        col for col in required_columns
        if col not in df.columns
    ]

    if missing_columns:
        raise ValueError(
            f"Missing columns: {missing_columns}"
        )

    df = df[df["label"].isin([0, 1])].copy()

    for col in [
        "subject",
        "receiver",
        "sender",
        "body",
        "urls"
    ]:
        df[col] = df[col].fillna("").astype(str)

    df["subject_clean"] = df["subject"].apply(clean_text)
    df["body_clean"] = df["body"].apply(clean_text)
    df["urls_clean"] = df["urls"].apply(clean_text)

    df["content_text"] = (
        df["subject_clean"]
        + " "
        + df["body_clean"]
        + " "
        + df["urls_clean"]
    )

    df = df.drop_duplicates(
        subset=["content_text"]
    ).reset_index(drop=True)

    df["body_length"] = df["body"].str.len()

    df["subject_length"] = df["subject"].str.len()

    df["url_length"] = df["urls"].str.len()

    df["word_count"] = (
        df["body"]
        .str.split()
        .str.len()
    )

    df["url_count"] = df["urls"].apply(
        lambda x: len(
            re.findall(
                r"https?://|www\.",
                x.lower()
            )
        )
    )

    df["has_url"] = (
        df["url_count"] > 0
    ).astype(int)

    df["exclamation_count"] = (
        df["body"].str.count("!")
    )

    df["question_count"] = (
        df["body"].str.count(r"\?")
    )

    df["uppercase_count"] = df["body"].apply(
        lambda x: sum(
            char.isupper()
            for char in x
        )
    )

    df["phishing_keyword_count"] = (
        df["content_text"].apply(
            lambda x: sum(
                x.count(word)
                for word in PHISHING_WORDS
            )
        )
    )

    return df


def get_numeric_features(df):

    columns = [
        "body_length",
        "subject_length",
        "url_length",
        "word_count",
        "url_count",
        "has_url",
        "exclamation_count",
        "question_count",
        "uppercase_count",
        "phishing_keyword_count"
    ]

    return df[columns]


def train_model():

    print("\nLoading dataset...")

    df = pd.read_csv(DATA_PATH)

    print(
        f"Original dataset size: {len(df)}"
    )

    df = prepare_dataset(df)

    print(
        f"Dataset after cleaning: {len(df)}"
    )

    print("\nClass distribution:")
    print(
        df["label"]
        .value_counts()
        .sort_index()
    )

    X_text = df["content_text"]

    X_numeric = get_numeric_features(df)

    y = df["label"].astype(int)

    (
        X_train_text,
        X_test_text,
        X_train_num,
        X_test_num,
        y_train,
        y_test
    ) = train_test_split(
        X_text,
        X_numeric,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y
    )

    print(
        f"\nTraining samples: {len(X_train_text)}"
    )

    print(
        f"Testing samples: {len(X_test_text)}"
    )

    print("\nCreating word TF-IDF...")

    word_vectorizer = TfidfVectorizer(
        max_features=20000,
        ngram_range=(1, 2),
        min_df=3,
        max_df=0.95,
        sublinear_tf=True,
        dtype="float32"
    )

    X_train_word = word_vectorizer.fit_transform(
        X_train_text
    )

    X_test_word = word_vectorizer.transform(
        X_test_text
    )

    print(
        f"Word features: {X_train_word.shape}"
    )

    print("\nCreating character TF-IDF...")

    char_vectorizer = TfidfVectorizer(
        analyzer="char",
        ngram_range=(3, 5),
        max_features=10000,
        min_df=3,
        sublinear_tf=True,
        dtype="float32"
    )

    X_train_char = char_vectorizer.fit_transform(
        X_train_text
    )

    X_test_char = char_vectorizer.transform(
        X_test_text
    )

    print(
        f"Character features: {X_train_char.shape}"
    )

    print("\nScaling numeric features...")

    scaler = StandardScaler()

    X_train_num_scaled = (
        scaler.fit_transform(X_train_num)
        .astype("float32")
    )

    X_test_num_scaled = (
        scaler.transform(X_test_num)
        .astype("float32")
    )

    print("\nCombining features...")

    X_train = hstack(
        [
            X_train_word,
            X_train_char,
            X_train_num_scaled
        ],
        format="csr",
        dtype="float32"
    )

    X_test = hstack(
        [
            X_test_word,
            X_test_char,
            X_test_num_scaled
        ],
        format="csr",
        dtype="float32"
    )

    print(
        f"Final training shape: {X_train.shape}"
    )

    print(
        f"Final testing shape: {X_test.shape}"
    )

    print("\nTraining Linear SVM...")

    svm_model = LinearSVC(
        C=1.0,
        class_weight="balanced"
    )

    svm_model.fit(
        X_train,
        y_train
    )

    print("\nEvaluating model...")

    y_pred = svm_model.predict(
        X_test
    )

    accuracy = accuracy_score(
        y_test,
        y_pred
    )

    print(
        f"\nTest Accuracy: {accuracy * 100:.2f}%"
    )

    print("\nClassification Report:")

    print(
        classification_report(
            y_test,
            y_pred,
            target_names=[
                "Legitimate",
                "Phishing"
            ]
        )
    )

    print("Confusion Matrix:")

    print(
        confusion_matrix(
            y_test,
            y_pred
        )
    )

    os.makedirs(
        MODEL_DIR,
        exist_ok=True
    )

    print("\nSaving model files...")

    joblib.dump(
        svm_model,
        MODEL_PATH
    )

    joblib.dump(
        word_vectorizer,
        WORD_PATH
    )

    joblib.dump(
        char_vectorizer,
        CHAR_PATH
    )

    joblib.dump(
        scaler,
        SCALER_PATH
    )

    print("\nModel saved successfully.")

    print(
        f"Model: {MODEL_PATH}"
    )

    print(
        f"Word vectorizer: {WORD_PATH}"
    )

    print(
        f"Char vectorizer: {CHAR_PATH}"
    )

    print(
        f"Scaler: {SCALER_PATH}"
    )

    return accuracy


if __name__ == "__main__":
    train_model()