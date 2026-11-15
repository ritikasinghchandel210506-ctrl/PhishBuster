import os
import re
import joblib
import pandas as pd

from scipy.sparse import hstack


BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

PREDICTION_PATH = os.path.join(
    BASE_DIR,
    "data",
    "predictions.csv"
)

MODEL_DIR = os.path.join(
    BASE_DIR,
    "ml",
    "models"
)

MODEL_PATH = os.path.join(
    MODEL_DIR,
    "svm_model.pkl"
)

WORD_PATH = os.path.join(
    MODEL_DIR,
    "word_vectorizer.pkl"
)

CHAR_PATH = os.path.join(
    MODEL_DIR,
    "char_vectorizer.pkl"
)

SCALER_PATH = os.path.join(
    MODEL_DIR,
    "scaler.pkl"
)


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

    text = re.sub(
        r"http\S+|www\S+",
        " URL ",
        text
    )

    text = re.sub(
        r"\S+@\S+",
        " EMAIL ",
        text
    )

    text = re.sub(
        r"\d+",
        " NUMBER ",
        text
    )

    text = re.sub(
        r"[^a-zA-Z\s]",
        " ",
        text
    )

    text = re.sub(
        r"\s+",
        " ",
        text
    )

    return text.strip()


def load_model():

    required_files = [
        MODEL_PATH,
        WORD_PATH,
        CHAR_PATH,
        SCALER_PATH
    ]

    missing_files = [
        file
        for file in required_files
        if not os.path.exists(file)
    ]

    if missing_files:

        raise FileNotFoundError(
            "\nModel files are missing.\n"
            "Run this command first:\n\n"
            "python ml/train_model.py\n\n"
            f"Missing files: {missing_files}"
        )

    svm_model = joblib.load(
        MODEL_PATH
    )

    word_vectorizer = joblib.load(
        WORD_PATH
    )

    char_vectorizer = joblib.load(
        CHAR_PATH
    )

    scaler = joblib.load(
        SCALER_PATH
    )

    return (
        svm_model,
        word_vectorizer,
        char_vectorizer,
        scaler
    )


def extract_urls(body):

    return re.findall(
        r"https?://\S+|www\.\S+",
        str(body or "")
    )


def extract_features(
    subject="",
    body=""
):

    subject = str(
        subject or ""
    )

    body = str(
        body or ""
    )

    urls_found = extract_urls(
        body
    )

    url_text = " ".join(
        urls_found
    )

    subject_clean = clean_text(
        subject
    )

    body_clean = clean_text(
        body
    )

    urls_clean = clean_text(
        url_text
    )

    content_text = (
        subject_clean
        + " "
        + body_clean
        + " "
        + urls_clean
    )

    url_count = len(
        urls_found
    )

    url_length = len(
        url_text
    )

    numeric_features = pd.DataFrame(
        [{
            "body_length": len(body),

            "subject_length": len(subject),

            "url_length": url_length,

            "word_count": len(
                body.split()
            ),

            "url_count": url_count,

            "has_url": int(
                url_count > 0
            ),

            "exclamation_count": body.count(
                "!"
            ),

            "question_count": body.count(
                "?"
            ),

            "uppercase_count": sum(
                char.isupper()
                for char in body
            ),

            "phishing_keyword_count": sum(
                content_text.count(word)
                for word in PHISHING_WORDS
            )
        }]
    )

    return (
        content_text,
        numeric_features
    )


def save_prediction(
    sender,
    receiver,
    subject,
    body,
    prediction
):

    os.makedirs(
        os.path.dirname(
            PREDICTION_PATH
        ),
        exist_ok=True
    )

    text = (
        "Sender: "
        + str(sender)
        + "\n"
        + "Receiver: "
        + str(receiver)
        + "\n"
        + "Subject: "
        + str(subject)
        + "\n"
        + "Body: "
        + str(body)
    )

    label = (
        "phishing"
        if prediction == 1
        else "legitimate"
    )

    new_row = pd.DataFrame(
        [{
            "text": text,
            "label": label
        }]
    )

    if os.path.exists(
        PREDICTION_PATH
    ):

        old_data = pd.read_csv(
            PREDICTION_PATH
        )

        old_data = old_data[
            ["text", "label"]
        ]

        new_row = pd.concat(
            [
                old_data,
                new_row
            ],
            ignore_index=True
        )

    new_row.to_csv(
        PREDICTION_PATH,
        index=False
    )


def predict_email(
    sender="",
    receiver="",
    subject="",
    body=""
):

    (
        svm_model,
        word_vectorizer,
        char_vectorizer,
        scaler
    ) = load_model()

    (
        content_text,
        numeric_features
    ) = extract_features(
        subject=subject,
        body=body
    )

    word_features = word_vectorizer.transform(
        [content_text]
    )

    char_features = char_vectorizer.transform(
        [content_text]
    )

    numeric_features_scaled = (
        scaler.transform(
            numeric_features
        )
        .astype("float32")
    )

    final_features = hstack(
        [
            word_features,
            char_features,
            numeric_features_scaled
        ],
        format="csr",
        dtype="float32"
    )

    prediction = int(
        svm_model.predict(
            final_features
        )[0]
    )

    score = float(
        svm_model.decision_function(
            final_features
        )[0]
    )

    label = (
        "phishing"
        if prediction == 1
        else "legitimate"
    )

    save_prediction(
        sender=sender,
        receiver=receiver,
        subject=subject,
        body=body,
        prediction=prediction
    )

    return {
        "prediction": prediction,
        "label": label,
        "score": score
    }


def analyze_email(
    sender="",
    receiver="",
    subject="",
    body=""
):

    result = predict_email(
        sender=sender,
        receiver=receiver,
        subject=subject,
        body=body
    )

    if result["prediction"] == 1:
        message = (
            "This email is classified as phishing."
        )
    else:
        message = (
            "This email is classified as legitimate."
        )

    return {
        "label": result["label"],
        "prediction": result["prediction"],
        "score": result["score"],
        "message": message
    }


if __name__ == "__main__":

    result = analyze_email(
        sender="security@example.com",
        receiver="user@example.com",
        subject="Urgent: Verify your account",
        body=(
            "Your account has been suspended. "
            "Click here immediately to verify "
            "your password."
        )
    )

    print("\nPrediction Result:")
    print(result)

    print(
        f"\nPredictions saved to:\n"
        f"{PREDICTION_PATH}"
    )