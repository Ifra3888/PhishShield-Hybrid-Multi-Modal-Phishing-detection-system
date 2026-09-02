import pandas as pd
import os
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)


# ==========================================
# 1. LOAD TRAINING DATASET
# ==========================================

DATASET_PATH = "training_dataset.csv"

df = pd.read_csv(DATASET_PATH)

print("Dataset shape:", df.shape)


# ==========================================
# 2. CHECK DATA
# ==========================================

print("\nColumns:")
print(df.columns.tolist())

print("\nLabel distribution:")
print(df["label"].value_counts())


# ==========================================
# 3. HANDLE MISSING VALUES
# ==========================================

df["text"] = df["text"].fillna("")


# ==========================================
# 4. REMOVE EMPTY EMAILS
# ==========================================

df = df[
    df["text"].str.strip() != ""
]

print("\nDataset after cleaning:")
print(df.shape)


# ==========================================
# 5. INPUT AND OUTPUT
# ==========================================

X = df["text"]
y = df["label"]


# ==========================================
# 6. TRAIN / TEST SPLIT
# ==========================================

X_train, X_test, y_train, y_test = train_test_split(

    X,
    y,

    test_size=0.20,

    random_state=42,

    stratify=y
)


print("\nTraining samples:", len(X_train))
print("Testing samples:", len(X_test))


# ==========================================
# 7. TF-IDF
# ==========================================

vectorizer = TfidfVectorizer(

    max_features=20000,

    stop_words="english",

    ngram_range=(1, 2)
)


print("\nCreating TF-IDF features...")

X_train_tfidf = vectorizer.fit_transform(
    X_train
)

X_test_tfidf = vectorizer.transform(
    X_test
)


print(
    "TF-IDF training shape:",
    X_train_tfidf.shape
)


# ==========================================
# 8. TRAIN LOGISTIC REGRESSION
# ==========================================

print("\nTraining Logistic Regression...")


model = LogisticRegression(

    max_iter=1000
)


model.fit(

    X_train_tfidf,

    y_train
)


print("Model training completed!")


# ==========================================
# 9. PREDICTION
# ==========================================

y_pred = model.predict(

    X_test_tfidf
)


# ==========================================
# 10. EVALUATION
# ==========================================

accuracy = accuracy_score(

    y_test,

    y_pred
)


print("\n======================================")
print("MODEL EVALUATION")
print("======================================")


print(
    "Accuracy:",
    round(accuracy, 4)
)


print("\nClassification Report:")

print(
    classification_report(
        y_test,
        y_pred
    )
)


print("\nConfusion Matrix:")

print(
    confusion_matrix(
        y_test,
        y_pred
    )
)


# ==========================================
# 11. SAVE MODEL
# ==========================================

os.makedirs(
    "model",
    exist_ok=True
)


joblib.dump(

    model,

    "model/phishing_model.pkl"
)


joblib.dump(

    vectorizer,

    "model/tfidf_vectorizer.pkl"
)


print("\n======================================")
print("MODEL SAVED")
print("======================================")


print(
    "Model:",
    "model/phishing_model.pkl"
)


print(
    "Vectorizer:",
    "model/tfidf_vectorizer.pkl"
)