import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier

from sklearn.metrics import (
    confusion_matrix,
    classification_report,
    accuracy_score,
    roc_auc_score
)

from joblib import dump

from url_model import extract_features


# ============================================================
# 1. LOAD MASTER DATASET
# ============================================================

print("=" * 60)
print("PHISHSHIELD URL MODEL TRAINING")
print("=" * 60)

print("\nLoading phishshield_master.csv...")

df = pd.read_csv("phishshield_master.csv")

print("Dataset shape:", df.shape)


# ============================================================
# 2. CHECK DATA
# ============================================================

print("\nLabel distribution:")

print(df["Label"].value_counts().sort_index())

print("\nMissing values:")

print(
    df[["URL", "Label"]].isnull().sum()
)


# ============================================================
# 3. PREPARE URLS AND LABELS
# ============================================================

urls = df["URL"].astype(str)

y = df["Label"].astype(int)


# ============================================================
# 4. TRAIN / TEST SPLIT
# ============================================================

print("\nSplitting dataset...")

X_train_urls, X_test_urls, y_train, y_test = train_test_split(
    urls,
    y,
    test_size=0.20,
    stratify=y,
    random_state=42
)

print("Training samples:", len(X_train_urls))
print("Testing samples:", len(X_test_urls))


# ============================================================
# 5. FEATURE EXTRACTION
# ============================================================

print("\nExtracting training features...")

X_train = X_train_urls.apply(
    extract_features
).tolist()

print("Training feature extraction complete.")

print("\nExtracting testing features...")

X_test = X_test_urls.apply(
    extract_features
).tolist()

print("Testing feature extraction complete.")

print("\nNumber of features:", len(X_train[0]))


# ============================================================
# 6. CREATE RANDOM FOREST
# ============================================================

print("\nCreating Random Forest...")

model = RandomForestClassifier(
    n_estimators=300,
    max_depth=22,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1
)


# ============================================================
# 7. TRAIN MODEL
# ============================================================

print("\nTraining model...")

model.fit(
    X_train,
    y_train
)

print("Training completed!")


# ============================================================
# 8. PREDICTIONS
# ============================================================

print("\nGenerating predictions...")

probs = model.predict_proba(X_test)[:, 1]

y_pred = (
    probs >= 0.5
).astype(int)


# ============================================================
# 9. EVALUATION
# ============================================================

accuracy = accuracy_score(
    y_test,
    y_pred
)

roc_auc = roc_auc_score(
    y_test,
    probs
)

cm = confusion_matrix(
    y_test,
    y_pred
)

report = classification_report(
    y_test,
    y_pred,
    target_names=[
        "Legitimate",
        "Phishing"
    ],
    digits=4
)


print("\n")
print("=" * 60)
print("PHISHSHIELD URL MODEL RESULTS")
print("=" * 60)

print(
    f"\nAccuracy: {accuracy:.4f}"
)

print(
    f"ROC-AUC: {roc_auc:.4f}"
)

print("\nConfusion Matrix:")

print(cm)

print("\nClassification Report:")

print(report)


# ============================================================
# 10. SAVE NEW MODEL
# ============================================================

print("\nSaving new model...")

dump(
    model,
    "url_model.pkl"
)

print("\nNew model saved as:")
print("url_model.pkl")

print("\nOld model preserved as:")
print("url_model_old.pkl")

print("\nTraining finished successfully.")