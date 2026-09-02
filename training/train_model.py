import pandas as pd
import os


# ==========================================
# DATASET FILES
# ==========================================

FILES = [
    "CEAS_08.csv",
    "Enron.csv",
    "Ling.csv",
    "phishing_email.csv",
    "SpamAssasin.csv"
]


# ==========================================
# LOAD AND STANDARDIZE DATASETS
# ==========================================

all_data = []


for file in FILES:

    print("\nLoading:", file)

    df = pd.read_csv(file)

    print("Original shape:", df.shape)
    print("Columns:", df.columns.tolist())

    # --------------------------------------
    # Case 1: text_combined column
    # --------------------------------------

    if "text_combined" in df.columns:

        data = pd.DataFrame()

        data["text"] = df["text_combined"].fillna("")

        data["label"] = df["label"]


    # --------------------------------------
    # Case 2: subject + body
    # --------------------------------------

    elif (
        "subject" in df.columns
        and "body" in df.columns
    ):

        data = pd.DataFrame()

        data["text"] = (
            df["subject"].fillna("")
            + " "
            + df["body"].fillna("")
        )

        data["label"] = df["label"]


    else:

        print("Skipping:", file)
        continue


    # --------------------------------------
    # Remove empty emails
    # --------------------------------------

    data = data[
        data["text"].str.strip() != ""
    ]


    # --------------------------------------
    # Keep only valid labels
    # --------------------------------------

    data = data[
        data["label"].isin([0, 1])
    ]


    print(
        "After processing:",
        data.shape
    )

    print(
        data["label"].value_counts()
    )


    all_data.append(data)


# ==========================================
# COMBINE DATASETS
# ==========================================

final_df = pd.concat(
    all_data,
    ignore_index=True
)


print("\n======================================")
print("COMBINED DATASET")
print("======================================")

print("Shape:", final_df.shape)

print("\nLabels:")
print(final_df["label"].value_counts())


# ==========================================
# REMOVE DUPLICATES
# ==========================================

final_df = final_df.drop_duplicates(
    subset=["text"]
)


print(
    "\nAfter removing duplicates:",
    final_df.shape
)


# ==========================================
# BALANCE DATASET
# ==========================================

class_0 = final_df[
    final_df["label"] == 0
]

class_1 = final_df[
    final_df["label"] == 1
]


print("\nBefore balancing:")
print("Legitimate:", len(class_0))
print("Phishing/Spam:", len(class_1))


# Use equal number from both classes

sample_size = min(
    len(class_0),
    len(class_1)
)


class_0 = class_0.sample(
    n=sample_size,
    random_state=42
)


class_1 = class_1.sample(
    n=sample_size,
    random_state=42
)


final_df = pd.concat(
    [
        class_0,
        class_1
    ],
    ignore_index=True
)


# Shuffle

final_df = final_df.sample(
    frac=1,
    random_state=42
).reset_index(drop=True)


# ==========================================
# FINAL CHECK
# ==========================================

print("\n======================================")
print("FINAL DATASET")
print("======================================")

print("Shape:", final_df.shape)

print(
    final_df["label"].value_counts()
)


# ==========================================
# SAVE
# ==========================================

final_df.to_csv(
    "training_dataset.csv",
    index=False
)


print(
    "\nSaved as training_dataset.csv"
)