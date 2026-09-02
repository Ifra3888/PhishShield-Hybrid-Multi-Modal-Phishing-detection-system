from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
import joblib

from rules import (
    detect_keywords,
    extract_urls,
    detect_suspicious_urls
)


# ==========================================
# CREATE FASTAPI APPLICATION
# ==========================================

app = FastAPI(
    title="Email Phishing Detection API",
    description="Hybrid ML and rule-based email phishing detection system",
    version="1.0"
)


# ==========================================
# LOAD MODEL
# ==========================================

model = joblib.load(
    "model/phishing_model.pkl"
)

vectorizer = joblib.load(
    "model/tfidf_vectorizer.pkl"
)


# ==========================================
# SERVE FRONTEND FILES
# ==========================================

app.mount(
    "/static",
    StaticFiles(directory="static"),
    name="static"
)


# ==========================================
# EMAIL INPUT
# ==========================================

class EmailRequest(BaseModel):

    subject: str

    body: str


# ==========================================
# HOME PAGE
# ==========================================

@app.get("/")
def home():

    return FileResponse(
        "static/index.html"
    )


# ==========================================
# PREDICT EMAIL
# ==========================================

@app.post("/predict")
def predict_email(email: EmailRequest):

    # --------------------------------------
    # 1. Combine subject + body
    # --------------------------------------

    text = (
        email.subject +
        " " +
        email.body
    )


    # --------------------------------------
    # 2. ML PREDICTION
    # --------------------------------------

    text_vector = vectorizer.transform(
        [text]
    )


    prediction = model.predict(
        text_vector
    )[0]


    probabilities = model.predict_proba(
        text_vector
    )[0]


    confidence = max(probabilities)


    # --------------------------------------
    # 3. KEYWORD DETECTION
    # --------------------------------------

    keyword_hits = detect_keywords(
        text
    )


    # --------------------------------------
    # 4. URL DETECTION
    # --------------------------------------

    urls = extract_urls(
        text
    )


    suspicious_urls = detect_suspicious_urls(
        urls
    )


    # --------------------------------------
    # 5. RULE SCORE
    # --------------------------------------

    rule_score = 0

    rule_score += (
        len(keyword_hits) * 10
    )

    rule_score += (
        len(suspicious_urls) * 25
    )

    rule_score = min(
        rule_score,
        100
    )


    # --------------------------------------
    # 6. ML RESULT
    # --------------------------------------

    if prediction == 1:

        ml_result = "phishing"

    else:

        ml_result = "legitimate"


    # --------------------------------------
    # 7. FINAL VERDICT
    # --------------------------------------

    if (
        prediction == 1
        or rule_score >= 40
    ):

        final_verdict = "phishing"

    else:

        final_verdict = "legitimate"


    # --------------------------------------
    # 8. RISK LEVEL
    # --------------------------------------

    if (
        final_verdict == "phishing"
        and (
            confidence >= 0.80
            or rule_score >= 60
        )
    ):

        risk_level = "HIGH"

    elif (
        final_verdict == "phishing"
        or confidence >= 0.60
        or rule_score >= 20
    ):

        risk_level = "MEDIUM"

    else:

        risk_level = "LOW"


    # --------------------------------------
    # 9. RETURN RESULT
    # --------------------------------------

    return {

        "prediction": final_verdict,

        "ml_prediction": ml_result,

        "ml_confidence": round(
            float(confidence),
            4
        ),

        "risk_level": risk_level,

        "detected_keywords": keyword_hits,

        "urls_found": urls,

        "suspicious_urls": suspicious_urls,

        "rule_score": rule_score
    }