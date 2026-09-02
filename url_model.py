import joblib


# ============================================================
# FEATURE EXTRACTION
# ============================================================

def extract_features(url):
    """
    Extract the 17 URL-based features used by PhishShield.
    """

    url = str(url)
    url_lower = url.lower()

    return [
        # 1. URL length
        len(url),

        # 2. Number of dots
        url.count('.'),

        # 3. HTTPS flag
        int(url.startswith("https")),

        # 4. @ symbol
        int("@" in url),

        # 5. Hyphen
        int("-" in url),

        # 6. Slash count
        url.count('/'),

        # 7. Suspicious keywords
        sum(
            word in url_lower
            for word in [
                "login",
                "verify",
                "bank",
                "secure",
                "account"
            ]
        ),

        # 8. HTTP occurrence
        int("http" in url_lower),

        # 9. Double slash after protocol
        int("//" in url[7:]),

        # 10. Equals sign count
        url.count('='),

        # 11. Question mark count
        url.count('?'),

        # 12. Percent sign count
        url.count('%'),

        # 13. Contains a digit
        int(any(c.isdigit() for c in url)),

        # 14. More than 2 hyphens
        int(url.count('-') > 2),

        # 15. More than 5 dots
        int(url.count('.') > 5),

        # 16. URL longer than 100 characters
        int(len(url) > 100),

        # 17. Promotional/suspicious keywords
        int(
            any(
                word in url_lower
                for word in [
                    "free",
                    "bonus",
                    "win",
                    "prize"
                ]
            )
        )
    ]


# ============================================================
# MODEL LOADING
# ============================================================

_model = None


def get_model():
    """
    Load url_model.pkl only when prediction is requested.
    """

    global _model

    if _model is None:
        _model = joblib.load("url_model.pkl")

    return _model


# ============================================================
# URL PREDICTION
# ============================================================

def predict_url(url):
    """
    Return phishing probability between 0 and 1.
    """

    features = extract_features(url)

    model = get_model()

    probability = model.predict_proba([features])[0][1]

    return probability