def predict_text(text):
    text = text.lower()
    
    keywords = [
        "urgent", "verify now", "account suspended",
        "click below", "login immediately", "security alert"
    ]
    
    score = sum(1 for word in keywords if word in text)
    
    return min(score * 0.2, 1.0)