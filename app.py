from fastapi import FastAPI, UploadFile, File, Form
from url_model import predict_url
from qr_scanner import scan_qr
import shutil
import os

app = FastAPI()

@app.post("/scan")
async def scan(
    text: str = Form(""),   # keep but ignore
    url: str = Form(""),
    file: UploadFile = File(None)
):
    try:
        print("URL:", url)

        reasons = []
        url_score = 0.0
        qr_score = 0.0

        # 🔹 URL Detection
        if url:
            try:
                if not url.startswith("http"):
                    url = "http://" + url

                url_score = predict_url(url)

                if url_score > 0.5:
                    reasons.append("Suspicious URL pattern")
            except Exception as e:
                reasons.append("URL analysis failed")

        # 🔹 QR Detection
        if file:
            try:
                file_path = f"temp_{file.filename}"

                with open(file_path, "wb") as buffer:
                    shutil.copyfileobj(file.file, buffer)

                qr_data = scan_qr(file_path)

                os.remove(file_path)

                if qr_data:
                    if not qr_data.startswith("http"):
                        qr_data = "http://" + qr_data

                    qr_score = predict_url(qr_data)

                    if qr_score > 0.5:
                        reasons.append(f"QR suspicious URL: {qr_data}")
                else:
                    reasons.append("No QR code detected")

            except Exception as e:
                reasons.append("QR processing failed")

        # 🔥 FINAL SCORE (NO TEXT)
        final_score = max(url_score, qr_score)

        # 🔹 Result
        if final_score > 0.7:
            result = "Phishing"
        elif final_score > 0.4:
            result = "Suspicious"
        else:
            result = "Safe"

        return {
            "result": result,
            "confidence": round(final_score, 2),
            "reasons": reasons
        }

    except Exception as e:
        return {
            "result": "Error",
            "confidence": 0,
            "reasons": [f"Internal server error: {str(e)}"]
        }