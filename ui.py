import streamlit as st
import requests
import validators

st.title("PishShield Phishing Detector")

text = st.text_area("Enter Message")
url = st.text_input("Enter URL")
file = st.file_uploader("Upload QR Code")

if st.button("Scan"):

    # ✅ Edge Case 1: Empty input
    if not text and not url and not file:
        st.warning("Please enter at least one input!")
        st.stop()

    # ✅ Edge Case 2: Invalid URL
    if url:
        if not url.startswith("http"):
            url = "http://" + url

        if not validators.url(url):
            st.warning("URL format looks unusual, but still analyzing...")
    try:
        files = {"file": file} if file else {}

        response = requests.post(
            "http://127.0.0.1:8000/scan",
            data={"text": text, "url": url},
            files=files
        )

        if response.status_code == 200:
            result = response.json()

            # ✅ Clean UI output
            st.subheader(f"Result: {result['result']}")
            st.write(f"Confidence: {result['confidence']}")

            if result["reasons"]:
                st.write("Reasons:")
                for r in result["reasons"]:
                    st.write(f"- {r}")
        else:
            st.error(f"Server Error: {response.text}")

    except Exception as e:
        st.error(f"Request Failed: {e}")