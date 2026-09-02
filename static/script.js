async function analyzeEmail() {

    const subject =
        document.getElementById("subject").value;

    const body =
        document.getElementById("body").value;


    // ======================================
    // VALIDATION
    // ======================================

    if (
        subject.trim() === "" &&
        body.trim() === ""
    ) {

        alert(
            "Please enter an email subject or body."
        );

        return;
    }


    // ======================================
    // SHOW LOADING
    // ======================================

    document
        .getElementById("loading")
        .classList
        .remove("hidden");


    document
        .getElementById("result")
        .classList
        .add("hidden");


    try {

        // ==================================
        // SEND REQUEST TO FASTAPI
        // ==================================

        const response = await fetch(
            "/predict",
            {

                method: "POST",

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify({

                    subject: subject,

                    body: body

                })

            }
        );


        // ==================================
        // GET RESPONSE
        // ==================================

        const data =
            await response.json();


        // ==================================
        // DISPLAY RESULT
        // ==================================

        displayResult(data);


    }

    catch (error) {

        console.error(error);

        alert(
            "Something went wrong while analyzing the email."
        );

    }


    // ======================================
    // HIDE LOADING
    // ======================================

    document
        .getElementById("loading")
        .classList
        .add("hidden");
}



function displayResult(data) {


    // ======================================
    // RESULT SECTION
    // ======================================

    document
        .getElementById("result")
        .classList
        .remove("hidden");


    // ======================================
    // VERDICT
    // ======================================

    const verdict =
        document.getElementById("verdict");


    if (
        data.prediction === "phishing"
    ) {

        verdict.innerHTML =
            "⚠️ PHISHING EMAIL DETECTED";

    }

    else {

        verdict.innerHTML =
            "✅ EMAIL APPEARS LEGITIMATE";

    }


    // ======================================
    // CONFIDENCE
    // ======================================

    document
        .getElementById("confidence")
        .innerText =
        (
            data.ml_confidence * 100
        ).toFixed(2) + "%";


    // ======================================
    // RISK
    // ======================================

    document
        .getElementById("risk")
        .innerText =
        data.risk_level;


    // ======================================
    // RULE SCORE
    // ======================================

    document
        .getElementById("ruleScore")
        .innerText =
        data.rule_score + "/100";


    // ======================================
    // KEYWORDS
    // ======================================

    const keywords =
        document.getElementById(
            "keywords"
        );


    if (
        data.detected_keywords.length > 0
    ) {

        keywords.innerHTML =
            data.detected_keywords
                .map(
                    keyword =>
                        `<span>${keyword}</span>`
                )
                .join(", ");

    }

    else {

        keywords.innerText =
            "None detected";

    }


    // ======================================
    // URLS
    // ======================================

    const urls =
        document.getElementById(
            "urls"
        );


    if (
        data.urls_found.length > 0
    ) {

        urls.innerHTML =
            data.urls_found
                .map(
                    url =>
                        `<div>${url}</div>`
                )
                .join("");

    }

    else {

        urls.innerText =
            "No URLs found";

    }


    // ======================================
    // SUSPICIOUS URLS
    // ======================================

    const suspicious =
        document.getElementById(
            "suspiciousUrls"
        );


    if (
        data.suspicious_urls.length > 0
    ) {

        suspicious.innerHTML =
            data.suspicious_urls
                .map(
                    url =>
                        `<div>${url}</div>`
                )
                .join("");

    }

    else {

        suspicious.innerText =
            "No suspicious URLs detected";

    }

}