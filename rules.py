import re
from urllib.parse import urlparse


# ==========================================
# HIGH RISK PHRASES
# ==========================================

HIGH_RISK_PHRASES = [
    "send your password",
    "provide your password",
    "share your password",
    "enter your password",
    "verify your password",
    "confirm your password",
    "send otp",
    "share otp",
    "provide otp",
    "click here immediately",
    "account will be suspended",
]


# ==========================================
# MEDIUM RISK PHRASES
# ==========================================

MEDIUM_RISK_PHRASES = [
    "account suspended",
    "verify your identity",
    "confirm your identity",
    "urgent",
    "limited time",
    "click here",
    "security alert",
]


# ==========================================
# LOW RISK WORDS
# These words alone should NOT make an
# email phishing.
# ==========================================

LOW_RISK_WORDS = [
    "password",
    "login",
    "account",
    "sign in",
]


# ==========================================
# JOB / RECRUITMENT PHRASES
# ==========================================

JOB_RISK_PHRASES = [
    "first come, first served",
    "limited openings",
    "apply now",
    "internship",
    "stipend",
    "ctc",
    "lpa",
]


# ==========================================
# SUSPICIOUS DOMAINS
# ==========================================

SUSPICIOUS_DOMAINS = [
    "bit.ly",
    "tinyurl.com",
    "free-login",
    "secure-account",
    "foundjobs.in",
]


# ==========================================
# OFFICIAL COMPANY DOMAINS
# ==========================================

OFFICIAL_DOMAINS = {
    "tcs": [
        "tcs.com"
    ],

    "microsoft": [
        "microsoft.com"
    ],

    "google": [
        "google.com"
    ],

    "amazon": [
        "amazon.com"
    ]
}


# ==========================================
# DETECT RISK PHRASES
# ==========================================

def detect_keywords(text):

    findings = []

    text_lower = text.lower()

    # HIGH RISK
    for phrase in HIGH_RISK_PHRASES:

        if phrase in text_lower:

            findings.append(phrase)

    # MEDIUM RISK
    for phrase in MEDIUM_RISK_PHRASES:

        if phrase in text_lower:

            findings.append(phrase)

    # JOB / RECRUITMENT
    for phrase in JOB_RISK_PHRASES:

        if phrase in text_lower:

            findings.append(phrase)

    return list(dict.fromkeys(findings))


# ==========================================
# EXTRACT ALL URLs
# ==========================================

def extract_urls(text):

    url_pattern = r'https?://[^\s\]\)<>"]+'

    urls = re.findall(url_pattern, text)

    all_urls = []

    for url in urls:

        # Add original URL
        all_urls.append(url)

        # Check URL fragment (#)
        parsed = urlparse(url)

        fragment_urls = re.findall(
            r'https?://[^\s\]\)<>"]+',
            parsed.fragment
        )

        for inner_url in fragment_urls:

            all_urls.append(inner_url)

    # Remove duplicates
    return list(dict.fromkeys(all_urls))


# ==========================================
# EXTRACT DOMAINS
# ==========================================

def extract_domains(urls):

    domains = []

    for url in urls:

        try:

            parsed = urlparse(url)

            domain = parsed.netloc.lower()

            if domain:
                domains.append(domain)

        except Exception:
            pass

    return list(dict.fromkeys(domains))


# ==========================================
# DETECT SUSPICIOUS URLs
# ==========================================

def detect_suspicious_urls(urls):

    suspicious = []

    for url in urls:

        url_lower = url.lower()

        for domain in SUSPICIOUS_DOMAINS:

            if domain in url_lower:

                suspicious.append(url)

                break

    return list(dict.fromkeys(suspicious))


# ==========================================
# CHECK COMPANY DOMAIN
# ==========================================

def check_company_domain(text, domains):

    text_lower = text.lower()

    score = 0

    reasons = []

    for company, official_domains in OFFICIAL_DOMAINS.items():

        # Check whether company is mentioned
        if company in text_lower:

            valid_domain = False

            for domain in domains:

                for official in official_domains:

                    if (
                        domain == official
                        or domain.endswith("." + official)
                    ):
                        valid_domain = True

            # Company mentioned but official domain absent
            if not valid_domain:

                score += 30

                reasons.append(
                    f"Email mentions {company.upper()} "
                    f"but no official {official_domains[0]} "
                    f"domain was found"
                )

    return score, reasons


# ==========================================
# DETECT JOB-RELATED RISK
# ==========================================

def detect_job_risk(text):

    text_lower = text.lower()

    score = 0

    reasons = []

    # High stipend claim
    if "₹40,000" in text or "40000" in text:

        score += 10

        reasons.append(
            "High stipend claim detected"
        )

    # High CTC claim
    if (
        "12–15 lpa" in text_lower
        or "12-15 lpa" in text_lower
        or "12 – 15 lpa" in text_lower
    ):

        score += 10

        reasons.append(
            "High salary/CTC claim detected"
        )

    # Urgency
    if "first come, first served" in text_lower:

        score += 10

        reasons.append(
            "Urgency language detected"
        )

    # Missing application link
    if "[insert application link]" in text_lower:

        score += 10

        reasons.append(
            "Application link appears to be missing"
        )

    return score, reasons


# ==========================================
# CALCULATE KEYWORD SCORE
# ==========================================

def calculate_keyword_score(text):

    text_lower = text.lower()

    score = 0

    reasons = []

    # High-risk phrases
    for phrase in HIGH_RISK_PHRASES:

        if phrase in text_lower:

            score += 15

            reasons.append(
                f"High-risk phrase detected: {phrase}"
            )

    # Medium-risk phrases
    for phrase in MEDIUM_RISK_PHRASES:

        if phrase in text_lower:

            score += 5

            reasons.append(
                f"Medium-risk phrase detected: {phrase}"
            )

    # Job phrases
    for phrase in JOB_RISK_PHRASES:

        if phrase in text_lower:

            score += 3

            reasons.append(
                f"Recruitment-related phrase detected: {phrase}"
            )

    return min(score, 30), reasons


# ==========================================
# COMPLETE RULE ANALYSIS
# ==========================================

def analyze_rules(text):

    total_score = 0

    reasons = []

    # --------------------------------------
    # 1. Keywords
    # --------------------------------------

    keywords = detect_keywords(text)

    keyword_score, keyword_reasons = calculate_keyword_score(text)

    total_score += keyword_score

    reasons.extend(keyword_reasons)


    # --------------------------------------
    # 2. URLs
    # --------------------------------------

    urls = extract_urls(text)

    domains = extract_domains(urls)

    suspicious_urls = detect_suspicious_urls(urls)

    if suspicious_urls:

        total_score += 20

        reasons.append(
            "Suspicious URL/domain detected"
        )


    # --------------------------------------
    # 3. Company/domain mismatch
    # --------------------------------------

    company_score, company_reasons = check_company_domain(
        text,
        domains
    )

    total_score += company_score

    reasons.extend(company_reasons)


    # --------------------------------------
    # 4. Job-related risk
    # --------------------------------------

    job_score, job_reasons = detect_job_risk(text)

    total_score += job_score

    reasons.extend(job_reasons)


    # --------------------------------------
    # Maximum score = 100
    # --------------------------------------

    total_score = min(total_score, 100)


    # --------------------------------------
    # Risk level
    # --------------------------------------

    if total_score <= 20:

        risk_level = "LOW"

    elif total_score <= 50:

        risk_level = "MEDIUM"

    else:

        risk_level = "HIGH"


    return {

        "score": total_score,

        "risk_level": risk_level,

        "keywords": keywords,

        "urls": urls,

        "domains": domains,

        "suspicious_urls": suspicious_urls,

        "reasons": reasons
    }