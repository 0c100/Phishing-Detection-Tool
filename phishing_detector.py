from urllib.parse import urlsplit
import ipaddress
import json
import difflib
from datetime import datetime


# Known domains for similarity checking
KNOWN_BRANDS = [
    "google",
    "facebook",
    "microsoft",
    "paypal",
    "amazon",
    "instagram"
]

# URL shortener services
SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly"
]


def analyze_url(url):

    score = 0
    findings = []

    url = url.strip()

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parsed = urlsplit(url)
        domain = parsed.hostname

    except ValueError:
        domain = None

    if not domain:
        return {
            "url": url,
            "risk": "INVALID URL",
            "score": 0,
            "findings": ["Invalid URL format"]
        }

        # 1. Check HTTPS
    if parsed.scheme != "https":
        score += 15
        findings.append("HTTPS is not used")

    # 2. Check IP address
    try:
        ipaddress.ip_address(domain)
        score += 30
        findings.append("URL uses an IP address")
    except ValueError:
        pass

    # 3. Check suspicious keywords
    keywords = [
        "login", "verify", "account",
        "password", "secure", "update"
    ]

    for word in keywords:
        if word in url.lower():
            score += 8
            findings.append(
                f"Suspicious keyword: {word}"
            )

    # 4. Check URL length
    if len(url) > 100:
        score += 10
        findings.append("Unusually long URL")

    # 5. Check @ symbol
    if "@" in parsed.netloc:
        score += 25
        findings.append("URL contains @ symbol")
        # 6. Check shortened URLs
    if domain.lower() in SHORTENERS:
        score += 20
        findings.append("URL uses a shortening service")

    # 7. Check Punycode
    if "xn--" in domain.lower():
        score += 25
        findings.append("Punycode domain detected")

    # 8. Check suspicious subdomains
   

    try:
        ipaddress.ip_address(domain)
        is_ip = True

    except ValueError:
        is_ip = False

    if not is_ip and len(domain.split(".")) > 3:
        score += 10
        findings.append("Many subdomains detected")

    # 9. Check similar brand names
    domain_labels = domain.lower().split(".")

    # Convert similar-looking numbers into letters
    leet_map = str.maketrans({
        "0": "o",
        "1": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t"
    })
    brand_detected = False

    for label in domain_labels:

        parts = label.split("-")

        for part in parts:

            normalized_part = part.translate(leet_map)

            for brand in KNOWN_BRANDS:

                similarity = difflib.SequenceMatcher(
                    None, normalized_part, brand
                ).ratio()

                if part != brand and similarity >= 0.80:
                    score += 25

                    findings.append(
                        f"Possible brand impersonation: {brand}"
                    )

                    brand_detected = True
                    break

            if brand_detected:
                break

        if brand_detected:
            break

   # Final risk calculation
    score = min(score, 100)

    if score >= 50:
        risk = "HIGH RISK"

    elif score >= 25:
        risk = "MEDIUM RISK"

    else:
        risk = "LOW RISK"

    return {
        "url": url,
        "domain": domain,
        "risk": risk,
        "score": score,
        "findings": findings
    }


# Main program
print("=" * 45)
print("       PHISHING DETECTION TOOL V3")
print("=" * 45)

target = input("\nEnter URL to analyze: ")

result = analyze_url(target)

print("\n========== ANALYSIS REPORT ==========")
print("URL:", result["url"])
print("Domain:", result.get("domain", "Unknown"))
print("Risk Level:", result["risk"])
print("Risk Score:", result["score"], "/ 100")

print("\nFindings:")

if result["findings"]:

    for finding in result["findings"]:
        print("-", finding)

else:
    print("No suspicious indicators found.")

# Save report as JSON
report = {
    "analysis_time": datetime.now().isoformat(),
    **result
}
with open("analysis_report.json", "w", encoding="utf-8") as file:
    json.dump(report, file, indent=4, ensure_ascii=False)

print("\nReport saved successfully!")
print("File: analysis_report.json")

print("\n=====================================")


#python phishing_detector.py  امر تشغيل ال tool 
#https://g00gle.example  رابط تجريبي 