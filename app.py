from flask import Flask, render_template, request
import requests
import whois
import socket
from datetime import datetime
from urllib.parse import urlparse

app = Flask(__name__)


# -------------------- Helper: extract domain safely --------------------
def get_domain(url):
    parsed = urlparse(url)
    return parsed.netloc


# -------------------- Google Safe Browsing (optional use later) --------------------
def check_google_safe_browsing(url):
    API_KEY = "AIzaSyBcCiPOgFGQHOAL0AM6bMjL3EfIQjX-zfs"
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={AIzaSyBcCiPOgFGQHOAL0AM6bMjL3EfIQjX-zfs}"

    payload = {
        "client": {"clientId": "fraud-detector", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        response = requests.post(api_url, json=payload, timeout=5)
        if response.status_code == 200 and response.json():
            return True
    except:
        pass
    return False


# -------------------- Risk calculation logic --------------------
def calculate_risk(url):
    score = 0
    reasons = []
    domain = get_domain(url)

    # HTTPS check
    if not url.startswith("https"):
        score += 20
        reasons.append("URL is not using HTTPS")

    #  IP address in URL check
    try:
        socket.inet_aton(domain)
        score += 30
        reasons.append("URL contains IP address instead of domain")
    except:
        pass

    #  Suspicious keywords
    suspicious_words = ["login", "verify", "bank", "free", "win", "update"]
    for word in suspicious_words:
        if word in url.lower():
            score += 15
            reasons.append(f"Suspicious keyword found: {word}")

    #  Domain age check (WHOIS)
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        age_days = (datetime.now() - creation_date).days

        if age_days < 180:
            score += 25
            reasons.append("Domain is less than 6 months old")

    except:
        reasons.append("Could not fetch domain age")

    #  Website reachable / SSL check
    try:
        requests.get(url, timeout=5)
    except:
        score += 20
        reasons.append("Website not reachable or SSL issue")

    return score, reasons


# ---- ---- ---- ---- ---- Main Route ---- ---- ---- ---- ----
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form["url"]
        domain = get_domain(url)

        # Risk analysis
        score, reasons = calculate_risk(url)

        # Status based on score
        if score <= 30:
            status = "Safe ✅"
        elif score <= 60:
            status = "Suspicious ⚠️"
        else:
            status = "Fraud ❌"

        # IP address
        try:
            ip = socket.gethostbyname(domain)
        except:
            ip = "Not Found"

        # WHOIS domain details
        domain_details = {}
        try:
            domain_info = whois.whois(domain)
            domain_details["registrar"] = domain_info.registrar
            domain_details["creation_date"] = str(domain_info.creation_date)
            domain_details["country"] = domain_info.country
            domain_details["org"] = domain_info.org
        except:
            domain_details = {
                "registrar": "Not Available",
                "creation_date": "Not Available",
                "country": "Not Available",
                "org": "Not Available",
            }

        # Send data to result page
        return render_template(
            "result.html",
            url=url,
            score=score,
            reasons=reasons,
            status=status,
            ip=ip,
            details=domain_details
        )

    return render_template("index.html")


# ---- ---- ----  ---- ---- Run App ---- ---- ----  ---- ----
if __name__ == "__main__":
    app.run(debug=True)
