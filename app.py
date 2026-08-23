from flask import Flask, request, jsonify, render_template, session
from urllib.parse import urlparse
import ipaddress
import os
from dotenv import load_dotenv

load_dotenv()
import re
import requests
import sqlite3
import json
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "change-this-secret-key-in-production")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.getenv("SESSION_COOKIE_SECURE", "0") == "1"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "sentinal.db")

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            analysis_type TEXT NOT NULL CHECK (analysis_type IN ('url', 'email', 'message')),
            input_text TEXT NOT NULL,
            result TEXT NOT NULL,
            score INTEGER NOT NULL,
            reasons_json TEXT NOT NULL,
            recommendation TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_analyses_user_created
        ON analyses(user_id, created_at DESC)
    """)
    conn.commit()
    conn.close()

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Authentication required."}), 401
        return fn(*args, **kwargs)
    return wrapper

def save_analysis(user_id, analysis_type, input_text, result):
    """Store an analysis under the authenticated user's account."""
    conn = get_db()
    conn.execute(
        """
        INSERT INTO analyses
        (user_id, analysis_type, input_text, result, score, reasons_json, recommendation)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user_id,
            analysis_type,
            input_text,
            result.get("result", ""),
            int(result.get("score", 0)),
            json.dumps(result.get("reasons", []), ensure_ascii=False),
            result.get("recommendation", "")
        )
    )
    conn.commit()
    conn.close()

init_db()

# These are heuristic signals, not proof of maliciousness.
SUSPICIOUS_URL_WORDS = {
    "login", "verify", "verification", "account", "update", "secure", "security",
    "password", "signin", "bank", "wallet", "confirm", "recover", "free", "bonus",
    "gift", "claim", "payment", "unlock", "reset", "suspend", "limited", "invoice",
    "kyc", "refund", "reward", "support", "webmail", "auth"
}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "shorturl.at", "ow.ly", "buff.ly", "rebrand.ly"}
DANGEROUS_EXTENSIONS = {".exe", ".scr", ".bat", ".cmd", ".msi", ".apk", ".jar", ".vbs", ".ps1", ".hta"}
SUSPICIOUS_TLDS = {".top", ".xyz", ".click", ".zip", ".mov", ".work", ".gq", ".tk", ".ml", ".cf", ".ga"}

TEXT_PATTERNS = [
    (r"\b(otp|one[- ]time password|verification code|passcode)\b", 22, "Requests or mentions an OTP/verification code."),
    (r"\b(password|pass(word)?|pin|cvv|card number|bank account|aadhar|aadhaar|pan number)\b", 20, "Requests sensitive account, identity, or payment information."),
    (r"\b(click|tap|open|follow)\b.{0,60}\b(link|url|button)\b", 12, "Pushes you to click or open a link."),
    (r"\b(urgent|immediately|right now|act now|last chance|within \d+ (minutes?|hours?)|expire(s|d)? today)\b", 14, "Uses urgency or pressure to make you act quickly."),
    (r"\b(account|service|subscription|bank|wallet|sim|number)\b.{0,70}\b(suspend|suspended|blocked|locked|close|closed|expire|expired|deactivat)\b", 18, "Claims an account, SIM, or service is at risk of suspension/closure."),
    (r"\b(prize|winner|won|reward|gift|bonus|lottery|refund|cashback)\b", 14, "Promises a prize, reward, refund, or unexpected benefit."),
    (r"\b(pay|payment|transfer|send money|gift card|crypto|bitcoin|upi|usdt)\b", 16, "Requests or discusses a payment or money transfer."),
    (r"\b(verify your identity|confirm your identity|kyc|re-?kyc)\b", 14, "Uses an identity-verification request that may be used for phishing."),
    (r"\b(keep this secret|don't tell|do not tell|confidential|don't share)\b", 12, "Uses secrecy to discourage you from checking with others."),
    (r"\b(refund|delivery|parcel|courier|customs|shipping)\b.{0,80}\b(pay|fee|charge|click|verify)\b", 14, "Matches a common delivery/refund scam pattern."),
    (r"\b(technical support|support team|virus|infected|hacked|remote access|anydesk|teamviewer)\b", 16, "Matches a common fake technical-support or remote-access scam pattern."),
    (r"\b(job|work from home|part[- ]time)\b.{0,80}\b(fee|deposit|registration|pay)\b", 14, "Matches a possible job/task scam requesting money upfront."),
]

BRAND_DOMAINS = {
    "google": {"google.com", "google.co.in"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "outlook.com"},
    "apple": {"apple.com", "icloud.com"},
    "paypal": {"paypal.com"},
    "amazon": {"amazon.com", "amazon.in"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com"},
    "netflix": {"netflix.com"},
    "linkedin": {"linkedin.com"},
}


def _hostname_domain(hostname):
    hostname = hostname.lower().strip(".")
    parts = hostname.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else hostname



# Optional external threat intelligence. Keep API keys on the server, never in JavaScript.
SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v5/urls:search"

def check_google_safe_browsing(url):
    """Check a URL against Google's current Safe Browsing threat lists.

    Returns a status dictionary. If no API key is configured or the provider is
    temporarily unavailable, the local heuristic result remains usable. The raw
    URL is sent to Google only when this optional integration is enabled.
    """
    if not SAFE_BROWSING_API_KEY:
        return {"status": "not_configured", "provider": "Google Safe Browsing", "threats": []}

    try:
        response = requests.get(
            SAFE_BROWSING_URL,
            params={
                "key": SAFE_BROWSING_API_KEY,
                "urls": [url],
            },
            timeout=8,
        )
        
        if response.status_code != 200:
            print("SAFE BROWSING DEBUG STATUS:", response.status_code)
            print("SAFE BROWSING DEBUG RESPONSE:", response.text[:500])

            return {
            "status": "error",
             "provider": "Google Safe Browsing",
             "threats": [],
            "message": f"Provider returned HTTP {response.status_code}."
           }

        payload = response.json()
        threats = payload.get("threats", []) or []
        simplified = []
        for threat in threats:
            simplified.append({
                "url": threat.get("url", ""),
                "threat_types": threat.get("threatTypes", []) or []
            })

        return {
            "status": "match" if simplified else "no_match",
            "provider": "Google Safe Browsing",
            "threats": simplified,
        }
    except requests.RequestException as exc:
        return {
            "status": "error",
            "provider": "Google Safe Browsing",
            "threats": [],
            "message": f"Threat-intelligence lookup failed: {exc.__class__.__name__}."
        }
    except ValueError:
        return {
            "status": "error",
            "provider": "Google Safe Browsing",
            "threats": [],
            "message": "Threat-intelligence provider returned an unexpected response."
        }


def analyze_url(raw_url):
    """Score a URL using independent heuristic signals.

    This is a screening layer only: it does not prove a URL is malicious or safe.
    """
    url = (raw_url or "").strip()
    if not url:
        return {"url": url, "domain": "", "result": "INVALID", "score": 100,
                "reasons": ["No URL was provided."],
                "recommendation": "Do not open an empty or unknown link."}

    # Only permit web URLs. We don't fetch or visit the supplied destination.
    candidate = url if re.match(r"^https?://", url, re.I) else "https://" + url
    try:
        parsed = urlparse(candidate)
    except ValueError:
        parsed = None

    hostname = (parsed.hostname or "").lower().strip(".") if parsed else ""
    if not hostname or parsed.scheme.lower() not in {"http", "https"}:
        return {"url": url, "domain": hostname, "result": "INVALID", "score": 100,
                "reasons": ["The URL does not contain a valid HTTP/HTTPS hostname."],
                "recommendation": "Do not open this address until it has been verified."}

    reasons = []
    score = 0
    lower_url = candidate.lower()

    def add(points, reason):
        nonlocal score
        score += points
        reasons.append(reason)

    try:
        ipaddress.ip_address(hostname)
        is_ip = True
    except ValueError:
        is_ip = False

    # A trusted-domain check is deliberately narrow: it can reduce false positives,
    # but it never overrides strong danger indicators or proves the site is safe.
    domain = _hostname_domain(hostname)
    trusted_domain = any(domain in official for official_set in BRAND_DOMAINS.values() for official in official_set)

    found = sorted({word for word in SUSPICIOUS_URL_WORDS
                    if re.search(rf"(?<![a-z]){re.escape(word)}(?![a-z])", lower_url)})
    if found:
        # Login/verify words alone are weak signals; several together are stronger.
        points = min(4 * len(found), 16)
        if len(found) >= 3:
            points += 4
        if not trusted_domain:
            add(points, "Suspicious URL language found: " + ", ".join(found))

    if parsed.scheme.lower() != "https":
        add(12, "The address does not use HTTPS.")

    if is_ip:
        add(28, "The link uses a raw IP address instead of a normal domain name.")
        try:
            ip_obj = ipaddress.ip_address(hostname)
            if ip_obj.is_private:
                reasons.append("The IP address is private/internal; this is not proof of a phishing site, but it should only be used when you recognize the network.")
        except ValueError:
            pass

    if parsed.username or parsed.password or "@" in candidate:
        add(25, "The URL contains credentials or '@', which can hide the real destination.")

    if len(candidate) > 120:
        add(10, "The URL is unusually long.")
    elif len(candidate) > 80:
        add(5, "The URL is longer than usual.")

    # Subdomain depth only makes sense for domain names, not raw IP addresses.
    if not is_ip:
        parts = hostname.split(".")
        if len(parts) >= 5:
            add(14, "The hostname has many subdomains, which can be used in deceptive URLs.")
        elif len(parts) == 4:
            add(8, "The hostname has several subdomains; check the registered domain carefully.")

    if "xn--" in hostname:
        add(22, "The domain uses Punycode/IDN encoding; check carefully for look-alike characters.")

    if hostname.count("-") >= 4:
        add(12, "The hostname contains many hyphens.")
    elif hostname.count("-") >= 2:
        add(5, "The hostname contains multiple hyphens.")

    if hostname in SHORTENERS or domain in SHORTENERS:
        add(18, "The link uses a URL-shortening service, so the final destination is hidden.")

    if any(parsed.path.lower().endswith(ext) for ext in DANGEROUS_EXTENSIONS):
        add(30, "The link points to a potentially dangerous executable/script file type.")

    if any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS):
        add(7, "The domain uses a TLD that can be common among disposable or abusive registrations.")

    # Explicitly look for a brand name embedded in a non-official registered domain.
    for brand, official_domains in BRAND_DOMAINS.items():
        if brand in hostname and domain not in official_domains:
            add(24, f"The hostname contains '{brand}' but the registered domain is not an official {brand} domain.")
            break

    if re.search(r"(?:login|signin|verify|secure|account|bank|paypal|microsoft|apple|amazon)[a-z0-9-]{0,20}\.(?:com|net|org)", hostname):
        if not trusted_domain:
            add(10, "The hostname has a pattern commonly used for service impersonation.")

    # Suspicious query parameters often indicate tracking, redirects, or credential flows.
    if re.search(r"(?i)(?:^|[?&])(redirect|url|return|returnurl|next|continue|dest|destination)=https?%3a", lower_url):
        add(12, "The URL contains an encoded external redirect destination.")

    if re.search(r"(?i)(?:password|passwd|passcode|otp|token|session|auth)[^=&]{0,10}=", lower_url):
        add(8, "The URL contains a parameter name associated with credentials or session data.")

    if "%" in candidate and re.search(r"%(?:2f|2e|40|3a|5c)", lower_url):
        add(5, "The URL contains encoded structural characters; inspect the destination carefully.")

    if parsed.port and parsed.port not in {80, 443}:
        add(8, "The URL uses a non-standard web port.")

    if candidate.count("//") > 1:
        add(10, "The URL contains unusual repeated separators.")

    # Strong combinations matter more than a single keyword.
    strong_combo = (
        not trusted_domain and
        len(found) >= 2 and
        (parsed.scheme.lower() != "https" or is_ip or hostname.count("-") >= 2 or "@" in candidate)
    )
    if strong_combo:
        add(8, "Several independent phishing indicators occur together.")

    score = min(score, 100)
    if score >= 80:
        result = "VERY HIGH RISK"
        recommendation = "Do not open the link. Verify the sender and destination using an independent official source."
    elif score >= 60:
        result = "HIGH RISK"
        recommendation = "Do not open the link unless you independently verify the destination and sender."
    elif score >= 35:
        result = "SUSPICIOUS"
        recommendation = "Avoid opening it until you can independently verify the domain and sender."
    else:
        result = "NO OBVIOUS THREATS"
        recommendation = "No obvious malicious URL patterns were detected. This does not guarantee that the site is safe."

    if not reasons:
        reasons.append("No obvious suspicious URL patterns were detected.")

    # External reputation is deliberately separate from the heuristic score.
    # A confirmed Safe Browsing match is a much stronger signal than a keyword.
    reputation = check_google_safe_browsing(candidate)
    if reputation.get("status") == "match":
        threat_types = sorted({
            threat_type
            for item in reputation.get("threats", [])
            for threat_type in item.get("threat_types", [])
        })
        detail = ", ".join(threat_types) if threat_types else "known unsafe resource"
        score = max(score, 90)
        result = "KNOWN THREAT"
        recommendation = "Do not open this link. Use an independently verified official website or contact method instead."
        reasons.insert(0, f"Google Safe Browsing matched this URL to a known threat ({detail}).")

    print("PHISHGUARD REPUTATION:", reputation)

    return {"url": url,
             "domain": hostname,
             "result": result, 
             "score": score,
            "reasons": reasons, 
            "recommendation": recommendation,
            "reputation": reputation}

def extract_urls(text):
    return re.findall(r"(?i)\b(?:https?://|www\.)[^\s<>'\"]+", text or "")


def analyze_text(text, source="message"):
    text = (text or "").strip()
    if not text:
        return {"result": "INVALID", "score": 100,
                "reasons": ["No text was provided."], "urls": [],
                "recommendation": "Paste the email, message, or call transcript to analyze it."}

    score = 0
    reasons = []
    lower = text.lower()

    for pattern, points, reason in TEXT_PATTERNS:
        if re.search(pattern, lower, re.I | re.S):
            score += points
            reasons.append(reason)

    urls = extract_urls(text)
    url_results = [analyze_url(u.rstrip(".,);]")) for u in urls[:10]]
    for item in url_results:
        if item["score"] >= 70:
            score += 25
            reasons.append(f"A high-risk URL was found: {item['domain']}")
        elif item["score"] >= 40:
            score += 12
            reasons.append(f"A suspicious URL was found: {item['domain']}")

    if source == "email":
        if re.search(r"(?i)from\s*:\s*[^\n]+", text) and re.search(r"(?i)reply-to\s*:\s*[^\n]+", text):
            score += 5
            reasons.append("The text contains both From and Reply-To fields; compare them carefully for mismatches.")
        if re.search(r"(?i)dear (customer|user|sir|madam)\b", text):
            score += 5
            reasons.append("The message uses a generic greeting rather than identifying you by name.")

    if source == "call":
        if re.search(r"(?i)\b(call|caller)\b.{0,60}\b(bank|police|government|support|courier|tax|cyber)\b", text, re.S):
            score += 6
            reasons.append("The transcript contains authority/official-role claims; verify the caller independently.")

    # Multiple independent signals should increase concern, but never exceed 100.
    if len(reasons) >= 4:
        score += 8

    score = min(score, 100)
    if score >= 70:
        result = "HIGH RISK"
        recommendation = "Do not click links, share codes/passwords, send money, install software, or follow the caller's instructions. Verify through an official channel."
    elif score >= 40:
        result = "SUSPICIOUS"
        recommendation = "Treat this as potentially fraudulent and verify the claim independently before taking action."
    else:
        result = "LOW RISK"
        recommendation = "No obvious scam patterns were detected. Still avoid sharing sensitive information based only on an unsolicited message."

    if not reasons:
        reasons.append("No obvious scam patterns were detected in the supplied text.")

    return {"result": result, "score": score, "reasons": reasons,
            "urls": url_results, "recommendation": recommendation}


@app.route("/")
def home():
    return render_template("index.html")


@app.post("/api/register")
def register():
    data = request.get_json(silent=True) or {}
    username = " ".join(str(data.get("username", "")).split())
    password = str(data.get("password", "")).strip()

    if len(username) < 3 or len(username) > 50:
        return jsonify({"error": "Username must be 3-50 characters."}), 400
    if len(password) < 8 or len(password) > 128:
        return jsonify({"error": "Password must be 8-128 characters."}), 400

    try:
        conn = get_db()
        cur = conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, generate_password_hash(password))
        )
        conn.commit()
        user_id = cur.lastrowid
        conn.close()
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists."}), 409

    session.clear()
    session["user_id"] = user_id
    session["username"] = username
    return jsonify({"message": "Account created.", "username": username}), 201

@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    username = " ".join(str(data.get("username", "")).split())
    password = str(data.get("password", "")).strip()

    conn = get_db()
    user = conn.execute(
        "SELECT id, username, password_hash FROM users WHERE username = ? COLLATE NOCASE",
        (username,)
    ).fetchone()
    conn.close()

    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "Invalid username or password."}), 401

    session.clear()
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    return jsonify({"message": "Login successful.", "username": user["username"]})

@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify({"message": "Logged out."})

@app.get("/api/me")
def me():
    if "user_id" not in session:
        return jsonify({"authenticated": False})
    return jsonify({"authenticated": True, "username": session.get("username")})

@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "service": "PhishGuard"})


@app.post("/api/check-url")
@login_required
def check_url():
    data = request.get_json(silent=True) or {}
    raw_url = " ".join(str(data.get("url", "")).split())
    analysis = analyze_url(raw_url)
    save_analysis(session["user_id"], "url", raw_url, analysis)
    return jsonify(analysis)


@app.post("/api/check-text")
@login_required
def check_text():
    data = request.get_json(silent=True) or {}
    source = data.get("source", "message")
    if source not in {"email", "message", "call"}:
        source = "message"

    raw_text = str(data.get("text", "")).strip()
    analysis = analyze_text(raw_text, source)
    stored_type = source if source in {"email", "message"} else "message"
    save_analysis(session["user_id"], stored_type, raw_text, analysis)
    return jsonify(analysis)


@app.get("/api/history")
@login_required
def history():
    """Return only the authenticated user's analysis history."""
    conn = get_db()
    rows = conn.execute(
        """
        SELECT id, analysis_type, input_text, result, score,
               reasons_json, recommendation, created_at
        FROM analyses
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT 100
        """,
        (session["user_id"],)
    ).fetchall()
    conn.close()

    return jsonify({
        "history": [
            {
                "id": row["id"],
                "type": row["analysis_type"],
                "input": row["input_text"],
                "result": row["result"],
                "score": row["score"],
                "reasons": json.loads(row["reasons_json"] or "[]"),
                "recommendation": row["recommendation"],
                "created_at": row["created_at"]
            }
            for row in rows
        ]
    })


@app.delete("/api/history/<int:analysis_id>")
@login_required
def delete_history_item(analysis_id):
    """Delete only an analysis owned by the authenticated user."""
    conn = get_db()
    cursor = conn.execute(
        "DELETE FROM analyses WHERE id = ? AND user_id = ?",
        (analysis_id, session["user_id"])
    )
    conn.commit()
    deleted = cursor.rowcount
    conn.close()

    if not deleted:
        return jsonify({"error": "Analysis not found."}), 404

    return jsonify({"message": "Analysis deleted."})


if __name__ == "__main__":
    app.run(debug=True)