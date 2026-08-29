
from flask import Flask, render_template, request, jsonify
from urllib.parse import urlparse
from datetime import datetime
import socket
import ssl
import re
import ipaddress
import requests

app = Flask(__name__)

# Demo/local intelligence stores.
# Add known malicious domains to THREAT_DOMAINS and trusted domains to TRUSTED_DOMAINS.
THREAT_DOMAINS = {
    "malicious-example.com": {"type": "phishing", "source": "SENTINAL Threat DB"},
    "paypa1-login.com": {"type": "brand impersonation", "source": "SENTINAL Threat DB"},
    "secure-login-banking.example": {"type": "credential theft", "source": "SENTINAL Threat DB"},
}

TRUSTED_DOMAINS = {
    "google.com": {"brand": "Google", "category": "Technology"},
    "microsoft.com": {"brand": "Microsoft", "category": "Technology"},
    "apple.com": {"brand": "Apple", "category": "Technology"},
    "amazon.com": {"brand": "Amazon", "category": "Shopping"},
    "paypal.com": {"brand": "PayPal", "category": "Finance"},
}

SUSPICIOUS_TERMS = {
    "login", "signin", "secure-login", "verify", "verification",
    "verify-account", "account-verify", "update-payment", "password-reset",
    "wallet-connect", "free-gift", "confirm", "billing", "invoice",
    "security-alert", "unlock", "suspended", "webscr"
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly"
}

BRAND_TERMS = {
    "google": "google.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "paypal": "paypal.com",
}


def normalize_url(value):
    original = (value or "").strip()
    candidate = original if re.match(r"^https?://", original, re.I) else "https://" + original
    return original, candidate


def domain_from_url(value):
    _, candidate = normalize_url(value)
    parsed = urlparse(candidate)
    return (parsed.hostname or "").lower()


def root_domain(hostname):
    parts = hostname.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname


def add_signal(signals, category, title, detail, points, severity="medium"):
    signals.append({
        "category": category,
        "title": title,
        "detail": detail,
        "points": points,
        "severity": severity
    })


def fetch_technical_intelligence(candidate, hostname):
    """
    Best-effort live website intelligence.
    Network failures are recorded as evidence rather than crashing analysis.
    """
    data = {
        "reachable": False,
        "http_status": None,
        "final_url": None,
        "redirects": 0,
        "server": None,
        "content_length": None,
        "title": None,
        "forms": 0,
        "links": 0,
        "ip_addresses": [],
        "tls": None,
        "error": None,
    }

    try:
        ips = sorted({item[4][0] for item in socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)})
        data["ip_addresses"] = ips[:10]
    except Exception:
        pass

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=4) as raw:
            with context.wrap_socket(raw, server_hostname=hostname) as sock:
                cert = sock.getpeercert()
                data["tls"] = {
                    "enabled": True,
                    "issuer": next((v for group in cert.get("issuer", []) for k, v in group if k == "organizationName"), None),
                    "subject": next((v for group in cert.get("subject", []) for k, v in group if k == "commonName"), None),
                }
    except Exception as exc:
        data["tls"] = {"enabled": False, "error": str(exc)[:120]}

    try:
        response = requests.get(
            candidate,
            timeout=7,
            allow_redirects=True,
            headers={"User-Agent": "SENTINAL-Security-Scanner/1.0"},
        )
        data["reachable"] = True
        data["http_status"] = response.status_code
        data["final_url"] = response.url
        data["redirects"] = len(response.history)
        data["server"] = response.headers.get("Server")
        data["content_length"] = len(response.content)

        html = response.text[:1_000_000]
        title_match = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
        if title_match:
            data["title"] = re.sub(r"\s+", " ", title_match.group(1)).strip()[:180]

        data["forms"] = len(re.findall(r"<form\b", html, re.I))
        data["links"] = len(re.findall(r"<a\b", html, re.I))
    except Exception as exc:
        data["error"] = str(exc)[:180]

    return data


def analyze_url(url):
    original, candidate = normalize_url(url)

    try:
        parsed = urlparse(candidate)
        hostname = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError:
        return {
            "risk": "Invalid URL",
            "score": 100,
            "message": "The URL could not be parsed safely.",
            "reasons": ["Invalid URL format"],
            "signals": [],
            "evidence": [],
            "stages": {},
            "technical": {},
            "url": original,
        }

    if not hostname:
        return {
            "risk": "Invalid URL",
            "score": 100,
            "message": "Please enter a valid website address.",
            "reasons": ["Missing hostname"],
            "signals": [],
            "evidence": [],
            "stages": {},
            "technical": {},
            "url": original,
        }

    signals = []
    evidence = []
    score = 0
    lower_url = candidate.lower()
    root = root_domain(hostname)

    # 1. Threat DB
    threat_match = THREAT_DOMAINS.get(hostname) or THREAT_DOMAINS.get(root)
    if threat_match:
        add_signal(
            signals, "Threat DB", "Known threat-domain match",
            f"{hostname} is present in the local SENTINAL threat database as {threat_match['type']}.",
            100, "critical"
        )
        evidence.append({
            "label": "Threat database",
            "value": f"MATCH — {threat_match['type']}",
            "detail": f"Source: {threat_match['source']}",
            "status": "danger"
        })
        score = 100
        risk = "High Risk"
        message = "This domain is already classified as a known threat. Do not open it or enter credentials."
        return build_result(original, candidate, hostname, score, risk, message, signals, evidence,
                            {"threat_db": "MATCH", "trusted_domain": "NOT CHECKED", "deep_analysis": "SKIPPED"},
                            {}, threat_match)

    evidence.append({
        "label": "Threat database",
        "value": "NO MATCH",
        "detail": "No matching domain was found in the local SENTINAL threat database.",
        "status": "safe"
    })

    # 2. Exact trusted domain
    trusted = TRUSTED_DOMAINS.get(hostname)
    if trusted:
        evidence.append({
            "label": "Trusted registry",
            "value": f"VERIFIED — {trusted['brand']}",
            "detail": f"Exact official domain for {trusted['brand']} ({trusted['category']}).",
            "status": "safe"
        })
        evidence.append({
            "label": "Domain relationship",
            "value": "EXACT MATCH",
            "detail": "The entered hostname exactly matches the verified official domain.",
            "status": "safe"
        })
        return build_result(
            original, candidate, hostname, 0, "Verified Official",
            "This URL exactly matches a domain in the SENTINAL trusted registry. No strong phishing indicators were detected.",
            signals, evidence,
            {"threat_db": "NO MATCH", "trusted_domain": "EXACT MATCH", "deep_analysis": "OPTIONAL"},
            {}, None, trusted
        )

    evidence.append({
        "label": "Trusted registry",
        "value": "NO EXACT MATCH",
        "detail": "The hostname is not an exact match for a domain in the SENTINAL trusted registry.",
        "status": "warning"
    })

    # 3. Deep URL analysis
    try:
        ip = ipaddress.ip_address(hostname)
        add_signal(signals, "Domain", "IP address used as hostname",
                   "The URL uses a raw IP address instead of a recognizable domain name.",
                   25, "high")
    except ValueError:
        pass

    if "@" in candidate:
        add_signal(signals, "URL", "@ symbol detected",
                   "Everything before @ can be misleading while the browser uses the hostname after it.",
                   25, "high")

    if len(original) > 100:
        add_signal(signals, "URL", "Unusually long URL",
                   f"The submitted URL is {len(original)} characters long, increasing the chance of hidden or confusing path data.",
                   15, "medium")

    if hostname in SHORTENERS:
        add_signal(signals, "Domain", "URL-shortening service",
                   "Shortened URLs hide the final destination and make inspection harder.",
                   20, "medium")

    if hostname.startswith("xn--") or ".xn--" in hostname:
        add_signal(signals, "Domain", "Punycode / internationalized domain",
                   "The domain uses punycode, which can be abused for visually deceptive look-alike domains.",
                   25, "high")

    hyphens = hostname.count("-")
    if hyphens >= 3:
        add_signal(signals, "Domain", "Many hyphens",
                   f"The hostname contains {hyphens} hyphens. This pattern is common in disposable or impersonation domains.",
                   10, "medium")

    subdomains = max(0, len(hostname.split(".")) - 2)
    if len(hostname.split(".")) > 4:
        add_signal(signals, "Domain", "Deep subdomain chain",
                   f"The hostname contains {len(hostname.split('.'))} labels, which can make the true domain harder to recognize.",
                   10, "medium")

    suspicious_found = []
    for term in sorted(SUSPICIOUS_TERMS):
        if term in lower_url:
            suspicious_found.append(term)
    if suspicious_found:
        add_signal(
            signals, "Content", "Credential/payment language in URL",
            "The URL contains security-sensitive wording: " + ", ".join(suspicious_found[:6]) + ".",
            min(25, 10 + 5 * len(suspicious_found[:3])), "high"
        )

    if parsed.scheme != "https":
        add_signal(signals, "Transport", "HTTPS is not used",
                   "The submitted URL uses HTTP, so the connection does not provide HTTPS transport protection.",
                   15, "high")

    if port and port not in (80, 443):
        add_signal(signals, "Technical", "Non-standard port",
                   f"The URL explicitly uses port {port}, which is unusual for a normal public website.",
                   10, "medium")

    # Brand impersonation / look-alike detection
    compact = re.sub(r"[^a-z0-9]", "", hostname)
    for brand, official in BRAND_TERMS.items():
        if brand in compact and hostname != official and root != official:
            add_signal(
                signals, "Impersonation", f"Possible {brand.title()} impersonation",
                f"The hostname contains the brand name '{brand}' but does not match the official domain {official}.",
                30, "critical"
            )
            break

    # 4. Live technical intelligence
    technical = fetch_technical_intelligence(candidate, hostname)

    if technical.get("reachable"):
        evidence.append({
            "label": "Website reachability",
            "value": f"REACHED — HTTP {technical.get('http_status')}",
            "detail": f"Final destination: {technical.get('final_url')}",
            "status": "safe" if technical.get("http_status", 500) < 400 else "warning"
        })

        if technical.get("redirects", 0) > 0:
            add_signal(
                signals, "Technical", "Redirect chain detected",
                f"The request followed {technical['redirects']} redirect(s) before reaching the final destination.",
                min(20, technical["redirects"] * 5), "medium"
            )

        if technical.get("forms", 0) > 0:
            add_signal(
                signals, "Content", "Input forms detected",
                f"The page contains {technical['forms']} form(s). Forms are not malicious by themselves, but credential/payment forms deserve extra scrutiny on an unverified domain.",
                5, "low"
            )

        if technical.get("title"):
            evidence.append({
                "label": "Page title",
                "value": technical["title"],
                "detail": "Title extracted from the returned HTML.",
                "status": "neutral"
            })

    else:
        evidence.append({
            "label": "Website reachability",
            "value": "NOT REACHED",
            "detail": technical.get("error") or "The server could not be reached during the scan.",
            "status": "warning"
        })

    if technical.get("ip_addresses"):
        evidence.append({
            "label": "Resolved IP",
            "value": ", ".join(technical["ip_addresses"][:3]),
            "detail": "DNS resolution result observed during the scan.",
            "status": "neutral"
        })

    if technical.get("tls"):
        if technical["tls"].get("enabled"):
            evidence.append({
                "label": "TLS",
                "value": "HTTPS certificate presented",
                "detail": technical["tls"].get("subject") or "Certificate was successfully negotiated.",
                "status": "safe"
            })
        else:
            add_signal(
                signals, "Transport", "TLS connection could not be verified",
                "SENTINAL could not establish a trusted TLS connection during the live check.",
                10, "medium"
            )

    # 5. Score and explain
    score = min(100, sum(s["points"] for s in signals))

    if score >= 60:
        risk = "High Risk"
        message = "Multiple risk indicators were found. Treat this website as unsafe unless independently verified."
    elif score >= 30:
        risk = "Suspicious"
        message = "The website is not verified and contains indicators that deserve caution before opening or submitting information."
    else:
        risk = "Low Risk"
        message = "No major malicious URL patterns were detected, but this is not proof that the website is trustworthy."

    if not signals:
        add_signal(
            signals, "Heuristics", "No strong URL-pattern indicators",
            "The current checks did not find a strong phishing pattern. Continue to verify the domain independently.",
            0, "low"
        )

    for signal in signals:
        evidence.append({
            "label": signal["title"],
            "value": f"+{signal['points']} risk points" if signal["points"] else "Informational",
            "detail": signal["detail"],
            "status": "danger" if signal["severity"] in ("critical", "high") else
                      "warning" if signal["severity"] == "medium" else "neutral"
        })

    return build_result(
        original, candidate, hostname, score, risk, message, signals, evidence,
        {"threat_db": "NO MATCH", "trusted_domain": "NO EXACT MATCH", "deep_analysis": "COMPLETED"},
        technical, None
    )


def build_result(original, candidate, hostname, score, risk, message, signals,
                 evidence, stages, technical, threat=None, trusted=None):
    reasons = [s["detail"] for s in signals if s["points"] > 0]
    if not reasons:
        reasons = ["No strong risk indicators were detected by the current checks."]

    return {
        "status": "Analysis complete",
        "url": original,
        "normalized_url": candidate,
        "domain": hostname,
        "risk": risk,
        "score": score,
        "message": message,
        "reasons": reasons,
        "signals": signals,
        "evidence": evidence,
        "stages": stages,
        "technical": technical,
        "threat_record": threat,
        "trusted_record": trusted,
        "analyzed_at": datetime.now().strftime("%d %b %Y, %I:%M:%S %p"),
    }


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
def analyze_url_api():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"status": "error", "error": "Please enter a URL."}), 400

    try:
        return jsonify(analyze_url(url))
    except Exception as exc:
        return jsonify({
            "status": "error",
            "error": "SENTINAL could not complete the analysis.",
            "details": str(exc)
        }), 500


@app.route("/api/website-intelligence", methods=["POST"])
def website_intelligence_api():
    return analyze_url_api()


if __name__ == "__main__":
    app.run(debug=True)
