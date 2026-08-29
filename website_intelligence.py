# website_intelligence.py

import socket
import ssl
import ipaddress
from datetime import datetime, timezone
from unittest import result
from urllib.parse import urlparse, urljoin


import requests
import dns.resolver
from bs4 import BeautifulSoup


# ============================================================
# CONFIGURATION
# ============================================================

REQUEST_TIMEOUT = (5, 10)

# Maximum HTML/content that SENTINAL will read
MAX_RESPONSE_BYTES = 2 * 1024 * 1024  # 2 MB

# Maximum number of redirects
MAX_REDIRECTS = 5

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/151.0 Safari/537.36"
)


# ============================================================
# URL VALIDATION
# ============================================================

def normalize_url(url):
    """
    Make sure the submitted URL has HTTP or HTTPS.
    """

    url = url.strip()

    if not url:
        raise ValueError("URL cannot be empty.")

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError(
            "Only HTTP and HTTPS URLs are supported."
        )

    if not parsed.hostname:
        raise ValueError("Invalid hostname.")

    return url


# ============================================================
# IP SAFETY CHECK
# ============================================================

def is_safe_ip(ip):
    """
    Check whether an IP address is publicly routable.

    Private, localhost, multicast, reserved and unspecified
    addresses are rejected.

    This is an important SSRF protection layer.
    """

    try:
        address = ipaddress.ip_address(ip)

        if (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
            or address.is_unspecified
        ):
            return False

        return True

    except ValueError:
        return False


# ============================================================
# DNS / IP RESOLUTION
# ============================================================

def resolve_public_ips(hostname):
    """
    Resolve a hostname into IPv4 and IPv6 addresses.

    Private/internal addresses are rejected.
    """

    results = socket.getaddrinfo(
        hostname,
        None,
        type=socket.SOCK_STREAM
    )

    ipv4 = set()
    ipv6 = set()

    for result in results:

        address = result[4][0]

        if not is_safe_ip(address):
            raise ValueError(
                "Website resolves to a private or reserved IP address."
            )

        try:

            parsed = ipaddress.ip_address(address)

            if parsed.version == 4:
                ipv4.add(address)

            elif parsed.version == 6:
                ipv6.add(address)

        except ValueError:
            continue

    if not ipv4 and not ipv6:
        raise ValueError(
            "Could not resolve a public IP address."
        )

    return sorted(ipv4), sorted(ipv6)


# ============================================================
# DNS INFORMATION
# ============================================================

def get_dns_information(hostname):

    data = {
        "a_records": [],
        "aaaa_records": [],
        "mx_records": [],
        "ns_records": [],
        "cname_records": []
    }

    # --------------------------------------------------------
    # A / AAAA
    # --------------------------------------------------------

    try:

        ipv4, ipv6 = resolve_public_ips(hostname)

        data["a_records"] = ipv4
        data["aaaa_records"] = ipv6

    except Exception as exc:

        data["resolution_error"] = str(exc)

    # --------------------------------------------------------
    # MX
    # --------------------------------------------------------

    try:

        answers = dns.resolver.resolve(
            hostname,
            "MX",
            lifetime=3
        )

        data["mx_records"] = sorted(
           str(answer.exchange).rstrip(".")
           for answer in answers
           if str(answer.exchange).rstrip(".")
        )

    except Exception:
        pass

    # --------------------------------------------------------
    # NS
    # --------------------------------------------------------

    try:

        answers = dns.resolver.resolve(
            hostname,
            "NS",
            lifetime=3
        )

        data["ns_records"] = sorted(
            str(answer.target).rstrip(".")
            for answer in answers
        )

    except Exception:
        pass

    # --------------------------------------------------------
    # CNAME
    # --------------------------------------------------------

    try:

        answers = dns.resolver.resolve(
            hostname,
            "CNAME",
            lifetime=3
        )

        data["cname_records"] = sorted(
            str(answer.target).rstrip(".")
            for answer in answers
        )

    except Exception:
        pass

    return data


# ============================================================
# SSL CERTIFICATE
# ============================================================

def get_ssl_information(hostname, port=443):

    result = {
        "enabled": False,
        "valid": False,
        "issuer": None,
        "subject": None,
        "expires": None,
        "tls_version": None,
        "cipher": None,
        "error": None
    }

    try:

        context = ssl.create_default_context()

        with socket.create_connection(
            (hostname, port),
            timeout=5
        ) as raw_socket:

            with context.wrap_socket(
                raw_socket,
                server_hostname=hostname
            ) as secure_socket:

                certificate = secure_socket.getpeercert()

                result["enabled"] = True
                result["valid"] = True

                result["tls_version"] = (
                    secure_socket.version()
                )

                cipher = secure_socket.cipher()

                if cipher:
                    result["cipher"] = cipher[0]

                # ------------------------------------------------
                # Certificate Subject
                # ------------------------------------------------

                subject = {}

                for item in certificate.get(
                    "subject",
                    []
                ):

                    for key, value in item:
                        subject[key] = value

                result["subject"] = subject

                # ------------------------------------------------
                # Certificate Issuer
                # ------------------------------------------------

                issuer = {}

                for item in certificate.get(
                    "issuer",
                    []
                ):

                    for key, value in item:
                        issuer[key] = value

                result["issuer"] = issuer

                # ------------------------------------------------
                # Certificate Expiration
                # ------------------------------------------------

                expires = certificate.get("notAfter")

                if expires:

                    expiration_date = datetime.strptime(
                        expires,
                        "%b %d %H:%M:%S %Y %Z"
                    )

                    expiration_date = (
                        expiration_date.replace(
                            tzinfo=timezone.utc
                        )
                    )

                    result["expires"] = (
                        expiration_date.isoformat()
                    )

    except ssl.SSLError as exc:

        result["error"] = f"SSL error: {str(exc)}"

    except Exception as exc:

        result["error"] = str(exc)

    return result


# ============================================================
# WEBSITE FETCHING
# ============================================================

def fetch_website(url):

    url = normalize_url(url)

    parsed = urlparse(url)

    hostname = parsed.hostname

    if not hostname:
        raise ValueError(
            "Could not determine hostname."
        )

    # --------------------------------------------------------
    # Resolve IP BEFORE HTTP REQUEST
    # --------------------------------------------------------

    ipv4, ipv6 = resolve_public_ips(hostname)

    # --------------------------------------------------------
    # Create HTTP Session
    # --------------------------------------------------------

    session = requests.Session()

    session.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": (
            "text/html,"
            "application/xhtml+xml,"
            "application/xml;q=0.9,"
            "*/*;q=0.8"
        )
    })

    session.max_redirects = MAX_REDIRECTS

    # --------------------------------------------------------
    # Fetch website
    # --------------------------------------------------------

    response = session.get(
        url,
        timeout=REQUEST_TIMEOUT,
        allow_redirects=True,
        verify=True,
        stream=True
    )

    # --------------------------------------------------------
    # Read limited amount of data
    # --------------------------------------------------------

    content = b""

    for chunk in response.iter_content(
        chunk_size=8192
    ):

        if not chunk:
            continue

        content += chunk

        if len(content) >= MAX_RESPONSE_BYTES:

            content = content[
                :MAX_RESPONSE_BYTES
            ]

            break

    # --------------------------------------------------------
    # Decode HTML
    # --------------------------------------------------------

    encoding = response.encoding or "utf-8"

    try:

        html = content.decode(
            encoding,
            errors="replace"
        )

    except Exception:

        html = content.decode(
            "utf-8",
            errors="replace"
        )

    # ========================================================
    # REDIRECT INFORMATION
    # ========================================================

    redirects = []

    for item in response.history:

        redirects.append({
            "status_code": item.status_code,
            "url": item.url,
            "location": item.headers.get(
                "Location"
            )
        })

    # ========================================================
    # HTML PARSING
    # ========================================================

    soup = BeautifulSoup(
        html,
        "html.parser"
    )

    # --------------------------------------------------------
    # Page title
    # --------------------------------------------------------

    title = None

    if soup.title:

        title = soup.title.get_text(
            strip=True
        )

    # --------------------------------------------------------
    # Website elements
    # --------------------------------------------------------

    links = soup.find_all(
        "a",
        href=True
    )

    forms = soup.find_all(
        "form"
    )

    scripts = soup.find_all(
        "script"
    )

    iframes = soup.find_all(
        "iframe"
    )

    # --------------------------------------------------------
    # Password fields
    # --------------------------------------------------------

    password_fields = soup.find_all(
        "input",
        attrs={
            "type": lambda value:
            value and value.lower() == "password"
        }
    )

    # --------------------------------------------------------
    # Email fields
    # --------------------------------------------------------

    email_fields = soup.find_all(
        "input",
        attrs={
            "type": lambda value:
            value and value.lower() == "email"
        }
    )

    # --------------------------------------------------------
    # Hidden fields
    # --------------------------------------------------------

    hidden_fields = soup.find_all(
        "input",
        attrs={
            "type": lambda value:
            value and value.lower() == "hidden"
        }
    )

    # ========================================================
    # RETURN COMPLETE WEBSITE DATA
    # ========================================================

    return {

        "requested_url": url,

        "final_url": response.url,

        "hostname": hostname,

        # ----------------------------------------------------
        # HTTP
        # ----------------------------------------------------

        "http": {

            "status_code": response.status_code,

            "content_type": response.headers.get(
                "Content-Type"
            ),

            "server": response.headers.get(
                "Server"
            ),

            "content_length": len(content),

            "headers": {
                "content_security_policy":
                    response.headers.get(
                        "Content-Security-Policy"
                    ),

                "strict_transport_security":
                    response.headers.get(
                        "Strict-Transport-Security"
                    ),

                "x_frame_options":
                    response.headers.get(
                        "X-Frame-Options"
                    )
            }
        },

        # ----------------------------------------------------
        # IP
        # ----------------------------------------------------

        "ip": {

            "ipv4": ipv4,

            "ipv6": ipv6
        },

        # ----------------------------------------------------
        # Redirects
        # ----------------------------------------------------

        "redirects": redirects,

        # ----------------------------------------------------
        # Website
        # ----------------------------------------------------

        "website": {

            "title": title,

            "links": len(links),

            "forms": len(forms),

            "scripts": len(scripts),

            "iframes": len(iframes),

            "password_fields":
                len(password_fields),

            "email_fields":
                len(email_fields),

            "hidden_fields":
                len(hidden_fields)
        },

        # ----------------------------------------------------
        # DNS
        # ----------------------------------------------------

        "dns": get_dns_information(
            hostname
        ),

        # ----------------------------------------------------
        # SSL
        # ----------------------------------------------------

        "ssl": (
            get_ssl_information(
                hostname
            )
            if parsed.scheme == "https"
            else {
                "enabled": False,
                "valid": False,
                "error": "Website does not use HTTPS."
            }
        ),

        # ----------------------------------------------------
        # HTML
        # ----------------------------------------------------

        "html": html
    }


# ============================================================
# MAIN INVESTIGATION FUNCTION
# ============================================================

def investigate_website(url):

    started = datetime.now(
        timezone.utc
    )

    result = {

        "success": False,

        "error": None,

        "scan_started":
            started.isoformat()
    }

    try:

        data = fetch_website(url)

        # ------------------------------------------------------------
        # PHASE 2 - DEEP WEBSITE INSPECTION
        # ------------------------------------------------------------

        deep_analysis = deep_inspect_website(
    data["html"],
    data["final_url"]
)

        data["deep_analysis"] = deep_analysis

        result.update(data)

        result["success"] = True

    except Exception as exc:

        result["error"] = str(exc)

    result["scan_finished"] = (
        datetime.now(
            timezone.utc
        ).isoformat()
    )

    return result
# ============================================================
# PHASE 2 - DEEP WEBSITE INSPECTION
# ============================================================

SUSPICIOUS_KEYWORDS = [
    "verify your account",
    "verify account",
    "account verification",
    "confirm your account",
    "confirm account",
    "login",
    "sign in",
    "signin",
    "password",
    "security alert",
    "urgent",
    "suspended",
    "suspension",
    "unusual activity",
    "update payment",
    "verify identity",
    "unlock account",
    "reset password",
    "limited access",
    "click here immediately",
]


def get_domain(url):
    """Extract hostname from a URL."""

    try:
        hostname = urlparse(url).hostname

        if hostname:
            return hostname.lower()

    except Exception:
        pass

    return ""


def is_same_domain(url1, url2):
    """Check whether two URLs belong to the same hostname."""

    domain1 = get_domain(url1)
    domain2 = get_domain(url2)

    if not domain1 or not domain2:
        return False

    return domain1 == domain2


def inspect_forms(soup, page_url):
    """
    Inspect forms and determine where submitted information
    appears to be sent.
    """

    results = []

    for index, form in enumerate(soup.find_all("form"), 1):

        action = form.get("action", "").strip()

        method = form.get(
            "method",
            "GET"
        ).upper()

        if action:

            destination = urljoin(
                page_url,
                action
            )

        else:

            destination = page_url

        inputs = []

        for field in form.find_all("input"):

            field_type = (
                field.get("type", "text")
                .lower()
            )

            field_name = (
                field.get("name")
                or field.get("id")
                or ""
            )

            inputs.append({
                "type": field_type,
                "name": field_name
            })

        password_fields = [
            field
            for field in inputs
            if field["type"] == "password"
        ]

        email_fields = [
            field
            for field in inputs
            if field["type"] == "email"
        ]

        results.append({

            "form_number": index,

            "method": method,

            "action": action,

            "destination": destination,

            "same_domain": is_same_domain(
                page_url,
                destination
            ),

            "password_fields":
                len(password_fields),

            "email_fields":
                len(email_fields),

            "inputs": inputs
        })

    return results


def inspect_links(soup, page_url):
    """
    Analyze links and identify external domains.
    """

    internal_links = []
    external_links = []
    suspicious_links = []

    page_domain = get_domain(page_url)

    for link in soup.find_all(
        "a",
        href=True
    ):

        href = link.get("href", "").strip()

        if not href:
            continue

        # Ignore JavaScript and anchors
        if href.startswith(
            ("javascript:", "#", "mailto:", "tel:")
        ):
            continue

        absolute_url = urljoin(
            page_url,
            href
        )

        link_domain = get_domain(
            absolute_url
        )

        if not link_domain:
            continue

        link_data = {
            "url": absolute_url,
            "domain": link_domain,
            "text": link.get_text(
                " ",
                strip=True
            )[:150]
        }

        if link_domain == page_domain:

            internal_links.append(
                link_data
            )

        else:

            external_links.append(
                link_data
            )

            # Basic suspicious URL indicators
            lower_url = absolute_url.lower()

            suspicious_patterns = [
                "login",
                "verify",
                "account",
                "secure",
                "password",
                "confirm"
            ]

            if any(
                pattern in lower_url
                for pattern in suspicious_patterns
            ):

                suspicious_links.append(
                    link_data
                )

    return {
        "internal": internal_links,
        "external": external_links,
        "suspicious": suspicious_links
    }


def inspect_scripts(soup, page_url):
    """
    Identify external JavaScript sources.
    """

    external_scripts = []

    page_domain = get_domain(
        page_url
    )

    for script in soup.find_all(
        "script",
        src=True
    ):

        src = script.get(
            "src",
            ""
        ).strip()

        if not src:
            continue

        absolute_url = urljoin(
            page_url,
            src
        )

        script_domain = get_domain(
            absolute_url
        )

        if (
            script_domain
            and script_domain != page_domain
        ):

            external_scripts.append({
                "url": absolute_url,
                "domain": script_domain
            })

    return external_scripts


def inspect_iframes(soup, page_url):
    """
    Identify iframe sources and whether they are external.
    """

    results = []

    page_domain = get_domain(
        page_url
    )

    for iframe in soup.find_all(
        "iframe",
        src=True
    ):

        src = iframe.get(
            "src",
            ""
        ).strip()

        if not src:
            continue

        absolute_url = urljoin(
            page_url,
            src
        )

        iframe_domain = get_domain(
            absolute_url
        )

        results.append({

            "url": absolute_url,

            "domain": iframe_domain,

            "external": (
                iframe_domain != page_domain
                if iframe_domain
                else False
            )
        })

    return results


def detect_suspicious_keywords(
    soup
):
    """
    Search visible website text for common
    phishing/scam-related phrases.
    """

    text = soup.get_text(
        " ",
        strip=True
    ).lower()

    found = []

    for keyword in SUSPICIOUS_KEYWORDS:

        if keyword.lower() in text:

            found.append(keyword)

    return sorted(
        set(found)
    )


def detect_brand_claims(soup):
    """
    Try to identify brands mentioned in visible text.

    This is NOT the final brand-verification system.
    We will connect this to the verified website
    database later.
    """

    text = soup.get_text(
        " ",
        strip=True
    )

    known_brands = [
        "paypal",
        "google",
        "facebook",
        "microsoft",
        "apple",
        "amazon",
        "twitter",
        "linkedin",
        "instagram",
        "netflix",
        "github",
        "bank"
    ]

    found = []

    lower_text = text.lower()

    for brand in known_brands:

        if brand in lower_text:

            found.append(
                brand
            )

    return sorted(
        set(found)
    )


def deep_inspect_website(
    html,
    page_url
):
    """
    Perform complete Phase 2 HTML inspection.
    """

    soup = BeautifulSoup(
        html,
        "html.parser"
    )

    forms = inspect_forms(
        soup,
        page_url
    )

    links = inspect_links(
        soup,
        page_url
    )

    scripts = inspect_scripts(
        soup,
        page_url
    )

    iframes = inspect_iframes(
        soup,
        page_url
    )

    suspicious_keywords = (
        detect_suspicious_keywords(
            soup
        )
    )

    brand_claims = detect_brand_claims(
        soup
    )

    # --------------------------------------------------------
    # Evidence generation
    # --------------------------------------------------------

    evidence = []

    # Login/password evidence
    password_count = sum(
        form["password_fields"]
        for form in forms
    )

    if password_count > 0:

        evidence.append({
            "type": "warning",
            "category": "credential_collection",
            "message": (
                "The website contains "
                "password input fields."
            )
        })

    # External form evidence
    for form in forms:

        if not form["same_domain"]:

            evidence.append({
                "type": "danger",
                "category": "external_form",
                "message": (
                    "A form submits data to "
                    "a different domain."
                ),
                "destination":
                    form["destination"]
            })

    # External links
    if len(links["external"]) > 0:

        evidence.append({
            "type": "info",
            "category": "external_links",
            "message": (
                f"The page contains "
                f"{len(links['external'])} "
                "external links."
            )
        })

    # Suspicious links
    if len(links["suspicious"]) > 0:

        evidence.append({
            "type": "warning",
            "category": "suspicious_links",
            "message": (
                "The website contains "
                "links related to login, "
                "verification or account activity."
            )
        })

    # External scripts
    if len(scripts) > 0:

        evidence.append({
            "type": "info",
            "category": "external_scripts",
            "message": (
                f"The website loads "
                f"{len(scripts)} external scripts."
            )
        })

    # Iframes
    external_iframes = [
        iframe
        for iframe in iframes
        if iframe["external"]
    ]

    if external_iframes:

        evidence.append({
            "type": "warning",
            "category": "external_iframe",
            "message": (
                "The website contains "
                "externally hosted iframe content."
            )
        })

    # Suspicious language
    if suspicious_keywords:

        evidence.append({
            "type": "warning",
            "category": "suspicious_language",
            "message": (
                "Potentially suspicious "
                "security/account language "
                "was detected."
            ),
            "keywords":
                suspicious_keywords
        })

    # Brand claims
    if brand_claims:

        evidence.append({
            "type": "info",
            "category": "brand_detection",
            "message": (
                "Possible brand names were "
                "detected in the website content."
            ),
            "brands":
                brand_claims
        })

    return {

        "forms": forms,

        "links": {
            "internal_count":
                len(links["internal"]),

            "external_count":
                len(links["external"]),

            "suspicious_count":
                len(links["suspicious"]),

            "external":
                links["external"],

            "suspicious":
                links["suspicious"]
        },

        "scripts": {
            "external_count":
                len(scripts),

            "external":
                scripts
        },

        "iframes": {

            "total":
                len(iframes),

            "external":
                external_iframes
        },

        "suspicious_keywords":
            suspicious_keywords,

        "brand_claims":
            brand_claims,

        "evidence":
            evidence
    }