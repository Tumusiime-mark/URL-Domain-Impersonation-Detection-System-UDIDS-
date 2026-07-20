"""DIDS backend URL inspection service.

Run this locally and configure the browser app's Python Backend URL setting to point
at the running server (for example http://127.0.0.1:8000).

It supports GET /inspect?url=<url>&protected=<protected-domain>
and returns JSON with page analysis, relatedness, and phishing risk indicators.
"""

import html
import json
import re
import ssl
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, quote, urlparse, urlunparse
from urllib.request import Request, urlopen
from wsgiref.simple_server import make_server


USER_AGENT = "DIDS Backend/1.0"
PHISHING_TERMS = [
    "login",
    "password",
    "verify",
    "account",
    "secure",
    "credential",
    "reset",
    "otp",
    "authenticate",
    "security check",
    "confirm",
]


def normalize_url(raw_url):
    value = (raw_url or "").strip()
    if not value:
        raise ValueError("Missing URL")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        value = "http://" + value
    parsed = urlparse(value)
    if not parsed.netloc:
        raise ValueError("Malformed URL")
    if not parsed.scheme:
        parsed = parsed._replace(scheme="http")
    return urlunparse(parsed)


def extract_text(body):
    cleaned = re.sub(r"<script[^>]*>.*?</script>|<style[^>]*>.*?</style>|<[^>]+>", " ", body, flags=re.I | re.S)
    cleaned = html.unescape(cleaned)
    return re.sub(r"\s+", " ", cleaned).strip().lower()


def fetch_page(url, timeout=12):
    headers = {"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}
    request = Request(url, headers=headers)
    context = ssl.create_default_context()
    with urlopen(request, timeout=timeout, context=context) as response:
        status = getattr(response, "status", None) or 200
        final_url = response.geturl()
        content_type = response.headers.get("Content-Type", "")
        raw_body = response.read(320000)
        charset = response.headers.get_content_charset() or "utf-8"
    try:
        body = raw_body.decode(charset, errors="ignore")
    except (LookupError, TypeError):
        body = raw_body.decode("utf-8", errors="ignore")
    title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    title = html.unescape(title_match.group(1).strip()) if title_match else ""
    text = extract_text(body)
    return {
        "status_code": status,
        "final_url": final_url,
        "content_type": content_type,
        "title": title,
        "body": body,
        "text": text,
    }


def protected_terms(protected_domain):
    base = (protected_domain or "").strip().lower()
    tokens = set(re.split(r"[^a-z0-9]+", base))
    if "." in base:
        parts = base.split(".")
        tokens.update(parts)
        tokens.add(parts[0])
    if base:
        tokens.add(base)
    return {token for token in tokens if token and len(token) >= 2}


def classify_page(analysis, protected_domain):
    text = analysis["text"]
    url = analysis["final_url"]
    host = urlparse(url).hostname or ""
    terms = protected_terms(protected_domain)
    found = sorted({term for term in terms if term in text or term in host})
    phishing_matches = sorted({term for term in PHISHING_TERMS if term in text})
    indicators = []
    remarks = []

    if "<form" in analysis["body"].lower() and any(term in text for term in ["password", "login", "verify", "account", "credential"]):
        indicators.append("Login or credential form")
    if phishing_matches:
        indicators.append("Phishing bait terms: " + ", ".join(phishing_matches))
    if found:
        remarks.append("Page contains protected domain/brand terms: " + ", ".join(found))
    else:
        remarks.append("No protected domain or brand terms found in page or host.")

    if not found and phishing_matches:
        classification = "Likely phishing or unrelated page"
    elif found and phishing_matches:
        classification = "Related page with phishing indicators"
    elif found:
        classification = "Page appears related to the protected domain"
    else:
        classification = "Page does not appear related to the protected domain"

    return {
        "related_terms": found,
        "phishing_terms": phishing_matches,
        "indicators": indicators or ["No explicit phishing indicators detected."],
        "remarks": remarks,
        "classification": classification,
        "related": bool(found),
        "url": url,
        "protected": protected_domain,
    }


def json_response(start_response, data, status_code=200):
    payload = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
    headers = [
        ("Content-Type", "application/json; charset=utf-8"),
        ("Access-Control-Allow-Origin", "*"),
        ("Access-Control-Allow-Methods", "GET, OPTIONS"),
        ("Access-Control-Allow-Headers", "Content-Type"),
    ]
    start_response(f"{status_code} OK" if status_code == 200 else f"{status_code} Error", headers)
    return [payload]


def application(environ, start_response):
    method = environ.get("REQUEST_METHOD", "GET").upper()
    path = environ.get("PATH_INFO", "")
    if method == "OPTIONS":
        start_response("204 No Content", [
            ("Access-Control-Allow-Origin", "*"),
            ("Access-Control-Allow-Methods", "GET, OPTIONS"),
            ("Access-Control-Allow-Headers", "Content-Type"),
        ])
        return [b""]

    if path == "/":
        return json_response(start_response, {
            "service": "DIDS inspection backend",
            "inspect": "/inspect?url=<url>&protected=<domain>",
        })

    if path != "/inspect":
        return json_response(start_response, {"error": "Not found"}, status_code=404)

    query = parse_qs(environ.get("QUERY_STRING", ""))
    raw_url = query.get("url", [""])[0]
    protected = query.get("protected", [""])[0]
    if not raw_url:
        return json_response(start_response, {"error": "Missing url query parameter"}, status_code=400)

    try:
        url = normalize_url(raw_url)
    except ValueError as exc:
        return json_response(start_response, {"error": str(exc)}, status_code=400)

    try:
        page = fetch_page(url)
    except HTTPError as exc:
        return json_response(start_response, {
            "error": "HTTP error",
            "status_code": exc.code,
            "reason": str(exc),
        }, status_code=500)
    except URLError as exc:
        return json_response(start_response, {
            "error": "Unable to fetch URL",
            "reason": str(exc),
        }, status_code=502)
    except Exception as exc:
        return json_response(start_response, {
            "error": "Fetch failed",
            "reason": str(exc),
        }, status_code=500)

    classification = classify_page(page, protected)
    result = {
        "url": page["final_url"],
        "requested_url": raw_url,
        "protected": protected,
        "resolved": page["final_url"],
        "status": page["status_code"],
        "content_type": page["content_type"],
        "title": page["title"],
        "related": classification["related"],
        "classification": classification["classification"],
        "indicators": classification["indicators"],
        "remarks": classification["remarks"],
        "related_terms": classification["related_terms"],
        "phishing_terms": classification["phishing_terms"],
        "page_snippet": page["text"][:1200],
    }
    return json_response(start_response, result)


if __name__ == "__main__":
    port = 8000
    print(f"Starting DIDS backend inspection service on http://127.0.0.1:{port}")
    server = make_server("127.0.0.1", port, application)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Shutting down DIDS backend")
