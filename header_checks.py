import http.client
import re
import ssl

from .controls import finding
from .tls_checks import UA


def analyze_headers(h):
    h = {k.lower(): v for k, v in h.items()}
    out = []

    def add(id, title, ok, sev, good, bad, fix):
        out.append(finding(id, title, "pass" if ok else "fail", "info" if ok else sev, good if ok else bad, "" if ok else fix))

    add("hsts", "HSTS header", "strict-transport-security" in h, "medium",
        "HSTS is set, so browsers insist on HTTPS.",
        "No Strict-Transport-Security header; browsers can be tricked into using plain HTTP.",
        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains")
    add("csp", "Content-Security-Policy", "content-security-policy" in h, "medium",
        "A Content-Security-Policy limits what scripts can run on the site.",
        "No Content-Security-Policy; the site has less protection against injected scripts (XSS).",
        "Add a Content-Security-Policy header, starting with default-src 'self'.")
    add("xcto", "X-Content-Type-Options", h.get("x-content-type-options", "").lower() == "nosniff", "low",
        "Content-type sniffing is disabled.", "X-Content-Type-Options: nosniff is missing.",
        "Add: X-Content-Type-Options: nosniff")
    clickjack_ok = "x-frame-options" in h or "frame-ancestors" in h.get("content-security-policy", "").lower()
    add("clickjacking", "Clickjacking protection", clickjack_ok, "low",
        "Framing of the site by other sites is restricted.",
        "The site can be embedded in other pages, which enables clickjacking.",
        "Add: X-Frame-Options: DENY (or CSP frame-ancestors 'none').")
    add("referrer", "Referrer-Policy", "referrer-policy" in h, "low",
        "Referrer-Policy limits what URL data is leaked to other sites.",
        "No Referrer-Policy header.", "Add: Referrer-Policy: strict-origin-when-cross-origin")
    leaky = [f"{k}: {h[k]}" for k in ("server", "x-powered-by") if k in h and re.search(r"\d+\.\d+", h[k])]
    add("disclosure", "Software version disclosure", not leaky, "low",
        "Server does not advertise software versions.",
        f"Server reveals software versions ({'; '.join(leaky)}), helping attackers pick exploits.",
        "Hide version details in the web server configuration.")
    return out


def check_headers(host):
    ctx = ssl.create_default_context()
    conn = http.client.HTTPSConnection(host, 443, timeout=8, context=ctx)
    conn.request("GET", "/", headers=UA)
    resp = conn.getresponse()
    return analyze_headers(dict(resp.getheaders()))
