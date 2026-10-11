import http.client
import socket
import ssl
import time

from .controls import finding

UA = {"User-Agent": "ngoshield/0.1 (passive security check)"}


def analyze_tls(version, cert, now=None):
    now = now or time.time()
    days = int((ssl.cert_time_to_seconds(cert["notAfter"]) - now) // 86400)
    out = []
    if days < 0:
        out.append(finding("tls_cert", "TLS certificate validity", "fail", "high",
                           f"Certificate expired {-days} days ago. Browsers will show a warning.",
                           "Renew the certificate now and enable auto-renewal (e.g. Let's Encrypt/certbot)."))
    elif days <= 14:
        out.append(finding("tls_cert", "TLS certificate validity", "fail", "medium",
                           f"Certificate expires in {days} days.", "Renew it and enable auto-renewal."))
    else:
        out.append(finding("tls_cert", "TLS certificate validity", "pass", "info",
                           f"Valid certificate, {days} days remaining."))
    if version in ("SSLv3", "TLSv1", "TLSv1.1"):
        out.append(finding("tls_version", "TLS protocol version", "fail", "high",
                           f"Server negotiated outdated protocol {version}.",
                           "Disable TLS 1.0/1.1 and allow only TLS 1.2 and 1.3."))
    else:
        out.append(finding("tls_version", "TLS protocol version", "pass", "info", f"Negotiated {version}."))
    return out


def check_tls(host):
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                return analyze_tls(s.version(), s.getpeercert())
    except ssl.SSLCertVerificationError as e:
        return [finding("tls_cert", "TLS certificate validity", "fail", "high",
                        f"Certificate failed verification: {e.verify_message}.",
                        "Install a valid certificate issued by a trusted CA for this exact domain name.")]
    except OSError as e:
        return [finding("tls_cert", "HTTPS availability", "fail", "high",
                        f"Could not open an HTTPS connection ({e}).",
                        "Enable HTTPS on port 443 with a valid certificate.")]


def analyze_redirect(status, location):
    if status in (301, 302, 303, 307, 308) and (location or "").lower().startswith("https://"):
        return finding("https_redirect", "HTTP to HTTPS redirect", "pass", "info", "HTTP requests are redirected to HTTPS.")
    return finding("https_redirect", "HTTP to HTTPS redirect", "fail", "medium",
                   "Visitors using http:// are not automatically sent to the encrypted site.",
                   "Configure a permanent (301) redirect from HTTP to HTTPS.")


def check_redirect(host):
    try:
        conn = http.client.HTTPConnection(host, 80, timeout=8)
        conn.request("GET", "/", headers=UA)
        resp = conn.getresponse()
        return [analyze_redirect(resp.status, resp.getheader("Location"))]
    except OSError:
        return [finding("https_redirect", "HTTP to HTTPS redirect", "pass", "info",
                        "Port 80 is not open, so there is no insecure HTTP entry point.")]
