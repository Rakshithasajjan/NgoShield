"""Maps each check to simplified ISO 27001:2022 Annex A and CIS Controls v8 references."""
from .models import Finding

CONTROLS = {
    "spf": ["ISO 27001:2022 A.8.20 Network security", "CIS v8 9.5 Email authentication"],
    "dmarc": ["ISO 27001:2022 A.5.14 Information transfer", "CIS v8 9.5 Email authentication"],
    "dkim": ["ISO 27001:2022 A.5.14 Information transfer", "CIS v8 9.5 Email authentication"],
    "caa": ["ISO 27001:2022 A.8.24 Use of cryptography"],
    "tls_cert": ["ISO 27001:2022 A.8.24 Use of cryptography", "CIS v8 3.10 Encrypt data in transit"],
    "tls_version": ["ISO 27001:2022 A.8.24 Use of cryptography", "CIS v8 3.10 Encrypt data in transit"],
    "https_redirect": ["ISO 27001:2022 A.8.20 Network security", "CIS v8 3.10 Encrypt data in transit"],
    "hsts": ["ISO 27001:2022 A.8.9 Configuration management", "CIS v8 4.1 Secure configuration"],
    "csp": ["ISO 27001:2022 A.8.26 Application security requirements", "CIS v8 16.1 Secure application development"],
    "xcto": ["ISO 27001:2022 A.8.9 Configuration management", "CIS v8 4.1 Secure configuration"],
    "clickjacking": ["ISO 27001:2022 A.8.26 Application security requirements"],
    "referrer": ["ISO 27001:2022 A.8.9 Configuration management"],
    "disclosure": ["ISO 27001:2022 A.8.9 Configuration management", "CIS v8 4.1 Secure configuration"],
}


def finding(id, title, status, severity, detail, fix=""):
    return Finding(id, title, status, severity, detail, fix, CONTROLS.get(id, []))
