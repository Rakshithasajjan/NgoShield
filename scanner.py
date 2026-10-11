from urllib.parse import urlparse

from .controls import finding
from .dns_checks import check_dns
from .header_checks import check_headers
from .tls_checks import check_redirect, check_tls


def normalize(domain):
    d = domain.strip().lower()
    if "://" in d:
        d = urlparse(d).netloc
    return d.split("/")[0].split(":")[0]


def run_scan(domain):
    domain = normalize(domain)
    findings = []
    for fn in (check_dns, check_tls, check_redirect, check_headers):
        try:
            findings.extend(fn(domain))
        except Exception as e:  # one failing check must not kill the scan
            findings.append(finding(f"error_{fn.__name__}", f"{fn.__name__} could not complete", "info", "info", str(e)))
    return domain, findings
