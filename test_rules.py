from ngoshield.dns_checks import analyze_dmarc, analyze_spf
from ngoshield.header_checks import analyze_headers
from ngoshield.scanner import normalize
from ngoshield.scoring import score
from ngoshield.tls_checks import analyze_redirect, analyze_tls

NOW = 1_800_000_000  # fixed timestamp for deterministic tests


def test_spf_missing_is_high():
    f = analyze_spf([])
    assert f.status == "fail" and f.severity == "high"


def test_spf_plus_all_is_high():
    assert analyze_spf(["v=spf1 include:_spf.google.com +all"]).severity == "high"


def test_spf_strict_passes():
    assert analyze_spf(["v=spf1 include:_spf.google.com -all"]).status == "pass"


def test_dmarc_none_is_medium():
    f = analyze_dmarc(["v=DMARC1; p=none; rua=mailto:a@b.org"])
    assert f.status == "fail" and f.severity == "medium"


def test_dmarc_reject_passes():
    assert analyze_dmarc(["v=DMARC1; p=reject"]).status == "pass"


def test_headers_all_missing():
    fails = [f for f in analyze_headers({}) if f.status == "fail"]
    assert {f.id for f in fails} == {"hsts", "csp", "xcto", "clickjacking", "referrer"}


def test_headers_good_and_version_leak():
    h = {"Strict-Transport-Security": "max-age=1", "Content-Security-Policy": "default-src 'self'",
         "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer", "Server": "Apache/2.4.1"}
    fails = [f.id for f in analyze_headers(h) if f.status == "fail"]
    assert fails == ["disclosure"]


def test_tls_expired_and_old_protocol():
    cert = {"notAfter": "Jan  1 00:00:00 2020 GMT"}
    ids = {f.id: f for f in analyze_tls("TLSv1", cert, now=NOW)}
    assert ids["tls_cert"].severity == "high" and ids["tls_version"].status == "fail"


def test_tls_healthy():
    cert = {"notAfter": "Jan  1 00:00:00 2030 GMT"}
    assert all(f.status == "pass" for f in analyze_tls("TLSv1.3", cert, now=NOW))


def test_redirect():
    assert analyze_redirect(301, "https://x.org/").status == "pass"
    assert analyze_redirect(200, None).status == "fail"


def test_score_and_controls():
    fails = analyze_headers({})
    total, grade = score(fails)
    assert total < 100 and grade in "ABCDF"
    assert all(f.controls for f in fails)


def test_normalize():
    assert normalize("https://Example.ORG/path") == "example.org"
