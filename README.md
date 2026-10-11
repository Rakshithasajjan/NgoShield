# NGO Shield

A passive security posture checker for small NGOs and SMEs that cannot afford a security audit.
Give it a domain; it checks email spoofing protection, TLS, and web security headers, then produces a
plain-English HTML report with a grade, a "fix these first" list, and step-by-step fixes.
Each finding is mapped to simplified ISO 27001:2022 Annex A and CIS Controls v8 references.

## Why this exists

Small non-profits and businesses are breached through basic gaps (no SPF/DMARC, expired certificates,
missing headers), yet professional audits cost more than they can pay. I work in third-party risk
management, where I assess vendors against frameworks like ISO 27001 and SOC 2. NGO Shield turns that kind
of assessment into a free tool anyone can run and read without a security background.

## What it checks (passive only)

| Area | Checks |
|------|--------|
| Email | SPF, DMARC policy strength, DKIM (common selectors) |
| DNS | CAA record |
| TLS | Certificate validity/expiry, protocol version, HTTP to HTTPS redirect |
| Web | HSTS, CSP, X-Content-Type-Options, clickjacking protection, Referrer-Policy, version disclosure |

## Usage

```bash
pip install -r requirements.txt
python -m ngoshield yourdomain.org --i-have-permission --out report.html --json report.json
pytest
```

Open `report.html` in a browser.

## Responsible use

- Only run it on domains you own or have written permission to check. The `--i-have-permission` flag is mandatory.
- It performs only passive checks: DNS lookups, one TLS handshake, and two normal HTTP requests. No port
  scanning, fuzzing, or exploitation.

## Threat model (summary)

- **Assets protected:** an organisation's domain reputation, email channel, and visitors' browser sessions.
- **Threats addressed:** email spoofing/phishing from the domain, downgrade to plain HTTP, expired or invalid
  certificates, XSS/clickjacking exposure from missing headers, version disclosure.
- **Out of scope:** application vulnerabilities, server patching, internal networks, authentication.
- **Tool risk:** misuse for reconnaissance. Mitigated by passive-only checks and the permission flag.

## Limitations

- DKIM selectors are guessed from a common list, so absence is reported as "verify manually".
- A good grade is not proof of security. This is a baseline hygiene check, not an audit.

## Project layout

```
ngoshield/  dns_checks.py, tls_checks.py, header_checks.py   individual checks
            controls.py   mapping to ISO 27001 / CIS          scoring.py   severity scoring
            scanner.py    runs checks, isolates failures      report.py    HTML report
tests/      unit tests for all rule logic (no network needed)
```

## Roadmap

Web front end, PDF export, regional-language reports, more checks (DNSSEC, cookie flags).
