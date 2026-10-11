import dns.resolver
from .controls import finding

DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "s1", "s2", "mail", "dkim"]


def _txt(name):
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=5)
    except Exception:
        return []
    return ["".join(p.decode("utf-8", "ignore") for p in r.strings) for r in answers]


def analyze_spf(records):
    spf = [r for r in records if r.lower().startswith("v=spf1")]
    fix = "Publish one SPF TXT record listing your mail senders and ending in -all (or ~all)."
    if not spf:
        return finding("spf", "SPF record", "fail", "high",
                       "No SPF record found. Anyone can send email pretending to be your domain.", fix)
    if len(spf) > 1:
        return finding("spf", "SPF record", "fail", "medium",
                       "Multiple SPF records found. This is invalid and receivers may ignore them.",
                       "Merge everything into a single SPF record.")
    tokens = spf[0].lower().split()
    all_token = next((t for t in tokens if t in ("+all", "-all", "~all", "?all", "all")), None)
    if all_token in ("+all", "all", "?all"):
        return finding("spf", "SPF record", "fail", "high",
                       f"SPF ends in '{all_token}', which lets any server send mail as you.",
                       "Change the ending to -all (reject) or ~all (soft fail).")
    if all_token is None:
        return finding("spf", "SPF record", "fail", "medium",
                       "SPF record has no 'all' ending, so unlisted senders are not handled.", fix)
    return finding("spf", "SPF record", "pass", "info", f"SPF present and ends with '{all_token}'.")


def analyze_dmarc(records):
    dmarc = [r for r in records if r.lower().startswith("v=dmarc1")]
    if not dmarc:
        return finding("dmarc", "DMARC policy", "fail", "high",
                       "No DMARC record found. Spoofed emails from your domain are not blocked.",
                       "Add a TXT record at _dmarc.yourdomain with: v=DMARC1; p=none; rua=mailto:you@yourdomain "
                       "then move to p=quarantine and p=reject once reports look clean.")
    tags = {}
    for part in dmarc[0].split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip().lower()
    policy = tags.get("p", "")
    if policy == "none":
        return finding("dmarc", "DMARC policy", "fail", "medium",
                       "DMARC exists but p=none only monitors; spoofed mail is still delivered.",
                       "Move to p=quarantine, then p=reject, after reviewing reports.")
    if policy in ("quarantine", "reject"):
        return finding("dmarc", "DMARC policy", "pass", "info", f"DMARC enforced with p={policy}.")
    return finding("dmarc", "DMARC policy", "fail", "medium", "DMARC record is malformed (no valid p= tag).",
                   "Fix the record syntax: v=DMARC1; p=quarantine; rua=mailto:...")


def analyze_dkim(found_selectors):
    if found_selectors:
        return finding("dkim", "DKIM signing", "pass", "info",
                       f"DKIM key found at selector(s): {', '.join(found_selectors)}.")
    return finding("dkim", "DKIM signing", "info", "info",
                   "No DKIM key found at common selectors. Your provider may use a custom selector, so verify manually.",
                   "Enable DKIM in your email provider (Google Workspace, Microsoft 365, etc.).")


def analyze_caa(has_caa):
    if has_caa:
        return finding("caa", "CAA record", "pass", "info", "CAA record limits who may issue certificates for the domain.")
    return finding("caa", "CAA record", "fail", "low",
                   "No CAA record. Any certificate authority may issue certificates for your domain.",
                   "Add a CAA record naming only the CA you use (e.g. 0 issue \"letsencrypt.org\").")


def check_dns(domain):
    found = [s for s in DKIM_SELECTORS if _txt(f"{s}._domainkey.{domain}")]
    try:
        has_caa = bool(dns.resolver.resolve(domain, "CAA", lifetime=5))
    except Exception:
        has_caa = False
    return [
        analyze_spf(_txt(domain)),
        analyze_dmarc(_txt(f"_dmarc.{domain}")),
        analyze_dkim(found),
        analyze_caa(has_caa),
    ]
