import argparse
import json

from .report import to_html
from .scanner import run_scan
from .scoring import score


def main():
    p = argparse.ArgumentParser(prog="ngoshield", description="Passive security posture check for small orgs.")
    p.add_argument("domain")
    p.add_argument("--i-have-permission", action="store_true",
                   help="Confirm you own this domain or have written permission to check it.")
    p.add_argument("--out", default="report.html")
    p.add_argument("--json", dest="json_out", default=None)
    a = p.parse_args()
    if not a.i_have_permission:
        p.error("Only scan domains you own or have permission to check. Re-run with --i-have-permission.")

    domain, findings = run_scan(a.domain)
    total, grade = score(findings)
    open(a.out, "w", encoding="utf-8").write(to_html(domain, findings))
    if a.json_out:
        json.dump([f.to_dict() for f in findings], open(a.json_out, "w"), indent=2)
    fails = [f for f in findings if f.status == "fail"]
    print(f"{domain}: grade {grade} ({total}/100), {len(fails)} issue(s). Report: {a.out}")
    for f in fails:
        print(f"  [{f.severity.upper()}] {f.title}")
