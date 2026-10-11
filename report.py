import html

from .scoring import score

ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def to_html(domain, findings):
    total, grade = score(findings)
    fails = sorted([f for f in findings if f.status == "fail"], key=lambda f: ORDER[f.severity])
    others = [f for f in findings if f.status != "fail"]
    esc = html.escape

    def row(f):
        ctrl = "<br>".join(esc(c) for c in f.controls)
        fix = f"<p><b>How to fix:</b> {esc(f.fix)}</p>" if f.fix else ""
        return (f"<div class='f {f.status} {f.severity}'><h3>{esc(f.title)} "
                f"<span>{f.severity.upper() if f.status == 'fail' else f.status.upper()}</span></h3>"
                f"<p>{esc(f.detail)}</p>{fix}<small>{ctrl}</small></div>")

    top = "".join(f"<li>{esc(f.title)}</li>" for f in fails[:3]) or "<li>Nothing urgent found.</li>"
    return f"""<!doctype html><html><head><meta charset='utf-8'><title>Security report: {esc(domain)}</title>
<style>body{{font-family:sans-serif;max-width:800px;margin:2rem auto;padding:0 1rem}}
.f{{border-left:6px solid #888;padding:.5rem 1rem;margin:.8rem 0;background:#f7f7f7}}
.f.fail.high{{border-color:#c0392b}}.f.fail.medium{{border-color:#e67e22}}.f.fail.low{{border-color:#f1c40f}}
.f.pass{{border-color:#27ae60}}h3 span{{font-size:.7em;float:right}}small{{color:#555}}
.grade{{font-size:3rem;font-weight:bold}}</style></head><body>
<h1>Security check: {esc(domain)}</h1>
<p class='grade'>{grade} <small>({total}/100)</small></p>
<h2>Fix these first</h2><ol>{top}</ol>
<h2>Issues found</h2>{''.join(row(f) for f in fails) or '<p>None.</p>'}
<h2>Checks passed / notes</h2>{''.join(row(f) for f in others)}
<p><small>Passive checks only (DNS, TLS handshake, HTTP headers). This is a basic posture check, not a full security audit.</small></p>
</body></html>"""
