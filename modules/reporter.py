# modules/reporter.py
# saves scan results to disk — JSON and Markdown only.
# no HTML — terminal output IS the report.
# JSON = raw data for tools/scripts
# Markdown = human readable, good for bug bounty notes

import os
import json
from datetime import datetime
from pathlib import Path


# ══════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════

def safe(val, fallback="—"):
    """safely converts any value to a display string"""
    if val is None:          return fallback
    if isinstance(val, list):
        return ", ".join(str(v) for v in val) if val else fallback
    s = str(val).strip()
    return s if s else fallback

def count_sev(hints, sev):
    """counts hints of a specific severity level"""
    return sum(1 for h in hints if h.get("severity") == sev)

def sev_emoji(sev):
    """emoji for each severity level"""
    return {
        "Critical": "💀",
        "High":     "🔴",
        "Medium":   "🟡",
        "Low":      "🔵",
        "Info":     "⚪",
    }.get(sev, "⚪")


# ══════════════════════════════════════════════════════
#  JSON REPORT
# ══════════════════════════════════════════════════════

def build_json(results, config):
    """
    builds a clean JSON report.
    includes everything — good for piping into
    other tools or writing custom scripts against.
    """

    hints = results.get("vuln_hints", [])

    report = {
        "tool":    "ReconX v1.0",
        "target":  results.get("domain", ""),
        "ip":      results.get("ip", ""),
        "server":  results.get("server", ""),
        "scanned": datetime.now().isoformat(),

        # summary numbers
        "summary": {
            "critical":     count_sev(hints, "Critical"),
            "high":         count_sev(hints, "High"),
            "medium":       count_sev(hints, "Medium"),
            "low":          count_sev(hints, "Low"),
            "total_hints":  len(hints),
            "subdomains":   len(results.get("subdomains", [])),
            "open_ports":   len(results.get("open_ports", [])),
            "js_secrets":   len(results.get("js_secrets", [])),
            "emails":       len(results.get("emails", [])),
            "takeovers":    len(results.get("takeovers", [])),
            "chains":       len(results.get("chains", [])),
        },

        # analysis results
        "waf":           results.get("waf", []),
        "tech_stack":    results.get("tech_stack", []),
        "vuln_hints":    hints,
        "attack_chains": results.get("chains", []),
        "takeovers":     results.get("takeovers", []),

        # passive recon
        "whois":        results.get("whois", {}),
        "dns_records":  results.get("dns_records", {}),
        "geo_asn":      results.get("geo_asn", {}),
        "shodan":       results.get("shodan", {}),
        "crtsh_subs":   results.get("crtsh", {}).get("subdomains", []),

        # active recon
        "subdomains":    results.get("subdomains", []),
        "js_secrets":    results.get("js_secrets", []),
        "js_endpoints":  results.get("js_endpoints", []),
        "emails":        results.get("emails", []),

        # services
        "open_ports":    results.get("open_ports", []),
        "banners":       results.get("banners", []),
        "http_services": results.get("http_services", []),
    }

    return json.dumps(report, indent=2, default=str)


# ══════════════════════════════════════════════════════
#  MARKDOWN REPORT
# ══════════════════════════════════════════════════════

def build_markdown(results, config):
    """
    builds a clean Markdown report.
    follows the same pipeline order as terminal output:
    passive → active → services → analysis.
    good for: HackerOne reports, pentest notes, GitHub issues.
    """

    domain = results.get("domain", "unknown")
    hints  = results.get("vuln_hints", [])
    chains = results.get("chains", [])
    lines  = []
    a      = lines.append  # shortcut for append

    # ── header ─────────────────────────────────────────
    a(f"# ReconX Report — `{domain}`\n")
    a(f"| Field | Value |")
    a(f"|---|---|")
    a(f"| Target | `{domain}` |")
    a(f"| IP | `{results.get('ip','?')}` |")
    a(f"| Server | {safe(results.get('server'))} |")
    a(f"| WAF | {', '.join(results.get('waf',[])) or 'None'} |")
    a(f"| Tech | {', '.join(results.get('tech_stack',[])) or 'Unknown'} |")
    a(f"| Date | {datetime.now().strftime('%Y-%m-%d %H:%M')} |")
    a(f"| HTTPS | {'Yes' if results.get('https') else 'No'} |\n")

    # ── severity summary ───────────────────────────────
    a("---\n")
    a("## Summary\n")
    a("| Severity | Count |")
    a("|---|---|")
    for sev in ["Critical","High","Medium","Low","Info"]:
        a(f"| {sev_emoji(sev)} **{sev}** | {count_sev(hints, sev)} |")
    a(f"\n"
      f"- **Total hints:** {len(hints)}\n"
      f"- **Subdomains:** {len(results.get('subdomains',[]))}\n"
      f"- **Open ports:** {len(results.get('open_ports',[]))}\n"
      f"- **JS secrets:** {len(results.get('js_secrets',[]))}\n"
      f"- **Attack chains:** {len(chains)}\n"
      f"- **Takeovers:** {len(results.get('takeovers',[]))}\n")

    # ── passive recon ──────────────────────────────────
    a("---\n")
    a("## 🔎 Passive Recon\n")

    # WHOIS
    whois = results.get("whois", {})
    if whois and not whois.get("error"):
        a("### WHOIS\n")
        a(f"- **Registrar:** {safe(whois.get('registrar'))}")
        a(f"- **Created:** {safe(whois.get('created'))}")
        a(f"- **Expires:** {safe(whois.get('expires'))}")
        a(f"- **Org:** {safe(whois.get('registrant_org'))}")
        a(f"- **Country:** {safe(whois.get('registrant_country'))}")
        ns = whois.get("name_servers", [])
        if ns:
            a(f"- **Name Servers:** {', '.join(ns[:4])}")
        a("")

    # DNS
    dns = results.get("dns_records", {})
    if dns:
        a("### DNS Records\n")
        for rtype in ["A","AAAA","MX","NS","TXT","CNAME"]:
            records = dns.get(rtype, [])
            if not records:
                continue
            vals = []
            for r in records[:4]:
                if isinstance(r, dict):
                    vals.append(f"[{r.get('priority','')}] {r.get('host','')}")
                else:
                    vals.append(str(r)[:80])
            a(f"- **{rtype}:** {' · '.join(vals)}")

        # interesting TXT
        interesting = dns.get("interesting_txt", [])
        if interesting:
            services = [i.get("service","") for i in interesting]
            a(f"\n**Services in TXT:** {', '.join(services)}")

        # warnings
        has_spf   = any("SPF"   in i.get("service","") for i in interesting)
        has_dmarc = any("DMARC" in i.get("service","") for i in interesting)
        if not has_spf:
            a("\n> ⚠️ **No SPF record** — email spoofing possible")
        if not has_dmarc:
            a("> ⚠️ **No DMARC record** — phishing risk")
        a("")

    # Geo
    geo = results.get("geo_asn", {})
    if geo and not geo.get("error"):
        a("### Geo / ASN\n")
        a(f"- **Country:** {safe(geo.get('country'))} ({safe(geo.get('country_code'))})")
        a(f"- **City:** {safe(geo.get('city'))}")
        a(f"- **ISP:** {safe(geo.get('isp'))}")
        a(f"- **ASN:** {safe(geo.get('asn'))}")
        a(f"- **Hosting IP:** {'Yes' if geo.get('hosting') else 'No'}\n")

    # crt.sh
    crt_subs = results.get("crtsh", {}).get("subdomains", [])
    if crt_subs:
        a("### crt.sh Subdomains\n")
        a(f"Found **{len(crt_subs)}** subdomains in certificate logs:\n")
        for s in crt_subs[:30]:
            a(f"- `{s}`")
        if len(crt_subs) > 30:
            a(f"\n_...and {len(crt_subs)-30} more_")
        a("")

    # Shodan
    shodan = results.get("shodan", {})
    if shodan and not shodan.get("skipped") and not shodan.get("error"):
        a("### Shodan\n")
        vulns = shodan.get("vulns", [])
        ports = shodan.get("ports", [])
        if ports:
            a(f"- **Ports:** {', '.join(str(p) for p in ports[:10])}")
        if vulns:
            a(f"- **CVEs:** {', '.join(vulns[:5])}")
        a("")

    # ── active recon ───────────────────────────────────
    a("---\n")
    a("## 🎯 Active Recon\n")

    # subdomains
    bf        = results.get("subdomain_bruteforce", {})
    live      = bf.get("live", [])
    takeovers = results.get("takeovers", [])

    a(f"### Subdomains — {len(live)} live / {bf.get('total_tried',0)} tried\n")

    # takeovers first
    if takeovers:
        a("#### ⚑ Takeovers\n")
        for t in takeovers:
            a(f"- **`{t.get('subdomain','')}`** → {t.get('service','')} — "
              f"register this service to claim the subdomain")
        a("")

    if live:
        a("| Subdomain | Status | Title | Server |")
        a("|---|---|---|---|")
        for s in live[:40]:
            name   = s.get("subdomain","")
            status = s.get("status","—")
            title  = (s.get("title") or "—")[:35]
            server = (s.get("server") or "—")[:20]
            a(f"| `{name}` | {status} | {title} | {server} |")
        if len(live) > 40:
            a(f"\n_...and {len(live)-40} more_")
        a("")

    # JS secrets
    secrets = results.get("js_secrets", [])
    if secrets:
        a(f"### JS Secrets — {len(secrets)} found\n")
        for s in secrets:
            val    = s.get("value","")
            masked = val[:6]+"..." if len(val)>6 else val
            a(f"- **{s.get('type','')}:** `{masked}`  "
              f"_{s.get('file','')[-50:]}_")
        a("")

    # API endpoints
    endpoints = results.get("js_endpoints", [])
    if endpoints:
        a(f"### API Endpoints — {len(endpoints)} found\n")
        for ep in endpoints[:30]:
            a(f"- `{ep}`")
        if len(endpoints) > 30:
            a(f"\n_...and {len(endpoints)-30} more_")
        a("")

    # emails
    emails = results.get("emails", [])
    if emails:
        a(f"### Emails — {len(emails)} harvested\n")
        for e in emails[:20]:
            a(f"- `{e}`")
        a("")

    # ── service discovery ──────────────────────────────
    a("---\n")
    a("## 🔌 Service Discovery\n")

    # open ports
    ports = results.get("open_ports", [])
    if ports:
        a(f"### Open Ports — {len(ports)} found\n")
        a("| Host | Port | Service | Note |")
        a("|---|---|---|---|")
        int_ports = {2375,6379,27017,9200,5984,6443,
                     3389,23,11211,5900}
        for p in ports:
            note = "⚠️ Sensitive" if p.get("port") in int_ports else ""
            a(f"| `{p.get('host','')}` | `{p.get('port','')}` | "
              f"{p.get('service','')} | {note} |")
        a("")

    # banners
    banners = results.get("banners", [])
    useful  = [b for b in banners if b.get("version")]
    if useful:
        a(f"### Service Banners\n")
        for b in useful[:10]:
            a(f"- `{b.get('host','')}:{b.get('port','')}` — "
              f"**{b.get('version','?')}**"
              + (f" — SSL: {b.get('ssl_subject','')}"
                 if b.get("ssl_subject") else ""))
        a("")

    # HTTP services
    http = results.get("http_services", [])
    if http:
        a(f"### HTTP Services — {len(http)} found\n")
        a("| URL | Status | Title | Flags |")
        a("|---|---|---|---|")
        for svc in http:
            flags = []
            if svc.get("is_admin"):  flags.append("Admin")
            if svc.get("is_login"):  flags.append("Login")
            missing = len(svc.get("missing_headers", []))
            if missing:              flags.append(f"-{missing} headers")
            a(f"| {svc.get('url','')} | {svc.get('status','')} | "
              f"{(svc.get('title') or '—')[:35]} | "
              f"{', '.join(flags) or '—'} |")
        a("")

    # ── analysis ───────────────────────────────────────
    a("---\n")
    a("## 🧠 Analysis Engine\n")

    # vuln hints
    if hints:
        a(f"### Vulnerability Hints — {len(hints)} triggered\n")
        for h in hints:
            emoji = sev_emoji(h["severity"])
            a(f"#### {emoji} [{h['severity']}] {h['title']}")
            a(f"- **ID:** `{h.get('id','')}`")
            a(f"- **Detail:** {h.get('detail','')}\n")
    else:
        a("### Vulnerability Hints\n_None triggered._\n")

    # attack chains
    if chains:
        a(f"### Attack Chains — {len(chains)} identified\n")
        for c in chains:
            sev   = c.get("severity","High")
            emoji = sev_emoji(sev)
            a(f"#### {emoji} {c['title']}\n")
            for step in c.get("steps", []):
                a(f"{step}  ")
            comps = c.get("components", [])
            if comps:
                a(f"\n**Components:** {', '.join(comps)}")
            a("")
    else:
        a("### Attack Chains\n_None identified._\n")

    # ── what to do next ────────────────────────────────
    a("---\n")
    a("## 🗺️ What to do next\n")

    takeovers_list = results.get("takeovers", [])
    js_secs        = results.get("js_secrets", [])
    open_ports_l   = results.get("open_ports", [])
    dns_r          = results.get("dns_records", {})
    interesting_t  = dns_r.get("interesting_txt", [])
    has_spf_m      = any("SPF"   in i.get("service","") for i in interesting_t)
    has_dmarc_m    = any("DMARC" in i.get("service","") for i in interesting_t)
    admin_svcs     = [s for s in results.get("http_services",[])
                      if s.get("is_admin")]
    sensitive_p    = [p for p in open_ports_l
                      if p.get("port") in {2375,6379,27017,9200,5984,6443}]

    if takeovers_list:
        a("- 🔴 **Subdomain takeover** — claim the external service, "
          "host a page, test for cookie theft")
    if js_secs:
        a("- 🔴 **Leaked secrets** — test each key against its service "
          "(AWS CLI, Stripe API, etc.)")
    if sensitive_p:
        for p in sensitive_p[:3]:
            a(f"- 🔴 **Port {p['port']} ({p['service']})** — "
              f"test for unauthenticated access")
    if not has_spf_m or not has_dmarc_m:
        a("- 🟡 **Email spoofing** — test with `swaks` or GoPhish")
    if admin_svcs:
        a("- 🟡 **Admin panel** — test default creds, "
          "try credential stuffing")
    if endpoints:
        a("- 🟡 **API endpoints** — test for IDOR, auth bypass, "
          "data exposure in Burp Suite")
    if hints:
        a("- ⚪ **Review all vuln hints above** — "
          "manually verify each before reporting")

    a("\n---\n")
    a("_ReconX v1.0 — authorized security testing only_")

    return "\n".join(lines)


# ══════════════════════════════════════════════════════
#  MAIN — called by reconx.py
# ══════════════════════════════════════════════════════

def generate_report(results, config):
    """
    generates report files and saves to disk.
    returns dict of {format: filepath}.
    """

    domain    = results.get("domain", "target")
    fmt       = config.get("output_fmt", "json")
    outdir    = config.get("output_dir", "reports")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    Path(outdir).mkdir(parents=True, exist_ok=True)

    base = os.path.join(outdir, f"reconx_{domain}_{timestamp}")

    formats = ["json","md"] if fmt == "all" else [fmt]

    report_paths = {}

    for f in formats:
        if f == "json":
            path = base + ".json"
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(build_json(results, config))
            report_paths["json"] = path

        elif f == "md":
            path = base + ".md"
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(build_markdown(results, config))
            report_paths["md"] = path

    return report_paths
