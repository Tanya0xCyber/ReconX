# modules/reporter.py
# ─────────────────────────────────────────────────────
# REPORT GENERATOR — takes all results and produces:
#   1. HTML report  → visual, colored, professional
#   2. JSON report  → raw data, machine readable
#   3. Markdown     → for GitHub issues / bug reports
#
# This is what you show to clients or in your portfolio.
# A good report separates a "script kiddie" from a
# professional pentester.
# ─────────────────────────────────────────────────────

import os
import json
from datetime import datetime
from pathlib import Path


# ══════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════

def severity_color(severity):
    """Maps severity level to a CSS color class."""
    return {
        "Critical": "critical",
        "High":     "high",
        "Medium":   "medium",
        "Low":      "low",
        "Info":     "info",
    }.get(severity, "info")


def severity_emoji(severity):
    """Maps severity to an emoji for Markdown reports."""
    return {
        "Critical": "💀",
        "High":     "🔴",
        "Medium":   "🟡",
        "Low":      "🔵",
        "Info":     "⚪",
    }.get(severity, "⚪")


def safe(val, fallback="—"):
    """
    Safely converts any value to a display string.
    Returns fallback if value is None/empty.
    """
    if val is None:
        return fallback
    if isinstance(val, list):
        return ", ".join(str(v) for v in val) if val else fallback
    if isinstance(val, dict):
        return json.dumps(val, indent=2) if val else fallback
    s = str(val).strip()
    return s if s else fallback


def count_severity(hints, severity):
    """Counts hints of a given severity level."""
    return sum(1 for h in hints if h.get("severity") == severity)


# ══════════════════════════════════════════════════════
#  HTML REPORT
# ══════════════════════════════════════════════════════

def build_html(results, config):
    """
    Builds a complete HTML report as a string.

    The HTML is self-contained — no external dependencies.
    CSS is inline so it works offline and looks the same everywhere.

    Structure:
    - Header (tool name, target, scan time)
    - Summary dashboard (cards with counts)
    - WAF + Tech stack section
    - Vulnerability hints (sorted by severity)
    - Attack chains
    - Passive recon (WHOIS, DNS, Geo)
    - Discovered assets (subdomains, ports, HTTP services)
    - JS findings (secrets, endpoints)
    - Raw JSON (collapsible)
    """

    domain     = results.get("domain", "unknown")
    scan_start = results.get("scan_start", datetime.now().isoformat())
    scan_end   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    hints      = results.get("vuln_hints", [])
    chains     = results.get("chains", [])
    tech       = results.get("tech_stack", [])
    waf        = results.get("waf", [])

    # counts for summary dashboard
    c_crit   = count_severity(hints, "Critical")
    c_high   = count_severity(hints, "High")
    c_medium = count_severity(hints, "Medium")
    c_low    = count_severity(hints, "Low")
    c_info   = count_severity(hints, "Info")

    subdomains   = results.get("subdomains", [])
    open_ports   = results.get("open_ports", [])
    http_svcs    = results.get("http_services", [])
    js_secrets   = results.get("js_secrets", [])
    js_endpoints = results.get("js_endpoints", [])
    emails       = results.get("emails", [])
    takeovers    = results.get("takeovers", [])

    # ── CSS ───────────────────────────────────────────────────────────────
    css = """
        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            line-height: 1.6;
        }

        /* ── layout ── */
        .container { max-width: 1100px; margin: 0 auto; padding: 2rem; }

        /* ── header ── */
        .header {
            background: linear-gradient(135deg, #161b22, #1f2937);
            border-bottom: 2px solid #30363d;
            padding: 2.5rem 2rem;
            margin-bottom: 2rem;
        }
        .header h1 {
            font-size: 2rem;
            font-weight: 700;
            color: #58a6ff;
            letter-spacing: -0.5px;
        }
        .header h1 span { color: #f0f6fc; }
        .header .meta {
            margin-top: 0.75rem;
            font-size: 0.9rem;
            color: #8b949e;
        }
        .header .meta strong { color: #c9d1d9; }
        .badge {
            display: inline-block;
            padding: 0.2rem 0.6rem;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 600;
            margin-left: 0.5rem;
        }
        .badge-waf    { background: #1f3a5f; color: #58a6ff; }
        .badge-nowaf  { background: #1a3a2a; color: #3fb950; }

        /* ── summary cards ── */
        .cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        .card {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 10px;
            padding: 1.25rem;
            text-align: center;
        }
        .card .num {
            font-size: 2.2rem;
            font-weight: 700;
            line-height: 1;
        }
        .card .label {
            font-size: 0.78rem;
            color: #8b949e;
            margin-top: 0.4rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .card.critical { border-color: #da3633; }
        .card.critical .num { color: #f85149; }
        .card.high      { border-color: #d29922; }
        .card.high .num  { color: #e3b341; }
        .card.medium    { border-color: #388bfd; }
        .card.medium .num{ color: #58a6ff; }
        .card.low       { border-color: #3fb950; }
        .card.low .num  { color: #3fb950; }
        .card.neutral   { border-color: #30363d; }
        .card.neutral .num { color: #c9d1d9; }

        /* ── sections ── */
        .section {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 10px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }
        .section h2 {
            font-size: 1.1rem;
            font-weight: 600;
            color: #f0f6fc;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid #30363d;
        }
        .section h2 .icon { margin-right: 0.5rem; }

        /* ── severity badges ── */
        .sev {
            display: inline-block;
            padding: 0.15rem 0.5rem;
            border-radius: 4px;
            font-size: 0.72rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .sev.critical { background: #3d1a1a; color: #f85149; border: 1px solid #da3633; }
        .sev.high     { background: #2d2000; color: #e3b341; border: 1px solid #d29922; }
        .sev.medium   { background: #0d1f3c; color: #58a6ff; border: 1px solid #388bfd; }
        .sev.low      { background: #0d2318; color: #3fb950; border: 1px solid #2ea043; }
        .sev.info     { background: #1c2128; color: #8b949e; border: 1px solid #30363d; }

        /* ── hint cards ── */
        .hint {
            background: #0d1117;
            border: 1px solid #30363d;
            border-left: 4px solid #30363d;
            border-radius: 6px;
            padding: 1rem;
            margin-bottom: 0.75rem;
        }
        .hint.critical { border-left-color: #da3633; }
        .hint.high     { border-left-color: #d29922; }
        .hint.medium   { border-left-color: #388bfd; }
        .hint.low      { border-left-color: #2ea043; }
        .hint .hint-title {
            font-weight: 600;
            color: #f0f6fc;
            margin-bottom: 0.4rem;
        }
        .hint .hint-id {
            font-size: 0.72rem;
            color: #8b949e;
            font-family: monospace;
        }
        .hint .hint-detail {
            font-size: 0.88rem;
            color: #8b949e;
            margin-top: 0.4rem;
        }

        /* ── chain cards ── */
        .chain {
            background: #0d1117;
            border: 1px solid #30363d;
            border-left: 4px solid #f85149;
            border-radius: 6px;
            padding: 1rem;
            margin-bottom: 0.75rem;
        }
        .chain .chain-title {
            font-weight: 600;
            color: #f85149;
            margin-bottom: 0.5rem;
        }
        .chain ol {
            margin-left: 1.2rem;
            font-size: 0.88rem;
            color: #8b949e;
        }
        .chain ol li { margin-bottom: 0.2rem; }

        /* ── tables ── */
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.88rem;
        }
        th {
            background: #0d1117;
            color: #8b949e;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.72rem;
            letter-spacing: 0.5px;
            padding: 0.6rem 0.75rem;
            text-align: left;
            border-bottom: 1px solid #30363d;
        }
        td {
            padding: 0.5rem 0.75rem;
            border-bottom: 1px solid #21262d;
            color: #c9d1d9;
            vertical-align: top;
        }
        tr:last-child td { border-bottom: none; }
        tr:hover td { background: #1c2128; }
        .mono { font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.82rem; }

        /* ── tag pills ── */
        .pill {
            display: inline-block;
            padding: 0.1rem 0.5rem;
            background: #21262d;
            border: 1px solid #30363d;
            border-radius: 20px;
            font-size: 0.75rem;
            color: #c9d1d9;
            margin: 0.1rem;
        }
        .pill.red  { background: #3d1a1a; border-color: #da3633; color: #f85149; }
        .pill.blue { background: #0d1f3c; border-color: #388bfd; color: #58a6ff; }
        .pill.grn  { background: #0d2318; border-color: #2ea043; color: #3fb950; }

        /* ── collapsible raw JSON ── */
        details { margin-top: 0.5rem; }
        summary {
            cursor: pointer;
            color: #58a6ff;
            font-size: 0.88rem;
            padding: 0.4rem 0;
        }
        summary:hover { color: #79c0ff; }
        pre {
            background: #0d1117;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 1rem;
            font-size: 0.78rem;
            overflow-x: auto;
            color: #c9d1d9;
            font-family: 'SF Mono', 'Fira Code', monospace;
            margin-top: 0.5rem;
            max-height: 400px;
            overflow-y: auto;
        }

        /* ── footer ── */
        .footer {
            text-align: center;
            padding: 2rem;
            color: #8b949e;
            font-size: 0.82rem;
            border-top: 1px solid #30363d;
            margin-top: 2rem;
        }
        .footer strong { color: #58a6ff; }

        /* ── empty state ── */
        .empty {
            color: #8b949e;
            font-size: 0.88rem;
            padding: 0.5rem 0;
            font-style: italic;
        }

        /* ── whois grid ── */
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 0.75rem;
        }
        .info-item .key {
            font-size: 0.72rem;
            color: #8b949e;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 0.2rem;
        }
        .info-item .val {
            font-size: 0.9rem;
            color: #f0f6fc;
            font-family: monospace;
        }
    """

    # ── build HTML sections ───────────────────────────────────────────────

    def make_hint_cards(hints):
        """renders each vuln hint as a colored card"""
        if not hints:
            return '<p class="empty">No vulnerability hints triggered.</p>'
        html = ""
        for h in hints:
            sc = severity_color(h["severity"])
            html += f"""
            <div class="hint {sc}">
                <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.3rem">
                    <span class="sev {sc}">{h['severity']}</span>
                    <span class="hint-id">{h['id']}</span>
                </div>
                <div class="hint-title">{h['title']}</div>
                <div class="hint-detail">{h['detail']}</div>
            </div>"""
        return html

    def make_chain_cards(chains):
        """renders each attack chain as a card with steps"""
        if not chains:
            return '<p class="empty">No attack chains identified.</p>'
        html = ""
        for c in chains:
            sc   = severity_color(c.get("severity", "High"))
            steps = "".join(f"<li>{s}</li>" for s in c.get("steps", []))
            comps = "".join(
                f'<span class="pill red">{comp}</span>'
                for comp in c.get("components", [])
            )
            html += f"""
            <div class="chain">
                <div class="chain-title">{c['title']}</div>
                <div style="margin-bottom:0.5rem">{comps}</div>
                <ol>{steps}</ol>
            </div>"""
        return html

    def make_subdomain_table(subs):
        """renders subdomain list as a table"""
        if not subs:
            return '<p class="empty">No subdomains discovered.</p>'
        rows = ""
        for s in subs[:100]:  # cap at 100 for readability
            if isinstance(s, dict):
                name   = s.get("subdomain", s.get("sub", ""))
                status = s.get("status", "—")
                title  = s.get("title", "—")
                server = s.get("server", "—")
                # color status code
                st_col = "grn" if status == 200 else "red" if status in [403,500] else ""
                rows += f"""<tr>
                    <td class="mono">{name}</td>
                    <td><span class="pill {st_col}">{status}</span></td>
                    <td>{title[:50] if title else '—'}</td>
                    <td class="mono">{server[:30] if server else '—'}</td>
                </tr>"""
            else:
                rows += f'<tr><td class="mono" colspan="4">{s}</td></tr>'
        return f"""
        <table>
            <thead><tr>
                <th>Subdomain</th><th>Status</th>
                <th>Title</th><th>Server</th>
            </tr></thead>
            <tbody>{rows}</tbody>
        </table>"""

    def make_ports_table(ports):
        """renders open ports as a table"""
        if not ports:
            return '<p class="empty">No open ports found.</p>'
        rows = ""
        from modules.services import INTERESTING_PORTS
        for p in ports:
            port    = p.get("port", "")
            service = p.get("service", "")
            host    = p.get("host", "")
            # flag interesting ports
            flag = (
                '<span class="pill red">⚠ Sensitive</span>'
                if port in INTERESTING_PORTS else ""
            )
            rows += f"""<tr>
                <td class="mono">{host}</td>
                <td class="mono">{port}</td>
                <td>{service}</td>
                <td>{flag}</td>
            </tr>"""
        return f"""
        <table>
            <thead><tr>
                <th>Host</th><th>Port</th>
                <th>Service</th><th>Flag</th>
            </tr></thead>
            <tbody>{rows}</tbody>
        </table>"""

    def make_secrets_table(secrets):
        """renders JS secrets as a table"""
        if not secrets:
            return '<p class="empty">No secrets found in JS files.</p>'
        rows = ""
        for s in secrets:
            stype = s.get("type", "")
            val   = s.get("value", "")[:80]
            furl  = s.get("file", "")
            # mask middle of secret value for report safety
            if len(val) > 20:
                masked = val[:8] + "..." + val[-6:]
            else:
                masked = val
            crit = any(
                x in stype for x in ["AWS", "Private", "Stripe Live", "Firebase"]
            )
            flag = '<span class="pill red">Critical</span>' if crit else ""
            rows += f"""<tr>
                <td>{stype} {flag}</td>
                <td class="mono">{masked}</td>
                <td class="mono" style="font-size:0.75rem;color:#8b949e">
                    {furl[-60:] if furl else '—'}
                </td>
            </tr>"""
        return f"""
        <table>
            <thead><tr>
                <th>Type</th><th>Value (masked)</th><th>Found In</th>
            </tr></thead>
            <tbody>{rows}</tbody>
        </table>"""

    def make_whois_grid(whois):
        """renders WHOIS info as a grid of key-value pairs"""
        if not whois:
            return '<p class="empty">No WHOIS data.</p>'
        fields = [
            ("Registrar",    whois.get("registrar")),
            ("Created",      whois.get("created")),
            ("Expires",      whois.get("expires")),
            ("Updated",      whois.get("updated")),
            ("Org",          whois.get("registrant_org")),
            ("Country",      whois.get("registrant_country")),
        ]
        items = ""
        for key, val in fields:
            items += f"""
            <div class="info-item">
                <div class="key">{key}</div>
                <div class="val">{safe(val)}</div>
            </div>"""

        ns = whois.get("name_servers", [])
        if ns:
            ns_pills = "".join(
                f'<span class="pill">{n}</span>' for n in ns[:6]
            )
            items += f"""
            <div class="info-item" style="grid-column:1/-1">
                <div class="key">Name Servers</div>
                <div class="val">{ns_pills}</div>
            </div>"""

        return f'<div class="info-grid">{items}</div>'

    def make_dns_section(dns):
        """renders DNS records section"""
        if not dns:
            return '<p class="empty">No DNS data.</p>'
        html = ""
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "CAA"]
        for rtype in record_types:
            records = dns.get(rtype, [])
            if not records:
                continue
            html += f'<div style="margin-bottom:0.75rem">'
            html += f'<div class="key" style="color:#8b949e;font-size:0.72rem;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:0.3rem">{rtype}</div>'
            for rec in records:
                if isinstance(rec, dict):
                    # MX records have priority + host
                    val = f"[{rec.get('priority','')}] {rec.get('host','')}"
                else:
                    val = str(rec)
                html += f'<div class="mono" style="font-size:0.85rem;color:#c9d1d9;padding:0.1rem 0">{val}</div>'
            html += "</div>"

        # interesting TXT records
        interesting = dns.get("interesting_txt", [])
        if interesting:
            html += '<div style="margin-top:0.75rem">'
            html += '<div class="key" style="color:#8b949e;font-size:0.72rem;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:0.3rem">Interesting TXT</div>'
            for item in interesting:
                html += f'<span class="pill blue">{item["service"]}</span>'
            html += "</div>"

        return html

    # ── WAF + tech pills ──────────────────────────────────────────────────
    waf_html = "".join(
        f'<span class="pill red">{w}</span>' for w in waf
    ) or '<span class="pill grn">None detected</span>'

    tech_html = "".join(
        f'<span class="pill blue">{t}</span>' for t in tech
    ) or '<span class="empty">Could not fingerprint stack</span>'

    # ── HTTP services table ───────────────────────────────────────────────
    http_services = results.get("http_services", [])
    http_rows = ""
    for svc in http_services:
        url    = svc.get("url", "")
        status = svc.get("status", "")
        title  = svc.get("title", "") or "—"
        server = svc.get("server", "") or "—"
        admin  = "⚠ Admin" if svc.get("is_admin") else ""
        login  = "🔐 Login" if svc.get("is_login") else ""
        http_rows += f"""<tr>
            <td><a href="{url}" style="color:#58a6ff">{url}</a></td>
            <td><span class="pill">{status}</span></td>
            <td>{title[:50]}</td>
            <td class="mono">{server[:30]}</td>
            <td>{admin} {login}</td>
        </tr>"""

    http_table = f"""
    <table>
        <thead><tr>
            <th>URL</th><th>Status</th>
            <th>Title</th><th>Server</th><th>Flags</th>
        </tr></thead>
        <tbody>{http_rows if http_rows else '<tr><td colspan="5" class="empty">No HTTP services found</td></tr>'}</tbody>
    </table>""" if http_services else '<p class="empty">No HTTP services probed.</p>'

    # ── geo info ──────────────────────────────────────────────────────────
    geo  = results.get("geo_asn", {})
    whois_data = results.get("whois", {})

    geo_html = ""
    if geo and not geo.get("error"):
        geo_html = f"""
        <div class="info-grid">
            <div class="info-item">
                <div class="key">IP</div>
                <div class="val">{safe(geo.get('ip'))}</div>
            </div>
            <div class="info-item">
                <div class="key">Country</div>
                <div class="val">{safe(geo.get('country'))} ({safe(geo.get('country_code'))})</div>
            </div>
            <div class="info-item">
                <div class="key">City</div>
                <div class="val">{safe(geo.get('city'))}</div>
            </div>
            <div class="info-item">
                <div class="key">ISP</div>
                <div class="val">{safe(geo.get('isp'))}</div>
            </div>
            <div class="info-item">
                <div class="key">ASN</div>
                <div class="val">{safe(geo.get('asn'))}</div>
            </div>
            <div class="info-item">
                <div class="key">Hosting IP</div>
                <div class="val">{'Yes' if geo.get('hosting') else 'No'}</div>
            </div>
        </div>"""

    # ── emails ────────────────────────────────────────────────────────────
    email_html = "".join(
        f'<span class="pill">{e}</span>' for e in emails[:30]
    ) or '<p class="empty">No emails harvested.</p>'

    # ── endpoints ────────────────────────────────────────────────────────
    ep_html = "".join(
        f'<span class="pill mono">{ep}</span>'
        for ep in js_endpoints[:50]
    ) or '<p class="empty">No API endpoints extracted from JS.</p>'

    # ── takeovers ────────────────────────────────────────────────────────
    takeover_html = ""
    if takeovers:
        for t in takeovers:
            takeover_html += f"""
            <div class="hint critical">
                <div style="display:flex;align-items:center;gap:0.75rem">
                    <span class="sev critical">Critical</span>
                    <strong style="color:#f85149">TAKEOVER: {t.get('subdomain','')}</strong>
                </div>
                <div class="hint-detail">
                    Service: {t.get('service','')} — 
                    Claim this service to take control of the subdomain.
                </div>
            </div>"""
    else:
        takeover_html = '<p class="empty">No subdomain takeovers detected.</p>'

    # ── shodan ────────────────────────────────────────────────────────────
    shodan     = results.get("shodan", {})
    shodan_html = ""
    if shodan and not shodan.get("skipped") and not shodan.get("error"):
        vulns = shodan.get("vulns", [])
        if vulns:
            shodan_html = "".join(
                f'<span class="pill red">{v}</span>' for v in vulns
            )
        else:
            shodan_html = '<span class="pill grn">No CVEs in Shodan</span>'
    else:
        shodan_html = f'<p class="empty">{shodan.get("error","Shodan not used.")}</p>'

    # ── assemble full HTML ────────────────────────────────────────────────
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ReconX Report — {domain}</title>
    <style>{css}</style>
</head>
<body>

<div class="header">
    <div class="container">
        <h1>Recon<span>X</span> &nbsp;
            <span style="font-size:1rem;font-weight:400;color:#8b949e">
                Automated Recon Report
            </span>
        </h1>
        <div class="meta">
            <strong>Target:</strong> {domain} &nbsp;|&nbsp;
            <strong>IP:</strong> {safe(results.get('ip'))} &nbsp;|&nbsp;
            <strong>Started:</strong> {scan_start[:19].replace('T',' ')} &nbsp;|&nbsp;
            <strong>Finished:</strong> {scan_end}
            &nbsp;
            {''.join(f'<span class="badge badge-waf">{w}</span>' for w in waf)
             if waf else '<span class="badge badge-nowaf">No WAF</span>'}
        </div>
    </div>
</div>

<div class="container">

    <!-- SUMMARY CARDS -->
    <div class="cards">
        <div class="card critical">
            <div class="num">{c_crit}</div>
            <div class="label">Critical</div>
        </div>
        <div class="card high">
            <div class="num">{c_high}</div>
            <div class="label">High</div>
        </div>
        <div class="card medium">
            <div class="num">{c_medium}</div>
            <div class="label">Medium</div>
        </div>
        <div class="card low">
            <div class="num">{c_low}</div>
            <div class="label">Low / Info</div>
        </div>
        <div class="card neutral">
            <div class="num">{len(subdomains)}</div>
            <div class="label">Subdomains</div>
        </div>
        <div class="card neutral">
            <div class="num">{len(open_ports)}</div>
            <div class="label">Open Ports</div>
        </div>
        <div class="card neutral">
            <div class="num">{len(js_secrets)}</div>
            <div class="label">JS Secrets</div>
        </div>
        <div class="card neutral">
            <div class="num">{len(emails)}</div>
            <div class="label">Emails</div>
        </div>
    </div>

    <!-- WAF + TECH -->
    <div class="section">
        <h2><span class="icon">🛡</span>WAF & Technology Stack</h2>
        <div style="margin-bottom:0.75rem">
            <div class="key" style="color:#8b949e;font-size:0.72rem;
                text-transform:uppercase;letter-spacing:0.5px;margin-bottom:0.4rem">
                WAF / CDN
            </div>
            {waf_html}
        </div>
        <div>
            <div class="key" style="color:#8b949e;font-size:0.72rem;
                text-transform:uppercase;letter-spacing:0.5px;margin-bottom:0.4rem">
                Tech Stack
            </div>
            {tech_html}
        </div>
    </div>

    <!-- VULNERABILITY HINTS -->
    <div class="section">
        <h2><span class="icon">🔍</span>Vulnerability Hints
            <span style="font-weight:400;font-size:0.85rem;color:#8b949e">
                ({len(hints)} triggered)
            </span>
        </h2>
        {make_hint_cards(hints)}
    </div>

    <!-- ATTACK CHAINS -->
    <div class="section">
        <h2><span class="icon">⛓</span>Attack Chains
            <span style="font-weight:400;font-size:0.85rem;color:#8b949e">
                ({len(chains)} identified)
            </span>
        </h2>
        {make_chain_cards(chains)}
    </div>

    <!-- SUBDOMAIN TAKEOVERS -->
    <div class="section">
        <h2><span class="icon">🎯</span>Subdomain Takeovers</h2>
        {takeover_html}
    </div>

    <!-- PASSIVE RECON -->
    <div class="section">
        <h2><span class="icon">🔎</span>Passive Recon</h2>

        <div style="margin-bottom:1.25rem">
            <div class="key" style="color:#8b949e;font-size:0.8rem;
                font-weight:600;margin-bottom:0.5rem">WHOIS</div>
            {make_whois_grid(whois_data)}
        </div>

        <div style="margin-bottom:1.25rem">
            <div class="key" style="color:#8b949e;font-size:0.8rem;
                font-weight:600;margin-bottom:0.5rem">DNS Records</div>
            {make_dns_section(results.get('dns_records', {}))}
        </div>

        <div style="margin-bottom:1.25rem">
            <div class="key" style="color:#8b949e;font-size:0.8rem;
                font-weight:600;margin-bottom:0.5rem">Geo / ASN</div>
            {geo_html or '<p class="empty">No geo data.</p>'}
        </div>

        <div>
            <div class="key" style="color:#8b949e;font-size:0.8rem;
                font-weight:600;margin-bottom:0.5rem">Shodan CVEs</div>
            {shodan_html}
        </div>
    </div>

    <!-- DISCOVERED ASSETS -->
    <div class="section">
        <h2><span class="icon">🌐</span>Discovered Assets</h2>

        <div style="margin-bottom:1.25rem">
            <div class="key" style="color:#8b949e;font-size:0.8rem;
                font-weight:600;margin-bottom:0.5rem">
                Subdomains ({len(subdomains)})
            </div>
            {make_subdomain_table(
                results.get('subdomain_bruteforce', {}).get('live', subdomains)
            )}
        </div>

        <div style="margin-bottom:1.25rem">
            <div class="key" style="color:#8b949e;font-size:0.8rem;
                font-weight:600;margin-bottom:0.5rem">
                Open Ports ({len(open_ports)})
            </div>
            {make_ports_table(open_ports)}
        </div>

        <div>
            <div class="key" style="color:#8b949e;font-size:0.8rem;
                font-weight:600;margin-bottom:0.5rem">
                HTTP Services ({len(http_services)})
            </div>
            {http_table}
        </div>
    </div>

    <!-- JS FINDINGS -->
    <div class="section">
        <h2><span class="icon">📜</span>JS Analysis</h2>

        <div style="margin-bottom:1.25rem">
            <div class="key" style="color:#8b949e;font-size:0.8rem;
                font-weight:600;margin-bottom:0.5rem">
                Secrets ({len(js_secrets)})
            </div>
            {make_secrets_table(js_secrets)}
        </div>

        <div style="margin-bottom:1.25rem">
            <div class="key" style="color:#8b949e;font-size:0.8rem;
                font-weight:600;margin-bottom:0.5rem">
                API Endpoints ({len(js_endpoints)})
            </div>
            {ep_html}
        </div>

        <div>
            <div class="key" style="color:#8b949e;font-size:0.8rem;
                font-weight:600;margin-bottom:0.5rem">
                Harvested Emails ({len(emails)})
            </div>
            {email_html}
        </div>
    </div>

    <!-- RAW JSON (collapsible) -->
    <div class="section">
        <h2><span class="icon">📦</span>Raw Data</h2>
        <details>
            <summary>Expand raw JSON results</summary>
            <pre>{json.dumps(results, indent=2, default=str)[:20000]}</pre>
        </details>
    </div>

</div>

<div class="footer">
    Generated by <strong>ReconX</strong> &nbsp;|&nbsp;
    Target: <strong>{domain}</strong> &nbsp;|&nbsp;
    {scan_end} &nbsp;|&nbsp;
    For authorized security testing only.
</div>

</body>
</html>"""

    return html


# ══════════════════════════════════════════════════════
#  JSON REPORT
# ══════════════════════════════════════════════════════

def build_json(results, config):
    """
    Builds a clean JSON report.
    Strips out huge raw data to keep file size reasonable.
    Focuses on the important findings.
    """

    hints  = results.get("vuln_hints", [])
    chains = results.get("chains", [])

    report = {
        "tool":    "ReconX v1.0",
        "target":  results.get("domain", ""),
        "ip":      results.get("ip", ""),
        "scanned": datetime.now().isoformat(),

        # summary numbers
        "summary": {
            "critical":    count_severity(hints, "Critical"),
            "high":        count_severity(hints, "High"),
            "medium":      count_severity(hints, "Medium"),
            "low":         count_severity(hints, "Low"),
            "info":        count_severity(hints, "Info"),
            "subdomains":  len(results.get("subdomains", [])),
            "open_ports":  len(results.get("open_ports", [])),
            "js_secrets":  len(results.get("js_secrets", [])),
            "emails":      len(results.get("emails", [])),
        },

        # key findings
        "waf":             results.get("waf", []),
        "tech_stack":      results.get("tech_stack", []),
        "vuln_hints":      hints,
        "attack_chains":   chains,
        "takeovers":       results.get("takeovers", []),
        "shodan_vulns":    results.get("shodan_vulns", []),

        # assets
        "subdomains":      results.get("subdomains", [])[:200],
        "open_ports":      results.get("open_ports", []),
        "http_services":   [
            {
                "url":      s.get("url"),
                "status":   s.get("status"),
                "title":    s.get("title"),
                "server":   s.get("server"),
                "is_admin": s.get("is_admin"),
                "is_login": s.get("is_login"),
            }
            for s in results.get("http_services", [])
        ],

        # intelligence
        "js_secrets":   results.get("js_secrets", []),
        "js_endpoints": results.get("js_endpoints", [])[:100],
        "emails":       results.get("emails", []),

        # passive recon
        "whois":        results.get("whois", {}),
        "dns_records":  results.get("dns_records", {}),
        "geo_asn":      results.get("geo_asn", {}),
    }

    return json.dumps(report, indent=2, default=str)


# ══════════════════════════════════════════════════════
#  MARKDOWN REPORT
# ══════════════════════════════════════════════════════

def build_markdown(results, config):
    """
    Builds a Markdown report.
    Useful for:
    - GitHub issues
    - HackerOne / Bugcrowd submissions
    - Notion / Obsidian notes
    - README in your pentest repo
    """

    domain  = results.get("domain", "unknown")
    hints   = results.get("vuln_hints", [])
    chains  = results.get("chains", [])
    waf     = results.get("waf", [])
    tech    = results.get("tech_stack", [])

    lines = []
    a = lines.append   # shortcut for append

    # header
    a(f"# 🔍 ReconX Report — `{domain}`\n")
    a(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ")
    a(f"**IP:** `{results.get('ip', 'unknown')}`  ")
    a(f"**WAF:** {', '.join(waf) if waf else 'None detected'}  ")
    a(f"**Tech:** {', '.join(tech) if tech else 'Unknown'}\n")
    a("---\n")

    # summary table
    a("## 📊 Summary\n")
    a("| Severity | Count |")
    a("|---|---|")
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        emoji = severity_emoji(sev)
        cnt   = count_severity(hints, sev)
        a(f"| {emoji} {sev} | {cnt} |")
    a(f"\n**Total hints:** {len(hints)}  ")
    a(f"**Subdomains:** {len(results.get('subdomains', []))}  ")
    a(f"**Open ports:** {len(results.get('open_ports', []))}  ")
    a(f"**JS secrets:** {len(results.get('js_secrets', []))}\n")
    a("---\n")

    # vulnerability hints
    a("## 🔍 Vulnerability Hints\n")
    if hints:
        for h in hints:
            emoji = severity_emoji(h["severity"])
            a(f"### {emoji} [{h['severity']}] {h['title']}")
            a(f"- **ID:** `{h['id']}`")
            a(f"- **Detail:** {h['detail']}\n")
    else:
        a("_No vulnerability hints triggered._\n")
    a("---\n")

    # attack chains
    a("## ⛓ Attack Chains\n")
    if chains:
        for c in chains:
            emoji = severity_emoji(c.get("severity", "High"))
            a(f"### {emoji} {c['title']}\n")
            for step in c.get("steps", []):
                a(f"{step}  ")
            a("")
    else:
        a("_No attack chains identified._\n")
    a("---\n")

    # passive recon
    a("## 🔎 Passive Recon\n")
    whois = results.get("whois", {})
    if whois and not whois.get("error"):
        a("### WHOIS\n")
        a(f"- **Registrar:** {safe(whois.get('registrar'))}")
        a(f"- **Created:** {safe(whois.get('created'))}")
        a(f"- **Expires:** {safe(whois.get('expires'))}")
        a(f"- **Org:** {safe(whois.get('registrant_org'))}")
        ns = whois.get("name_servers", [])
        if ns:
            a(f"- **Name Servers:** {', '.join(ns[:4])}")
        a("")

    geo = results.get("geo_asn", {})
    if geo and not geo.get("error"):
        a("### Geo / ASN\n")
        a(f"- **Country:** {safe(geo.get('country'))}")
        a(f"- **ISP:** {safe(geo.get('isp'))}")
        a(f"- **ASN:** {safe(geo.get('asn'))}\n")

    # subdomains
    subs = results.get("subdomains", [])
    a(f"## 🌐 Subdomains ({len(subs)})\n")
    if subs:
        for s in subs[:50]:
            name = s.get("subdomain", s) if isinstance(s, dict) else s
            a(f"- `{name}`")
        if len(subs) > 50:
            a(f"\n_...and {len(subs)-50} more_")
        a("")
    else:
        a("_None found._\n")

    # open ports
    ports = results.get("open_ports", [])
    a(f"## 🔌 Open Ports ({len(ports)})\n")
    if ports:
        a("| Host | Port | Service |")
        a("|---|---|---|")
        for p in ports:
            a(f"| `{p.get('host','')}` | `{p.get('port','')}` | {p.get('service','')} |")
        a("")
    else:
        a("_No open ports found._\n")

    # js secrets
    secrets = results.get("js_secrets", [])
    a(f"## 🔑 JS Secrets ({len(secrets)})\n")
    if secrets:
        for s in secrets:
            val = s.get("value", "")
            masked = val[:6] + "..." if len(val) > 6 else val
            a(f"- **{s.get('type','')}:** `{masked}` — _{s.get('file','')[-50:]}_")
        a("")
    else:
        a("_No secrets found._\n")

    # emails
    emails = results.get("emails", [])
    a(f"## 📧 Emails ({len(emails)})\n")
    if emails:
        for e in emails[:20]:
            a(f"- `{e}`")
        a("")
    else:
        a("_No emails harvested._\n")

    a("---\n")
    a("_Generated by ReconX — for authorized security testing only._")

    return "\n".join(lines)


# ══════════════════════════════════════════════════════
#  MAIN FUNCTION — called by reconx.py
# ══════════════════════════════════════════════════════

def generate_report(results, config):
    """
    Main entry point — reconx.py calls this as:
        generate_report(results, config)

    Generates whichever report formats were requested
    via the --output flag and saves them to the output dir.

    Returns a dict of {format: filepath} for each report generated.
    """

    domain    = results.get("domain", "target")
    fmt       = config.get("output_fmt", "html")
    outdir    = config.get("output_dir", "reports")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # make sure output directory exists
    Path(outdir).mkdir(parents=True, exist_ok=True)

    # base filename without extension
    base = os.path.join(outdir, f"reconx_{domain}_{timestamp}")

    report_paths = {}

    # decide which formats to generate
    # "all" means generate every format
    formats_to_generate = []
    if fmt == "all":
        formats_to_generate = ["html", "json", "md"]
    else:
        formats_to_generate = [fmt]

    # generate each requested format
    for f in formats_to_generate:

        if f == "html":
            content  = build_html(results, config)
            filepath = base + ".html"
            with open(filepath, "w", encoding="utf-8") as fh:
                fh.write(content)
            report_paths["html"] = filepath

        elif f == "json":
            content  = build_json(results, config)
            filepath = base + ".json"
            with open(filepath, "w", encoding="utf-8") as fh:
                fh.write(content)
            report_paths["json"] = filepath

        elif f == "md":
            content  = build_markdown(results, config)
            filepath = base + ".md"
            with open(filepath, "w", encoding="utf-8") as fh:
                fh.write(content)
            report_paths["md"] = filepath

    return report_paths