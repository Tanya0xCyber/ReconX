#!/usr/bin/env python3
"""
reconx.py — main entry point
runs the full recon pipeline and shows results in terminal
"""

import argparse
import sys
import os
import time
from datetime import datetime
from pathlib import Path

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.columns import Columns
    from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
    from rich.rule import Rule
    from rich.text import Text
    from rich.box import ROUNDED, SIMPLE_HEAVY, MINIMAL_DOUBLE_HEAD
except ImportError:
    print("[!] Run: pip install rich")
    sys.exit(1)

from modules.validator import validate_target
from modules.passive   import run_passive_recon
from modules.active    import run_active_recon
from modules.services  import run_service_discovery
from modules.analysis  import run_analysis
from modules.reporter  import generate_report

console = Console()


# ══════════════════════════════════════════════════════
#  BANNER
# ══════════════════════════════════════════════════════

def print_banner():
    os.system("cls" if os.name == "nt" else "clear")

    # ASCII art in bright green — different from red
    art = """
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝"""

    console.print(art, style="bold bright_green")
    console.print()

    # info line under art
    console.print(
        "  [dim white]recon pipeline[/]  [bright_green]·[/]  "
        "[dim white]bug bounty[/]  [bright_green]·[/]  "
        "[dim white]pentest[/]"
        "                    [dim]v1.0 · YOUR_NAME[/]"
    )
    console.print(
        "  [dim]" + "─" * 58 + "[/]"
    )
    console.print()


# ══════════════════════════════════════════════════════
#  ARG PARSER
# ══════════════════════════════════════════════════════

def build_arg_parser():
    parser = argparse.ArgumentParser(
        prog="reconx",
        description="ReconX — Automated Recon Pipeline",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "examples:\n"
            "  python3 reconx.py -t example.com\n"
            "  python3 reconx.py -t example.com --only passive\n"
            "  python3 reconx.py -t example.com --output all\n"
        )
    )
    parser.add_argument("-t", "--target",
        required=True, metavar="TARGET",
        help="target domain or IP")
    parser.add_argument("--threads",
        type=int, default=20,
        help="thread count (default: 20)")
    parser.add_argument("--timeout",
        type=int, default=5,
        help="timeout in seconds (default: 5)")
    parser.add_argument("--rate-limit",
        type=float, default=0.05, dest="rate_limit")
    parser.add_argument("--only", metavar="STAGE",
        help="run one stage: passive/active/services/analysis")
    parser.add_argument("--skip", metavar="STAGE")
    parser.add_argument("--no-ports",
        action="store_true", dest="no_ports")
    parser.add_argument("--no-active",
        action="store_true", dest="no_active")
    parser.add_argument("--shodan", metavar="KEY")
    parser.add_argument("--wordlist",
        metavar="FILE", default="wordlists/subdomains.txt")
    parser.add_argument("--output",
        choices=["json","md","all"],
        default="json", metavar="FORMAT",
        help="report format: json / md / all")
    parser.add_argument("--output-dir",
        metavar="DIR", default="reports", dest="output_dir")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-q", "--quiet",   action="store_true")
    parser.add_argument("--version",
        action="version", version="ReconX v1.0")
    return parser


# ══════════════════════════════════════════════════════
#  CONFIG
# ══════════════════════════════════════════════════════

def build_config(args):
    all_stages = {"passive", "active", "services", "analysis"}
    if args.only:
        skip_stages = all_stages - {args.only.lower()}
    elif args.skip:
        skip_stages = {args.skip.lower()}
    else:
        skip_stages = set()
    if args.no_active: skip_stages.add("active")
    if args.no_ports:  skip_stages.add("services")
    return {
        "target":      args.target.strip().lower(),
        "threads":     args.threads,
        "timeout":     args.timeout,
        "rate_limit":  args.rate_limit,
        "wordlist":    args.wordlist,
        "shodan_key":  args.shodan,
        "output_fmt":  args.output,
        "output_dir":  args.output_dir,
        "verbose":     args.verbose,
        "quiet":       args.quiet,
        "skip_stages": skip_stages,
        "scan_start":  datetime.now().isoformat(),
    }


# ══════════════════════════════════════════════════════
#  STAGE RUNNER
# ══════════════════════════════════════════════════════

def run_stage(name, func, args, config, results):
    """runs one stage with spinner, merges results"""

    stage_key = name.lower().replace(" ", "")
    for skip in config["skip_stages"]:
        if skip in stage_key:
            console.print(f"  [dim]⊘  {name} — skipped[/]")
            return False

    stage_start = time.time()

    with Progress(
        SpinnerColumn(spinner_name="dots2", style="bright_green"),
        TextColumn(f"  [dim]{name}...[/]"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("", total=None)
        try:
            stage_results = func(*args, config)
            results.update(stage_results)
        except KeyboardInterrupt:
            console.print(f"\n  [yellow]interrupted[/]")
            raise
        except Exception as e:
            elapsed = round(time.time() - stage_start, 2)
            console.print(
                f"  [red]✗[/]  [red]{name}[/] [dim]failed ({elapsed}s)[/] — {e}"
            )
            if config.get("verbose"):
                import traceback
                traceback.print_exc()
            results[f"{name}_error"] = str(e)
            return False

    elapsed = round(time.time() - stage_start, 2)
    console.print(
        f"  [bright_green]✓[/]  [bold white]{name}[/]  "
        f"[dim]done in {elapsed}s[/]"
    )
    return True


# ══════════════════════════════════════════════════════
#  PRINT FUNCTIONS — each one prints one section
#  called after every stage so results show as they come
# ══════════════════════════════════════════════════════

def print_section_rule(title):
    """prints a colored section divider"""
    console.print()
    console.rule(
        f"[bold bright_green] {title} [/]",
        style="bright_green"
    )
    console.print()


def print_passive_results(results):
    """
    prints passive recon findings to terminal.
    WHOIS, DNS, Geo, crt.sh subdomains.
    """

    print_section_rule("01 · Passive Recon")

    # ── WHOIS ──────────────────────────────────────────
    whois = results.get("whois", {})
    if whois and not whois.get("error"):
        t = Table(
            box=ROUNDED,
            border_style="dim",
            show_header=False,
            padding=(0, 1),
            title="[bold white]WHOIS[/]",
            title_style="bold bright_green",
            title_justify="left",
        )
        t.add_column("key",   style="dim",        width=18)
        t.add_column("value", style="bold white",  width=40)

        rows = [
            ("Registrar",   whois.get("registrar", "—")),
            ("Created",     whois.get("created",   "—")),
            ("Expires",     whois.get("expires",   "—")),
            ("Org",         whois.get("registrant_org", "—")),
            ("Country",     whois.get("registrant_country", "—")),
        ]
        ns = whois.get("name_servers", [])
        if ns:
            rows.append(("Name Servers", " · ".join(ns[:3])))

        for k, v in rows:
            t.add_row(k, str(v) if v else "—")

        console.print("  ", t)
        console.print()

    # ── DNS RECORDS ────────────────────────────────────
    dns = results.get("dns_records", {})
    if dns:
        console.print("  [bold bright_green]DNS Records[/]")
        console.print()

        for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
            records = dns.get(rtype, [])
            if not records:
                continue

            # format values
            vals = []
            for r in records[:4]:
                if isinstance(r, dict):
                    vals.append(f"[{r.get('priority','')}] {r.get('host','')}")
                else:
                    vals.append(str(r)[:80])

            console.print(
                f"  [bright_green]{rtype:<6}[/]  "
                f"[white]{' · '.join(vals)}[/]"
            )

        # interesting TXT services
        interesting = dns.get("interesting_txt", [])
        if interesting:
            services = [i.get("service","") for i in interesting]
            console.print()
            console.print(
                f"  [dim]Services in TXT:[/]  "
                + "  ".join(
                    f"[bright_green]{s}[/]" for s in services
                )
            )

        # SPF / DMARC warnings
        has_spf   = any("SPF"   in i.get("service","") for i in interesting)
        has_dmarc = any("DMARC" in i.get("service","") for i in interesting)
        if not has_spf:
            console.print(
                "  [yellow]⚠[/]  [yellow]No SPF record — email spoofing possible[/]"
            )
        if not has_dmarc:
            console.print(
                "  [yellow]⚠[/]  [yellow]No DMARC record — phishing risk[/]"
            )
        console.print()

    # ── GEO / ASN ──────────────────────────────────────
    geo = results.get("geo_asn", {})
    if geo and not geo.get("error"):
        console.print("  [bold bright_green]Geo / ASN[/]")
        console.print()
        console.print(
            f"  [dim]Country[/]   [white]{geo.get('country','')} "
            f"({geo.get('country_code','')})[/]"
        )
        console.print(
            f"  [dim]City[/]      [white]{geo.get('city','—')}[/]"
        )
        console.print(
            f"  [dim]ISP[/]       [white]{geo.get('isp','—')}[/]"
        )
        console.print(
            f"  [dim]ASN[/]       [white]{geo.get('asn','—')}[/]"
        )
        console.print(
            f"  [dim]Hosting[/]   "
            + (
                "[yellow]Yes — CDN/Cloud likely in front[/]"
                if geo.get("hosting") else
                "[white]No[/]"
            )
        )
        console.print()

    # ── CRT.SH ─────────────────────────────────────────
    crt  = results.get("crtsh", {})
    subs = crt.get("subdomains", [])
    if subs:
        console.print(
            f"  [bold bright_green]crt.sh[/]  "
            f"[dim]found[/] [bold white]{len(subs)}[/] "
            f"[dim]subdomains from {crt.get('total_certs',0)} certificates[/]"
        )
        console.print()
        # show first 15
        for s in subs[:15]:
            console.print(f"  [dim]·[/] [white]{s}[/]")
        if len(subs) > 15:
            console.print(
                f"  [dim]... and {len(subs)-15} more (see report file)[/]"
            )
        console.print()

    # ── SHODAN ─────────────────────────────────────────
    shodan = results.get("shodan", {})
    if shodan and not shodan.get("skipped") and not shodan.get("error"):
        vulns = shodan.get("vulns", [])
        ports = shodan.get("ports", [])
        console.print("  [bold bright_green]Shodan[/]")
        if ports:
            console.print(
                f"  [dim]Ports seen:[/]  "
                f"[white]{' · '.join(str(p) for p in ports[:10])}[/]"
            )
        if vulns:
            console.print(
                f"  [dim]Known CVEs:[/]  "
                + "  ".join(f"[red]{v}[/]" for v in vulns[:5])
            )
        console.print()


def print_active_results(results):
    """
    prints active recon findings.
    subdomains brute-forced, JS secrets, emails.
    """

    print_section_rule("02 · Active Recon")

    # ── SUBDOMAINS ─────────────────────────────────────
    bf       = results.get("subdomain_bruteforce", {})
    live     = bf.get("live", [])
    takeovers = results.get("takeovers", [])

    console.print(
        f"  [bold bright_green]Subdomains[/]  "
        f"[bold white]{len(live)}[/] [dim]live  ·  "
        f"{bf.get('total_tried',0)} tried[/]"
    )
    console.print()

    # takeovers first — most important
    if takeovers:
        for t in takeovers:
            console.print(
                f"  [bold red]⚑ TAKEOVER[/]  "
                f"[bold white]{t.get('subdomain','')}[/]  "
                f"[dim]→[/]  [red]{t.get('service','')}[/]"
            )
        console.print()

    # live subdomains table
    if live:
        t = Table(
            box=SIMPLE_HEAVY,
            border_style="dim",
            header_style="dim bright_green",
            show_lines=False,
            padding=(0, 1),
        )
        t.add_column("Subdomain",  style="white",  width=35)
        t.add_column("Status",     width=8)
        t.add_column("Title",      style="dim",    width=30)
        t.add_column("Server",     style="dim",    width=20)

        for s in live[:25]:
            name   = s.get("subdomain", "")
            status = s.get("status", "—")
            title  = (s.get("title") or "—")[:28]
            server = (s.get("server") or "—")[:18]

            # color the status code
            if status == 200:
                st = f"[bright_green]{status}[/]"
            elif str(status).startswith("3"):
                st = f"[yellow]{status}[/]"
            elif status in [403, 401]:
                st = f"[red]{status}[/]"
            else:
                st = f"[dim]{status}[/]"

            t.add_row(name, st, title, server)

        console.print("  ", t)

        if len(live) > 25:
            console.print(
                f"  [dim]  ... and {len(live)-25} more in report file[/]"
            )
        console.print()

    # ── JS SECRETS ─────────────────────────────────────
    secrets = results.get("js_secrets", [])
    if secrets:
        console.print(
            f"  [bold bright_green]JS Secrets[/]  "
            f"[bold white]{len(secrets)}[/] [dim]found[/]"
        )
        console.print()
        for s in secrets[:10]:
            stype = s.get("type", "")
            val   = s.get("value", "")
            # mask the value
            masked = val[:6] + "••••" if len(val) > 6 else val
            is_crit = any(
                x in stype
                for x in ["AWS","Private","Stripe Live","Firebase"]
            )
            color = "red" if is_crit else "yellow"
            console.print(
                f"  [{color}]▸[/]  [bold white]{stype}[/]  "
                f"[{color}]{masked}[/{color}]  "
                f"[dim]{s.get('file','')[-40:]}[/]"
            )
        if len(secrets) > 10:
            console.print(
                f"  [dim]  ... and {len(secrets)-10} more in report file[/]"
            )
        console.print()
    else:
        console.print("  [dim]JS Secrets — none found[/]")
        console.print()

    # ── API ENDPOINTS ──────────────────────────────────
    endpoints = results.get("js_endpoints", [])
    if endpoints:
        console.print(
            f"  [bold bright_green]API Endpoints[/]  "
            f"[bold white]{len(endpoints)}[/] [dim]extracted from JS[/]"
        )
        console.print()
        for ep in endpoints[:12]:
            console.print(f"  [dim]·[/] [white]{ep}[/]")
        if len(endpoints) > 12:
            console.print(
                f"  [dim]  ... and {len(endpoints)-12} more in report file[/]"
            )
        console.print()

    # ── EMAILS ─────────────────────────────────────────
    emails = results.get("emails", [])
    if emails:
        console.print(
            f"  [bold bright_green]Emails[/]  "
            f"[bold white]{len(emails)}[/] [dim]harvested[/]"
        )
        console.print()
        for e in emails[:10]:
            console.print(f"  [dim]·[/] [white]{e}[/]")
        console.print()


def print_services_results(results):
    """
    prints service discovery findings.
    open ports, banners, HTTP services.
    """

    print_section_rule("03 · Service Discovery")

    # ── OPEN PORTS ─────────────────────────────────────
    ports       = results.get("open_ports", [])
    interesting = results.get("interesting", [])
    int_nums    = {i.get("port") for i in interesting}

    console.print(
        f"  [bold bright_green]Open Ports[/]  "
        f"[bold white]{len(ports)}[/] [dim]found[/]"
    )
    console.print()

    if ports:
        t = Table(
            box=SIMPLE_HEAVY,
            border_style="dim",
            header_style="dim bright_green",
            show_lines=False,
            padding=(0, 1),
        )
        t.add_column("Host",    style="white", width=28)
        t.add_column("Port",    width=8)
        t.add_column("Service", width=16)
        t.add_column("Flag",    width=20)

        for p in ports:
            port    = p.get("port", "")
            service = p.get("service", "")
            host    = p.get("host", "")
            flag    = (
                "[red]⚠ Sensitive[/]"
                if port in int_nums else ""
            )
            port_str = (
                f"[red]{port}[/]" if port in int_nums
                else f"[bright_green]{port}[/]"
            )
            t.add_row(host, port_str, service, flag)

        console.print("  ", t)
        console.print()

    # ── BANNERS ────────────────────────────────────────
    banners = results.get("banners", [])
    useful  = [b for b in banners if b.get("version") or b.get("ssl_subject")]
    if useful:
        console.print(
            f"  [bold bright_green]Service Banners[/]  "
            f"[bold white]{len(useful)}[/] [dim]with version info[/]"
        )
        console.print()
        for b in useful[:8]:
            console.print(
                f"  [dim]·[/] [white]{b.get('host','')}:{b.get('port','')}[/]  "
                f"[bright_green]{b.get('version','—')}[/]  "
                + (f"[dim]SSL: {b.get('ssl_subject','')}[/]"
                   if b.get("ssl_subject") else "")
            )
        console.print()

    # ── HTTP SERVICES ──────────────────────────────────
    http = results.get("http_services", [])
    if http:
        console.print(
            f"  [bold bright_green]HTTP Services[/]  "
            f"[bold white]{len(http)}[/] [dim]live[/]"
        )
        console.print()

        t = Table(
            box=SIMPLE_HEAVY,
            border_style="dim",
            header_style="dim bright_green",
            show_lines=False,
            padding=(0, 1),
        )
        t.add_column("URL",    style="white",        width=35)
        t.add_column("Status", width=8)
        t.add_column("Title",  style="dim",          width=28)
        t.add_column("Flags",  width=20)

        for svc in http[:15]:
            url    = svc.get("url", "")
            status = svc.get("status", "")
            title  = (svc.get("title") or "—")[:26]

            flags = []
            if svc.get("is_admin"):
                flags.append("[red]Admin[/]")
            if svc.get("is_login"):
                flags.append("[yellow]Login[/]")
            missing = len(svc.get("missing_headers", []))
            if missing:
                flags.append(f"[dim]-{missing} headers[/]")

            if status == 200:
                st = f"[bright_green]{status}[/]"
            elif str(status).startswith("3"):
                st = f"[yellow]{status}[/]"
            else:
                st = f"[dim]{status}[/]"

            t.add_row(url[:33], st, title, " ".join(flags))

        console.print("  ", t)
        console.print()


def print_analysis_results(results):
    """
    prints analysis engine findings.
    WAF, tech stack, vuln hints, attack chains.
    this is the 'so what?' section — what does it all mean.
    """

    print_section_rule("04 · Analysis Engine")

    # ── WAF + TECH ─────────────────────────────────────
    waf  = results.get("waf", [])
    tech = results.get("tech_stack", [])

    console.print(
        f"  [bold bright_green]WAF / CDN[/]   "
        + (
            "  ".join(f"[yellow]{w}[/]" for w in waf)
            if waf else "[dim]None detected[/]"
        )
    )
    console.print(
        f"  [bold bright_green]Tech Stack[/]  "
        + (
            "  ".join(f"[white]{t}[/]" for t in tech[:6])
            if tech else "[dim]Unknown[/]"
        )
    )
    console.print()

    # ── VULN HINTS ─────────────────────────────────────
    hints = results.get("vuln_hints", [])
    if hints:
        console.print(
            f"  [bold bright_green]Vulnerability Hints[/]  "
            f"[bold white]{len(hints)}[/] [dim]triggered[/]"
        )
        console.print()

        for h in hints:
            sev = h.get("severity", "Info")

            # pick color based on severity
            if sev == "Critical":
                color = "red"
                icon  = "💀"
            elif sev == "High":
                color = "yellow"
                icon  = "🔴"
            elif sev == "Medium":
                color = "bright_blue"
                icon  = "🟡"
            else:
                color = "dim"
                icon  = "🔵"

            console.print(
                f"  [{color}]{icon} [{sev}][/{color}]  "
                f"[bold white]{h['title']}[/]  "
                f"[dim]{h.get('id','')}[/]"
            )
            # show detail on next line indented
            console.print(
                f"  [dim]        {h.get('detail','')[:90]}[/]"
            )
            console.print()

    else:
        console.print("  [dim]No vulnerability hints triggered[/]")
        console.print()

    # ── ATTACK CHAINS ──────────────────────────────────
    chains = results.get("chains", [])
    if chains:
        console.print(
            f"  [bold bright_green]Attack Chains[/]  "
            f"[bold white]{len(chains)}[/] [dim]identified[/]"
        )
        console.print()

        for c in chains:
            console.print(
                f"  [bold red]⛓  {c.get('title','')}[/]"
            )
            for step in c.get("steps", []):
                console.print(f"  [dim]     {step}[/]")
            console.print()


# ══════════════════════════════════════════════════════
#  FINAL SUMMARY — at the very end
# ══════════════════════════════════════════════════════

def print_final_summary(results, config, elapsed_total):
    """
    final summary — same info as start but now filled in.
    shows everything found in a clean table.
    then shows what to do next.
    """

    hints     = results.get("vuln_hints", [])
    chains    = results.get("chains", [])
    takeovers = results.get("takeovers", [])

    def count(key):
        val = results.get(key, [])
        return len(val) if isinstance(val, (list, set)) else 0

    def sev(severity):
        return sum(1 for h in hints if h.get("severity") == severity)

    def strval(key, fallback="—"):
        val = results.get(key, [])
        if isinstance(val, list):
            return ", ".join(str(x) for x in val[:2]) or fallback
        return str(val) if val else fallback

    console.print()
    console.rule(
        "[bold bright_green]  Scan Complete  [/]",
        style="bright_green"
    )
    console.print()

    # ── two tables side by side ─────────────────────────

    # left: what was found
    found = Table(
        title="[bold white]What was found[/]",
        title_style="bold bright_green",
        title_justify="left",
        box=ROUNDED,
        border_style="dim",
        header_style="dim bright_green",
        show_lines=False,
        padding=(0, 2),
    )
    found.add_column("Category",   style="white",        width=18)
    found.add_column("Count",      justify="right",
                     style="bold bright_green",          width=7)
    found.add_column("Note",       style="dim",          width=22)

    found.add_row("Subdomains",    str(count("subdomains")),    "passive + brute-force")
    found.add_row("Open ports",    str(count("open_ports")),    "targeted TCP scan")
    found.add_row("HTTP services", str(count("http_services")), "live web servers")
    found.add_row("JS secrets",    str(count("js_secrets")),    "tokens · keys · URIs")
    found.add_row("API endpoints", str(count("js_endpoints")),  "from JS files")
    found.add_row("Emails",        str(count("emails")),        "harvested")
    found.add_row("Takeovers",     str(count("takeovers")),     "subdomain claim risk")
    found.add_row("Attack chains", str(len(chains)),            "combined findings")

    # right: severity breakdown
    sevt = Table(
        title="[bold white]Severity[/]",
        title_style="bold bright_green",
        title_justify="left",
        box=ROUNDED,
        border_style="dim",
        header_style="dim bright_green",
        show_lines=False,
        padding=(0, 2),
    )
    sevt.add_column("Level",   width=12)
    sevt.add_column("Count",   justify="right",
                    style="bold", width=7)

    sevt.add_row("[bold red]Critical[/]",       str(sev("Critical")))
    sevt.add_row("[yellow]High[/]",             str(sev("High")))
    sevt.add_row("[bright_blue]Medium[/]",      str(sev("Medium")))
    sevt.add_row("[dim]Low / Info[/]",
        str(sum(1 for h in hints if h.get("severity") in ["Low","Info"])))
    sevt.add_row("[bold white]Total hints[/]",  str(len(hints)))

    console.print(Columns(["  ", found, "    ", sevt]))
    console.print()

    # ── target info recap ───────────────────────────────
    # same info shown at start but now complete
    console.print("  [bold bright_green]Target recap[/]")
    console.print()

    recap = [
        ("Target",     config["target"]),
        ("IP",         results.get("ip", "—")),
        ("Server",     results.get("server", "—")),
        ("WAF",        strval("waf")),
        ("Tech stack", strval("tech_stack")),
        ("HTTPS",      "Yes" if results.get("https") else "No"),
        ("Scan time",  f"{round(elapsed_total, 2)}s"),
        ("Started",    config["scan_start"][:19].replace("T", " ")),
    ]
    for k, v in recap:
        console.print(
            f"  [dim]{k:<12}[/]  [white]{v}[/]"
        )
    console.print()

    # ── what to do next ─────────────────────────────────
    console.print("  [bold bright_green]What to do next[/]")
    console.print()

    next_steps = []

    if takeovers:
        next_steps.append(
            "[red]⚑[/]  Subdomain takeover found — "
            "claim the service and test for cookie theft"
        )

    crits = [h for h in hints if h.get("severity") == "Critical"]
    if crits:
        for c in crits[:3]:
            next_steps.append(
                f"[red]▸[/]  {c['title']} — manually verify this"
            )

    js_secs = results.get("js_secrets", [])
    if js_secs:
        next_steps.append(
            "[yellow]▸[/]  Test leaked API keys/tokens "
            "against their respective services"
        )

    eps = results.get("js_endpoints", [])
    if eps:
        next_steps.append(
            "[yellow]▸[/]  Probe discovered API endpoints "
            "for auth issues, IDOR, and data exposure"
        )

    open_ports = results.get("open_ports", [])
    sensitive  = [p for p in open_ports if p.get("port") in
                  {2375, 6379, 27017, 9200, 5984, 6443}]
    if sensitive:
        for p in sensitive[:2]:
            next_steps.append(
                f"[red]▸[/]  Port {p['port']} ({p['service']}) "
                f"open — test for unauthenticated access"
            )

    dns = results.get("dns_records", {})
    interesting = dns.get("interesting_txt", [])
    has_spf   = any("SPF"   in i.get("service","") for i in interesting)
    has_dmarc = any("DMARC" in i.get("service","") for i in interesting)
    if not has_spf or not has_dmarc:
        next_steps.append(
            "[yellow]▸[/]  Missing SPF/DMARC — "
            "test email spoofing with tools like swaks"
        )

    admin_svcs = [s for s in results.get("http_services", [])
                  if s.get("is_admin")]
    if admin_svcs:
        next_steps.append(
            "[yellow]▸[/]  Admin panel found — "
            "test default credentials and brute-force"
        )

    # default if nothing specific
    if not next_steps:
        next_steps = [
            "[dim]▸  Run Burp Suite on discovered HTTP services[/]",
            "[dim]▸  Test subdomains for authentication bypass[/]",
            "[dim]▸  Check robots.txt and sitemap.xml on all subdomains[/]",
        ]

    for step in next_steps:
        console.print(f"  {step}")

    console.print()


# ══════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════

def main():

    print_banner()

    parser = build_arg_parser()
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args   = parser.parse_args()
    config = build_config(args)

    Path(config["output_dir"]).mkdir(parents=True, exist_ok=True)

    results = {
        "target":     config["target"],
        "scan_start": config["scan_start"],
    }

    total_start = time.time()

    # ── show scan config before starting ───────────────
    print_section_rule("Scan Config")

    t = Table(
        box=ROUNDED,
        border_style="dim",
        show_header=False,
        padding=(0, 1),
    )
    t.add_column("k", style="dim",       width=16)
    t.add_column("v", style="bold white", width=38)

    t.add_row("Target",    config["target"])
    t.add_row("Threads",   str(config["threads"]))
    t.add_row("Timeout",   f"{config['timeout']}s")
    t.add_row("Wordlist",  config["wordlist"])
    t.add_row("Output",    config["output_fmt"].upper())
    t.add_row("Shodan",    "Yes" if config.get("shodan_key") else "No")
    t.add_row("Skip",
        ", ".join(config["skip_stages"]) if config["skip_stages"] else "None"
    )
    t.add_row("Started",
        config["scan_start"][:19].replace("T", " ")
    )

    console.print("  ", t)
    console.print()

    # ── validation ─────────────────────────────────────
    with Progress(
        SpinnerColumn(spinner_name="dots2", style="bright_green"),
        TextColumn("  [dim]Validating target...[/]"),
        transient=True, console=console,
    ) as p:
        p.add_task("", total=None)
        validation = validate_target(config["target"], config)

    if not validation.get("is_valid"):
        console.print(
            f"\n  [red]✗  {validation.get('error','invalid target')}[/]\n"
        )
        sys.exit(1)

    results.update(validation)

    console.print(
        f"  [bright_green]✓[/]  [bold white]{config['target']}[/]  "
        f"[dim]→[/]  [white]{validation.get('ip','?')}[/]  "
        f"[dim]status[/] [white]{validation.get('status_code','?')}[/]  "
        f"[dim]server[/] [white]{validation.get('server','?')}[/]"
    )
    console.print()

    try:
        # ── stage 1: passive ───────────────────────────
        run_stage("Passive Recon", run_passive_recon,
                  (config["target"],), config, results)
        if not config["quiet"]:
            print_passive_results(results)

        # ── stage 2: active ────────────────────────────
        run_stage("Active Recon", run_active_recon,
                  (config["target"], config["wordlist"]),
                  config, results)
        if not config["quiet"]:
            print_active_results(results)

        # ── stage 3: services ──────────────────────────
        targets_to_scan = (
            results.get("subdomains", [])[:5] + [config["target"]]
        )
        run_stage("Service Discovery", run_service_discovery,
                  (targets_to_scan,), config, results)
        if not config["quiet"]:
            print_services_results(results)

        # ── stage 4: analysis ──────────────────────────
        run_stage("Analysis Engine", run_analysis,
                  (results,), config, results)
        if not config["quiet"]:
            print_analysis_results(results)

    except KeyboardInterrupt:
        console.print(
            "\n  [yellow]⚠  interrupted — saving partial report...[/]\n"
        )

    # ── save report ────────────────────────────────────
    print_section_rule("05 · Saving Report")

    try:
        report_paths = generate_report(results, config)
        for fmt, path in report_paths.items():
            console.print(
                f"  [bright_green]✓[/]  "
                f"[dim]{fmt.upper()} saved →[/]  [bold white]{path}[/]"
            )
    except Exception as e:
        console.print(f"  [red]✗  Report failed: {e}[/]")
        if config.get("verbose"):
            import traceback
            traceback.print_exc()

    # ── final summary ──────────────────────────────────
    print_final_summary(results, config, time.time() - total_start)

    console.print(
        "  [dim]ReconX done. "
        "Open your report file for full details.[/]\n"
    )


if __name__ == "__main__":
    main()
