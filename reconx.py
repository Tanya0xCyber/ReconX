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

    # ASCII art 
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
        "[dim white]pentest[/]  [bright_green]·[/]"
         "\n"
        " [dim] Tanya singh[/]"
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
#  INTELLIGENCE HELPERS
#  used by all print functions below
# ══════════════════════════════════════════════════════

def tag_subdomain(name):
    """categorizes subdomain — returns (tag, color, priority)"""
    n = name.lower()
    if any(x in n for x in ["admin","panel","manage","dashboard","cms","cpanel"]):
        return "Admin",         "red",     3
    if any(x in n for x in ["api","graphql","rest","gateway","ws","grpc"]):
        return "API",           "yellow",  3
    if any(x in n for x in ["dev","debug","test","sandbox","local"]):
        return "Dev",           "yellow",  2
    if any(x in n for x in ["staging","stage","uat","qa","preprod","beta"]):
        return "Staging",       "yellow",  2
    if any(x in n for x in ["vpn","rdp","remote","bastion","citrix","ssh"]):
        return "RemoteAccess",  "red",     3
    if any(x in n for x in ["git","jenkins","ci","cd","jira","deploy","build"]):
        return "DevOps",        "red",     3
    if any(x in n for x in ["db","mysql","mongo","redis","elastic","postgres"]):
        return "Database",      "red",     3
    if any(x in n for x in ["old","bak","backup","legacy","archive","tmp"]):
        return "Legacy",        "red",     2
    if any(x in n for x in ["mail","smtp","mx","webmail"]):
        return "Mail",          "bright_blue", 1
    return "std", "dim", 0


def port_intel(port):
    """returns (label, risk, one-line attacker opportunity)"""
    db = {
        22:    ("SSH",         "med",  "brute-force / key reuse"),
        23:    ("Telnet",      "crit", "creds in cleartext — intercept"),
        21:    ("FTP",         "high", "anon login / cleartext creds"),
        3389:  ("RDP",         "crit", "ransomware entry / BlueKeep"),
        5900:  ("VNC",         "crit", "often no auth — direct desktop"),
        2375:  ("Docker API",  "crit", "mount host fs → full takeover"),
        6379:  ("Redis",       "crit", "no auth default → RCE via SLAVEOF"),
        27017: ("MongoDB",     "crit", "no auth default → full DB dump"),
        9200:  ("Elastic",     "crit", "no auth default → read/write/delete"),
        5432:  ("PostgreSQL",  "high", "brute-force → SQL pivot"),
        3306:  ("MySQL",       "high", "brute-force → data exfil"),
        1433:  ("MSSQL",       "high", "xp_cmdshell → OS commands"),
        5984:  ("CouchDB",     "high", "/_utils admin panel exposed"),
        6443:  ("K8s API",     "crit", "anonymous access → cluster takeover"),
        10250: ("K8s Kubelet", "crit", "exec into pods → secret access"),
        2379:  ("etcd",        "crit", "k8s secrets store → read all secrets"),
        8080:  ("HTTP-Alt",    "med",  "dev server / proxy — less hardened"),
        8443:  ("HTTPS-Alt",   "med",  "alt HTTPS — weak cert / config"),
        4848:  ("GlassFish",   "high", "admin panel → default admin:adminadmin"),
        8161:  ("ActiveMQ",    "high", "admin panel → default admin:admin"),
        15672: ("RabbitMQ",    "high", "mgmt UI → default guest:guest"),
        8888:  ("Jupyter",     "crit", "often no auth → direct code exec"),
        11211: ("Memcached",   "high", "amplification / data exposure"),
        9090:  ("Prometheus",  "med",  "metrics leak internal infra map"),
        389:   ("LDAP",        "high", "directory enum / cred attacks"),
    }
    return db.get(port, (None, None, None))


def risk_color(r):
    """maps risk string to rich color"""
    return {
        "crit": "red",
        "high": "yellow",
        "med":  "bright_blue",
        "low":  "dim"
    }.get(r, "dim")


# ══════════════════════════════════════════════════════
#  SECTION DIVIDER — used by all print functions
# ══════════════════════════════════════════════════════

def section(title):
    """prints a bright green section rule"""
    console.print()
    console.rule(
        f"[bold bright_green] {title} [/]",
        style="bright_green"
    )
    console.print()

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
    """passive recon — signal only, no edu text"""

    section("01 · Passive Recon")

    # WHOIS
    whois = results.get("whois", {})
    if whois and not whois.get("error"):
        fields = [
            ("Registrar", whois.get("registrar")),
            ("Created",   whois.get("created")),
            ("Expires",   whois.get("expires")),
            ("Org",       whois.get("registrant_org")),
        ]
        for k, v in fields:
            if v and v != "—":
                console.print(
                    f"  [dim]{k:<12}[/]  [white]{v}[/]"
                )

        # expiry flag only
        expires = whois.get("expires","")
        if expires:
            try:
                from datetime import datetime as dt
                days = (dt.strptime(expires, "%Y-%m-%d") - dt.now()).days
                if days < 90:
                    console.print(
                        f"  [red]⚠  Expires in {days}d[/]  "
                        f"[dim]→ domain hijack risk[/]"
                    )
            except Exception:
                pass

        # NS insight — one line
        ns = whois.get("name_servers", [])
        ns_str = " ".join(ns).lower()
        if ns:
            ns_hint = ""
            if "cloudflare" in ns_str:
                ns_hint = "[dim]→ origin IP hidden — find via cert SANs / SPF[/]"
            elif "awsdns" in ns_str:
                ns_hint = "[dim]→ AWS hosted — check for S3 buckets[/]"
            console.print(
                f"  [dim]{'NS':<12}[/]  "
                f"[white]{' · '.join(ns[:2])}[/]  {ns_hint}"
            )
        console.print()

    # DNS — compact, just the records + one contextual note
    dns = results.get("dns_records", {})
    if dns:
        for rtype in ["A","MX","NS","CNAME"]:
            records = dns.get(rtype, [])
            if not records:
                continue
            vals = []
            for r in records[:2]:
                if isinstance(r, dict):
                    vals.append(
                        f"[{r.get('priority','')}] {r.get('host','')}"
                    )
                else:
                    vals.append(str(r)[:60])
            console.print(
                f"  [bright_green]{rtype:<6}[/]  [white]{' · '.join(vals)}[/]"
            )

        # MX → mail provider in one line
        mx = dns.get("MX",[])
        if mx:
            mx_str = str(mx).lower()
            if "google" in mx_str:
                console.print("  [dim]       Google Workspace — phishing hits spam filters[/]")
            elif "outlook" in mx_str or "microsoft" in mx_str:
                console.print("  [dim]       M365 — O365 phishing highly effective, check MFA[/]")

        # Email security — compact table
        interesting = dns.get("interesting_txt", [])
        has_spf   = any("SPF"   in i.get("service","") for i in interesting)
        has_dmarc = any("DMARC" in i.get("service","") for i in interesting)

        console.print()
        spf_str   = "[bright_green]✓[/]" if has_spf   else "[red]✗ Missing[/]  [dim]→ spoofable[/]"
        dmarc_str = "[bright_green]✓[/]" if has_dmarc else "[red]✗ Missing[/]  [dim]→ domain spoofable even with SPF[/]"
        console.print(f"  [dim]SPF  [/]   {spf_str}")
        console.print(f"  [dim]DMARC[/]   {dmarc_str}")

        if interesting:
            svcs = [i.get("service","") for i in interesting if "SPF" not in i.get("service","") and "DMARC" not in i.get("service","")]
            if svcs:
                console.print(
                    f"  [dim]TXT  [/]   "
                    + "  ".join(f"[bright_green]{s}[/]" for s in svcs[:4])
                )
        console.print()

    # Geo
    geo = results.get("geo_asn", {})
    if geo and not geo.get("error"):
        isp     = geo.get("isp","—")
        asn     = geo.get("asn","—")
        hosting = geo.get("hosting", False)
        console.print(
            f"  [dim]ISP[/]     [white]{isp}[/]  [dim]{asn}[/]"
        )
        if hosting:
            console.print(
                "  [yellow]CDN/Proxy[/]  [dim]→ real IP hidden  "
                "check: cert history, SPF includes, email headers[/]"
            )
        console.print()

    # crt.sh — high-value subs only
    crt  = results.get("crtsh", {})
    subs = crt.get("subdomains", [])
    if subs:
        tagged = [(s, *tag_subdomain(s)) for s in subs]
        hv = [(s,t,c,p) for s,t,c,p in tagged if p >= 2]
        console.print(
            f"  [bold bright_green]crt.sh[/]  "
            f"[white]{len(subs)}[/] [dim]total  ·  "
            f"{len(hv)} high-value[/]"
        )
        console.print()
        for name, tag, color, _ in hv[:6]:
            console.print(
                f"  [{color}]▸[/]  [white]{name}[/]  "
                f"[{color}][{tag}][/{color}]"
            )
        if len(subs) > 6:
            console.print(
                f"  [dim]  + {len(subs)-6} more in report[/]"
            )
        console.print()

    # Shodan
    shodan = results.get("shodan", {})
    if shodan and not shodan.get("skipped") and not shodan.get("error"):
        vulns = shodan.get("vulns", [])
        ports_s = shodan.get("ports", [])
        if vulns:
            console.print(
                "  [bold red]Shodan CVEs[/]  "
                + "  ".join(f"[red]{v}[/]" for v in vulns[:4])
            )
        if ports_s:
            console.print(
                f"  [dim]Shodan ports:[/]  "
                f"[white]{' · '.join(str(p) for p in ports_s[:8])}[/]"
            )
        console.print()


def print_active_results(results):
    """active recon — filtered, high-value only"""

    section("02 · Active Recon")

    bf        = results.get("subdomain_bruteforce", {})
    live      = bf.get("live", [])
    takeovers = results.get("takeovers", [])
    secrets   = results.get("js_secrets", [])
    endpoints = results.get("js_endpoints", [])
    emails    = results.get("emails", [])

    # takeovers — always top
    if takeovers:
        for t in takeovers:
            console.print(
                f"  [bold red]⚑ TAKEOVER[/]  "
                f"[bold white]{t.get('subdomain','')}[/]  "
                f"[dim]→[/]  [red]{t.get('service','')}[/]  "
                f"[dim]register account → own subdomain[/]"
            )
        console.print()

    # subdomains — priority tiers only
    if live:
        tagged = []
        for s in live:
            name = s.get("subdomain","")
            tag, color, pri = tag_subdomain(name)
            tagged.append((s, tag, color, pri))

        critical = [(s,t,c,p) for s,t,c,p in tagged if p == 3]
        medium   = [(s,t,c,p) for s,t,c,p in tagged if p == 2]
        standard = [(s,t,c,p) for s,t,c,p in tagged if p <= 1]

        console.print(
            f"  [dim]Subdomains[/]  "
            f"[white]{len(live)} live[/]  "
            f"[dim]·[/]  [red]{len(critical)} critical[/]  "
            f"[dim]·[/]  [yellow]{len(medium)} medium[/]  "
            f"[dim]·[/]  [dim]{len(standard)} standard[/]"
        )
        console.print()

        if critical:
            for s, tag, color, _ in critical[:10]:
                name   = s.get("subdomain","")
                status = s.get("status","—")
                title  = (s.get("title") or "")[:30]

                st = (
                    f"[bright_green]{status}[/]" if status == 200
                    else f"[yellow]{status}[/]" if str(status).startswith("3")
                    else f"[red]{status}[/]" if status in [401,403]
                    else f"[dim]{status}[/]"
                )
                console.print(
                    f"  [red]▸[/]  [bold white]{name}[/]  "
                    f"{st}  [{color}][{tag}][/{color}]"
                    + (f"  [dim]{title}[/]" if title else "")
                )

            if len(critical) > 10:
                console.print(
                    f"  [dim]  + {len(critical)-10} more critical[/]"
                )
            console.print()

        if medium:
            for s, tag, color, _ in medium[:5]:
                name   = s.get("subdomain","")
                status = s.get("status","—")
                console.print(
                    f"  [yellow]·[/]  [white]{name}[/]  "
                    f"[dim]{status}[/]  [{color}][{tag}][/{color}]"
                )
            if len(medium) > 5:
                console.print(f"  [dim]  + {len(medium)-5} more[/]")
            console.print()

        if standard:
            console.print(
                f"  [dim]+ {len(standard)} standard subdomains in report[/]"
            )
            console.print()

    # JS secrets — compact, with use case
    if secrets:
        console.print(
            f"  [bold red]JS Secrets  {len(secrets)} found[/]"
        )
        console.print()

        secret_use = {
            "AWS":        "→ aws cli s3 ls / iam enumerate",
            "GitHub":     "→ clone private repos",
            "Stripe":     "→ charge cards / read customer PII",
            "Firebase":   "→ read/write DB if rules permissive",
            "JWT":        "→ decode → alg confusion → forge token",
            "Slack":      "→ read messages / post as bot",
            "Mailgun":    "→ send mail as domain / read logs",
            "Generic":    "→ test against discovered API endpoints",
            "Bearer":     "→ replay against API endpoints",
            "MongoDB":    "→ direct DB connection string",
        }

        for s in secrets[:8]:
            stype  = s.get("type","")
            val    = s.get("value","")
            masked = val[:6]+"••" if len(val)>6 else val
            file   = s.get("file","")[-35:] if s.get("file") else ""

            is_crit = any(
                x in stype
                for x in ["AWS","Private","Stripe Live","Firebase","GitHub"]
            )
            color = "red" if is_crit else "yellow"

            # find matching use case
            use = ""
            for k, u in secret_use.items():
                if k.lower() in stype.lower():
                    use = u
                    break
            if not use:
                use = secret_use["Generic"]

            console.print(
                f"  [{color}]▸[/]  [white]{stype}[/]  "
                f"[{color}]{masked}[/]  "
                f"[dim]{use}[/]"
            )
            if file:
                console.print(f"  [dim]     {file}[/]")

        if len(secrets) > 8:
            console.print(f"  [dim]  + {len(secrets)-8} more in report[/]")
        console.print()
    else:
        console.print("  [dim]JS Secrets — none[/]")
        console.print()

    # API endpoints — categorized, no noise
    if endpoints:
        crit_eps  = [e for e in endpoints
                     if any(x in e.lower()
                            for x in ["admin","config","debug","internal","secret","backup","root"])]
        auth_eps  = [e for e in endpoints
                     if any(x in e.lower()
                            for x in ["auth","login","token","oauth","password","reset","register"])]
        other_eps = [e for e in endpoints
                     if e not in crit_eps and e not in auth_eps]

        console.print(
            f"  [bold bright_green]Endpoints[/]  "
            f"[white]{len(endpoints)}[/]  "
            f"[dim]·[/]  [red]{len(crit_eps)} sensitive[/]  "
            f"[dim]·[/]  [yellow]{len(auth_eps)} auth[/]"
        )
        console.print()

        for e in crit_eps[:4]:
            console.print(
                f"  [red]▸[/]  [white]{e}[/]  "
                f"[dim]← auth bypass / config leak[/]"
            )
        for e in auth_eps[:3]:
            console.print(
                f"  [yellow]▸[/]  [white]{e}[/]  "
                f"[dim]← brute-force / token reuse[/]"
            )
        if other_eps:
            console.print(
                f"  [dim]+ {len(other_eps)} general endpoints in report[/]"
            )
        console.print()

    # emails — one line
    if emails:
        cat       = results.get("email_harvest",{}).get("categorized",{})
        sec_mails = cat.get("security",[])
        console.print(
            f"  [dim]Emails[/]  [white]{len(emails)} harvested[/]"
            + (f"  [bright_green]· {len(sec_mails)} security contact(s)[/]"
               if sec_mails else "")
        )
        if sec_mails:
            for e in sec_mails[:2]:
                console.print(f"  [dim]  ·[/] [white]{e}[/]")
        console.print()


def print_services_results(results):
    """service discovery — interesting ports only, mapped to opportunities"""

    section("03 · Service Discovery")

    ports    = results.get("open_ports", [])
    banners  = results.get("banners", [])
    http     = results.get("http_services", [])

    if not ports:
        console.print("  [dim]No open ports in scope[/]")
        console.print()
        return

    # split by risk level
    crit_ports = []
    high_ports = []
    web_ports  = []
    std_ports  = []

    for p in ports:
        num = p.get("port","")
        label, risk, opp = port_intel(num)
        if risk == "crit":
            crit_ports.append((p, label, opp))
        elif risk == "high":
            high_ports.append((p, label, opp))
        elif num in {80,443,8080,8443,8000,8888,3000}:
            web_ports.append((p, label or p.get("service",""), opp))
        else:
            std_ports.append(p)

    # critical — full detail
    if crit_ports:
        console.print(f"  [bold red]Critical Ports  ({len(crit_ports)})[/]")
        console.print()
        for p, label, opp in crit_ports:
            host = p.get("host","")
            num  = p.get("port","")

            # find banner
            b = next(
                (x for x in banners
                 if x.get("port")==num and x.get("host")==host),
                None
            )
            ver = f"  [dim]{b['version']}[/]" if b and b.get("version") else ""

            console.print(
                f"  [red]▸[/]  [bold white]{host}:{num}[/]  "
                f"[red]{label or p.get('service','')}[/]{ver}"
            )
            if opp:
                console.print(f"  [dim]     {opp}[/]")
        console.print()

    # high — compact
    if high_ports:
        console.print(f"  [bold yellow]High Risk Ports  ({len(high_ports)})[/]")
        console.print()
        for p, label, opp in high_ports[:6]:
            host = p.get("host","")
            num  = p.get("port","")
            console.print(
                f"  [yellow]▸[/]  [white]{host}:{num}[/]  "
                f"[yellow]{label or p.get('service','')}[/]  "
                f"[dim]{opp or ''}[/]"
            )
        console.print()

    # web ports — just flag unusual ones
    unusual_web = [p for p in web_ports
                   if p[0].get("port","") not in {80,443}]
    if unusual_web:
        console.print(
            f"  [bright_blue]Uncommon Web Ports[/]  "
            f"[dim](may be less hardened)[/]"
        )
        for p, label, opp in unusual_web[:4]:
            host = p.get("host","")
            num  = p.get("port","")
            console.print(
                f"  [bright_blue]·[/]  [white]{host}:{num}[/]  "
                f"[dim]{label}[/]"
                + (f"  [dim]→ {opp}[/]" if opp else "")
            )
        console.print()

    # standard — just count
    all_std = len(std_ports) + len([p for p in web_ports
                                    if p[0].get("port","") in {80,443}])
    if all_std:
        console.print(f"  [dim]Standard ports: {all_std}[/]")
        console.print()

    # HTTP services — admin / login flags only
    if http:
        admin  = [s for s in http if s.get("is_admin")]
        login  = [s for s in http if s.get("is_login") and not s.get("is_admin")]
        hdr_g  = [s for s in http if s.get("missing_headers")]

        if admin:
            console.print("  [red]Admin panels:[/]")
            for s in admin[:3]:
                console.print(
                    f"  [red]  ▸  {s.get('url','')}[/]  "
                    f"[dim]{s.get('status','')}  "
                    f"→ default creds / brute-force[/]"
                )
            console.print()

        if login:
            console.print("  [yellow]Login surfaces:[/]")
            for s in login[:3]:
                console.print(
                    f"  [yellow]  ·  {s.get('url','')}[/]  "
                    f"[dim]{s.get('status','')}[/]"
                )
            console.print()

        if hdr_g:
            # just the most common missing header
            from collections import Counter
            all_missing = []
            for s in hdr_g:
                all_missing.extend(s.get("missing_headers",[]))
            common = Counter(all_missing).most_common(3)
            gaps = "  ·  ".join(
                f"{h} ({c}x)" for h,c in common
            )
            console.print(
                f"  [bright_blue]Missing headers:[/]  [dim]{gaps}[/]"
            )
            console.print()


def print_analysis_results(results):
    """
    analysis engine — tech mapped to vectors,
    findings correlated into attack scenarios.
    30-second read.
    """

    section("04 · Analysis Engine")

    waf       = results.get("waf", [])
    tech      = results.get("tech_stack", [])
    hints     = results.get("vuln_hints", [])
    chains    = results.get("chains", [])
    endpoints = results.get("js_endpoints", [])
    secrets   = results.get("js_secrets", [])
    ports     = results.get("open_ports", [])
    http      = results.get("http_services", [])
    emails    = results.get("emails", [])
    takeovers = results.get("takeovers", [])
    dns       = results.get("dns_records", {})
    int_txt   = dns.get("interesting_txt", [])

    # ── WAF — one line ─────────────────────────────────
    if waf:
        waf_str = " + ".join(waf)
        # what to do based on WAF type
        strong = any(
            w in waf for w in ["Cloudflare","Akamai","Imperva"]
        )
        strategy = (
            "skip injection scans → IDOR / logic / origin bypass"
            if strong else
            "encoded payloads may pass → manual injection testing"
        )
        console.print(
            f"  [dim]WAF[/]      [yellow]{waf_str}[/]  "
            f"[dim]→ {strategy}[/]"
        )
    else:
        console.print(
            "  [dim]WAF[/]      [red]None[/]  "
            "[dim]→ full exposure — automated tools unimpeded[/]"
        )

    # ── Tech — mapped to attack direction ──────────────
    tech_map = {
        "WordPress":        "xmlrpc.php + plugin CVEs + /wp-admin BF",
        "Laravel":          ".env / APP_DEBUG=true / mass assignment",
        "Django":           "DEBUG=True / /admin BF / CSRF on APIs",
        "ASP.NET":          "ViewState deser / IIS shortname / WebDAV",
        "Next.js":          "/_next/data/ unauthed / API route missing auth",
        "React":            "API calls in bundle / JWT in localStorage",
        "Angular":          "env vars in bundle / source maps",
        "Nginx":            "alias path traversal / open redirect via proxy",
        "Apache":           "dir listing / .htaccess bypass",
        "IIS":              "shortname vuln / WebDAV / ASP handlers",
        "Cloudflare Pages": "static hosting → find origin / focus: app logic",
        "Shopify":          "app layer only → IDOR / checkout / discount abuse",
        "WordPress":        "xmlrpc + plugin CVEs + /wp-admin",
        "Drupal":           "Drupalgeddon — check version / module CVEs",
    }

    if tech:
        console.print()
        console.print("  [bold bright_green]Stack[/]")
        console.print()
        for t in tech[:6]:
            vec = tech_map.get(t, "check CVEs / default configs")
            console.print(
                f"  [bright_green]▸[/]  [white]{t}[/]  "
                f"[dim]→ {vec}[/]"
            )
    console.print()

    # ── Risk findings — compact format ─────────────────
    if hints:
    console.print(
        f"  [bold bright_green]Findings[/]  "
        f"[dim]{len(hints)} total[/]"
    )
    console.print()

    for h in hints:
        sev    = h.get("severity", "Info")
        title  = h.get("title", "")
        hid    = h.get("id", "")

        # severity indicator — no emoji, just color + symbol
        if sev == "Critical":
            sev_str = "[red][Critical][/]"
        elif sev == "High":
            sev_str = "[yellow][High]   [/]"
        elif sev == "Medium":
            sev_str = "[bright_blue][Medium] [/]"
        else:
            sev_str = "[dim][Low]    [/]"

        # generate evidence based on finding ID
        # this is what actually proves the finding is real
        evidence_map = {
            "HDR-001": "Strict-Transport-Security header absent in response",
            "HDR-002": "Content-Security-Policy header absent in response",
            "HDR-003": "X-Frame-Options header absent in response",
            "HDR-004": "X-Content-Type-Options header absent in response",
            "DNS-001": "Domain expiry date within 90 days",
            "DNS-002": "No SPF TXT record found for domain",
            "DNS-003": "_dmarc TXT lookup returned no record",
            "JS-001":  "AWS key pattern matched in JS bundle",
            "JS-002":  "Secret/token pattern matched in client-side JS",
            "PORT-001":"Port 2375 open — Docker API responded",
            "PORT-002":"Port 6379 open — Redis responded without auth prompt",
            "PORT-003":"Port 27017 open — MongoDB responded without auth",
            "PORT-004":"Port 9200 open — Elasticsearch responded without auth",
            "PORT-005":"Port 6443 open — Kubernetes API responded",
            "PORT-006":"Port 23 open — Telnet service responded",
            "PORT-007":"Port 3389 open — RDP service responded",
            "ADM-001": "Admin panel keywords found in HTTP response body",
            "TECH-001":"WordPress detected via /wp-content/ path in HTML",
            "TECH-002":"ASP.NET detected via __VIEWSTATE field in HTML",
            "CVE-001": "CVE identifiers returned by Shodan for this IP",
            "SUB-001": "Subdomain CNAME points to unclaimed external service",
        }

        evidence = evidence_map.get(
            hid,
            f"Detected via automated scan — {hid}"
        )

        console.print(
            f"  {sev_str}  [white]{title}[/]"
        )
        console.print(
            f"  [dim]           Evidence: {evidence}[/]"
        )
        console.print()

    # ── Correlations — scenario format ─────────────────
    has_no_csp   = any("CSP"   in h.get("title","") for h in hints)
    has_no_dmarc = any("DMARC" in h.get("title","") for h in hints)
    has_no_hsts  = any("HSTS"  in h.get("title","") for h in hints)
    login_pages  = [s for s in http if s.get("is_login")]
    sens_ports   = [p for p in ports
                    if p.get("port") in {2375,6379,27017,9200,6443}]

    scenarios = []

    if has_no_csp and endpoints:
        scenarios.append((
            "red",
            f"No CSP + {len(endpoints)} endpoints",
            "XSS unrestricted → inject via input → steal session"
        ))
    if has_no_dmarc:
        email_note = f"+ {len(emails)} targets harvested" if emails else ""
        scenarios.append((
            "yellow",
            f"No DMARC {email_note}",
            "spoof domain → craft phishing email → credential theft"
        ))
    if has_no_hsts and login_pages:
        scenarios.append((
            "yellow",
            f"No HSTS + {len(login_pages)} login page(s)",
            "SSL strip on LAN → creds in cleartext"
        ))
    if secrets and endpoints:
        scenarios.append((
            "red",
            f"{len(secrets)} JS secret(s) + {len(endpoints)} endpoints",
            "auth with leaked key → API access → data exfil / escalate"
        ))
    if sens_ports and not waf:
        svc_list = " · ".join(
            str(p.get("port","")) for p in sens_ports[:3]
        )
        scenarios.append((
            "red",
            f"No WAF + ports {svc_list}",
            "direct connect → no auth default → full data access"
        ))
    if takeovers and has_no_dmarc:
        scenarios.append((
            "red",
            "Takeover + No DMARC",
            "own subdomain + spoof email → undetectable phishing"
        ))

    if scenarios:
        console.print("  [bold bright_green]Attack Scenarios[/]")
        console.print()
        for color, condition, chain in scenarios:
            console.print(
                f"  [{color}]▸[/]  [white]{condition}[/]"
            )
            console.print(
                f"  [dim]     → {chain}[/]"
            )
            console.print()

    # ── Attacker perspective — 3 lines max ─────────────
    console.print("  [bold bright_green]Attacker POV[/]")
    console.print()

    pov = []
    if takeovers:
        pov.append(
            f"Claim `{takeovers[0].get('subdomain','')}` first — free, instant, no skill needed"
        )
    if secrets:
        pov.append(
            f"Test {len(secrets)} leaked secret(s) — fastest path to auth access"
        )
    if sens_ports:
        pov.append(
            f"Hit port(s) {', '.join(str(p.get('port','')) for p in sens_ports[:2])} — likely no auth"
        )
    if not pov:
        pov.append(
            "No critical shortcuts — pivot to manual: auth flows, IDOR, API logic"
        )
        if waf:
            pov.append(f"{' + '.join(waf)} blocks injection — focus IDOR and origin bypass")

    for line in pov[:3]:
        console.print(f"  [dim]→  {line}[/]")
    console.print()


def print_final_summary(results, config, elapsed_total):
    """
    final intelligence report.
    top 3 attack paths, critical entry, first 3 attacker moves.
    30-second read.
    """

    section("Intelligence Report")

    hints      = results.get("vuln_hints", [])
    chains     = results.get("chains", [])
    takeovers  = results.get("takeovers", [])
    secrets    = results.get("js_secrets", [])
    ports      = results.get("open_ports", [])
    endpoints  = results.get("js_endpoints", [])
    emails     = results.get("emails", [])
    subdomains = results.get("subdomains", [])
    http       = results.get("http_services", [])
    waf        = results.get("waf", [])
    tech       = results.get("tech_stack", [])
    dns        = results.get("dns_records", {})
    int_txt    = dns.get("interesting_txt", [])
    bf         = results.get("subdomain_bruteforce", {})
    live       = bf.get("live", [])

    def sev(s):
        return sum(1 for h in hints if h.get("severity") == s)

    # ── score + risk ───────────────────────────────────
    score = (
        len(subdomains)   * 1  +
        len(ports)        * 2  +
        len(endpoints)    * 2  +
        len(secrets)      * 5  +
        len(takeovers)    * 8  +
        sev("Critical")   * 10 +
        sev("High")       * 6  +
        sev("Medium")     * 3
    )

    if score >= 50 or sev("Critical") > 0 or takeovers or secrets:
        risk_str = "[bold red]HIGH[/]"
    elif score >= 20 or sev("High") > 0:
        risk_str = "[bold yellow]MEDIUM[/]"
    else:
        risk_str = "[bold bright_green]LOW[/]"

    # compact score line
    console.print(
        f"  [dim]Score[/]  [bold bright_green]{score}[/]  "
        f"[dim]·[/]  Risk: {risk_str}  "
        f"[dim]·[/]  "
        f"[red]{sev('Critical')} crit[/]  "
        f"[yellow]{sev('High')} high[/]  "
        f"[bright_blue]{sev('Medium')} med[/]  "
        f"[dim]·  {round(elapsed_total,1)}s[/]"
    )
    console.print()

    # ── top 3 attack paths ─────────────────────────────
    console.print(
        "  [bold bright_green]Top 3 Attack Paths[/]"
    )
    console.print()

    paths = []

    if takeovers:
        t = takeovers[0]
        paths.append((
            10,
            "[red]![/]",
            f"Takeover `{t.get('subdomain','')}` → phish under target domain → session hijack",
        ))

    if secrets and endpoints:
        paths.append((
            9,
            "[red]![/]",
            f"Leaked key ({secrets[0].get('type','')}) → auth API → enumerate / escalate",
        ))
    elif secrets:
        paths.append((
            8,
            "🔴",
            f"Test {len(secrets)} leaked secret(s) → direct authenticated access",
        ))

    sens_ports = [
        p for p in ports
        if p.get("port") in {2375,6379,27017,9200,6443,2379,23}
    ]
    if sens_ports:
        p   = sens_ports[0]
        lbl, _, opp = port_intel(p.get("port",""))
        paths.append((
            9,
            "[red]![/]" if p.get("port") in {2375,6443} else "🔴",
            f"Port {p.get('port','')} ({lbl}) → {opp}",
        ))

    admin_svcs = [s for s in http if s.get("is_admin")]
    if admin_svcs:
        paths.append((
            7,
            "🔴",
            f"Admin panel {admin_svcs[0].get('url','')} → cred attack → full access",
        ))

    has_no_dmarc = any("DMARC" in h.get("title","") for h in hints)
    has_no_csp   = any("CSP"   in h.get("title","") for h in hints)

    if has_no_dmarc and emails:
        paths.append((
            6,
            "🟡",
            f"Spoof domain + {len(emails)} targets → phishing → credential theft",
        ))

    if has_no_csp and endpoints:
        paths.append((
            5,
            "🟡",
            f"No CSP + {len(endpoints)} endpoints → find reflected input → XSS → session theft",
        ))

    if not paths:
        paths.append((
            3,
            "🔵",
            "No automated shortcuts — manual: auth bypass, IDOR, API testing",
        ))

    paths.sort(key=lambda x: x[0], reverse=True)
    for i, (_, icon, desc) in enumerate(paths[:3], 1):
        console.print(
            f"  [bold white]{i}.[/]  {icon}  [white]{desc}[/]"
        )
    console.print()

    # ── critical entry point — one line ───────────────
    console.print("  [bold bright_green]Critical Entry Point[/]")
    console.print()

    if takeovers:
        ep = (f"`{takeovers[0].get('subdomain','')}`",
              "takeover — zero skill, instant domain control")
    elif secrets:
        ep = ("leaked API credential in JS",
              "authenticated access — no exploit needed")
    elif sens_ports:
        p  = sens_ports[0]
        lbl, _, opp = port_intel(p.get("port",""))
        ep = (f"port {p.get('port','')} ({lbl})",
              opp or "sensitive service exposed")
    elif admin_svcs:
        ep = (admin_svcs[0].get("url","admin panel"),
              "cred attack surface")
    elif http:
        ep = (http[0].get("url","main app"),
              "manual testing target")
    else:
        ep = ("no clear entry point", "manual recon recommended")

    console.print(
        f"  [red]⚑[/]  [bold white]{ep[0]}[/]  "
        f"[dim]→ {ep[1]}[/]"
    )
    console.print()

    # ── weakest area — one line ────────────────────────
    console.print("  [bold bright_green]Weakest Security Area[/]")
    console.print()

    w_scores = {
        "Secret management":  len(secrets) * 5,
        "Subdomain security": len(takeovers) * 8,
        "Network exposure":   len(sens_ports) * 4,
        "Email security":     3 if has_no_dmarc else 0,
        "Web hardening":      len([h for h in hints
                                   if "header" in h.get("title","").lower()]) * 2,
        "Access control":     len(admin_svcs) * 3,
    }

    top_area  = max(w_scores, key=w_scores.get)
    top_score = w_scores[top_area]

    area_detail = {
        "Secret management":  "creds in client-side code → immediate auth bypass",
        "Subdomain security": "abandoned resources → no-skill domain takeover",
        "Network exposure":   "DB/infra directly on internet → likely no auth",
        "Email security":     "domain spoofable → phishing with no indicators",
        "Web hardening":      "missing headers → XSS / clickjack / SSL strip surface",
        "Access control":     "admin panels public → cred attacks unimpeded",
    }

    if top_score > 0:
        console.print(
            f"  [red]▸[/]  [bold white]{top_area}[/]  "
            f"[dim]→ {area_detail.get(top_area,'')}[/]"
        )
    else:
        console.print(
            "  [dim]Balanced — no dominant weakness from automation[/]"
        )
    console.print()

    # ── first 3 attacker actions ───────────────────────
    console.print("  [bold bright_green]First 3 Attacker Actions[/]")
    console.print()

    actions = []

    if takeovers:
        actions.append((
            "red",
            f"Register {takeovers[0].get('service','')} account → "
            f"claim `{takeovers[0].get('subdomain','')}`"
        ))
    if secrets:
        s = secrets[0]
        actions.append((
            "red",
            f"Test `{s.get('type','')}` against its service  "
            f"[{s.get('value','')[:6]}••]"
        ))
    if sens_ports:
        p   = sens_ports[0]
        lbl, _, opp = port_intel(p.get("port",""))
        actions.append((
            "red",
            f"Connect to {p.get('host','')}:{p.get('port','')} ({lbl}) → {opp}"
        ))
    if len(actions) < 3 and admin_svcs:
        actions.append((
            "yellow",
            f"Cred stuff {admin_svcs[0].get('url','')} — "
            "try default / breached passwords"
        ))
    if len(actions) < 3 and has_no_dmarc:
        actions.append((
            "yellow",
            f"Spoof email as {config['target']} + "
            f"{len(emails)} targets → phishing campaign"
        ))
    if len(actions) < 3 and endpoints:
        actions.append((
            "bright_blue",
            f"Probe {len(endpoints)} API endpoints for IDOR / unauth access in Burp"
        ))
    if not actions:
        actions = [
            ("bright_blue", "Burp Suite active scan on all live HTTP services"),
            ("bright_blue", "Manual auth testing — login bypass, session fixation"),
            ("bright_blue", "Fuzz API endpoints for IDOR and access control gaps"),
        ]

    for i, (color, action) in enumerate(actions[:3], 1):
        console.print(
            f"  [{color}]{i}.[/{color}]  [white]{action}[/]"
        )
    console.print()

    # single footer line
    console.print(
        f"  [dim]── {config['target']}  ·  "
        f"score {score}  ·  "
        f"{round(elapsed_total,1)}s  ·  "
        f"full analysis in .md ──[/]\n"
    )

 

   



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
    section("05 · Saving Report")

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
