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
    # REPLACE the JS secrets block with this:

    if secrets:
    # categorize properly — internal IPs are NOT secrets
        real_secrets = [
            s for s in secrets
            if "Internal IP" not in s.get("type","")
            and "Generic" not in s.get("type","")
        ]
        internal_ips = [
            s for s in secrets
            if "Internal IP" in s.get("type","")
        ]
        generic = [
            s for s in secrets
            if "Generic" in s.get("type","")
            or ("API Key" in s.get("type","")
                and not any(
                    x in s.get("type","")
                    for x in ["AWS","GitHub","Stripe","Firebase"]
                ))
        ]

        console.print("  [bold bright_green]JS Analysis[/]")
        console.print()
        console.print(
            f"  [dim]  Credentials / Keys  [/]  "
            f"[{'red' if real_secrets else 'dim'}]"
            f"{len(real_secrets)}"
            f"[/]"
        )
        console.print(
            f"  [dim]  Generic references  [/]  "
            f"[{'yellow' if generic else 'dim'}]{len(generic)}[/]"
        )
        console.print(
            f"  [dim]  Internal IPs        [/]  "
            f"[bright_blue]{len(internal_ips)}[/]"
            + (f"  [dim](infrastructure hints, not secrets)[/]"
               if internal_ips else "")
        )
        console.print()

    # show real secrets with use case
        secret_use = {
            "AWS":      "-> aws cli s3 ls / iam enumerate",
             "GitHub":   "-> clone private repos",
            "Stripe":   "-> charge cards / read customer PII",
                "Firebase": "-> read/write DB if rules permissive",
            "JWT":      "-> decode -> alg confusion -> forge",
            "Slack":    "-> read messages / post as bot",
        }    

        for s in real_secrets[:6]:
            stype  = s.get("type","")
            val    = s.get("value","")
            masked = val[:6]+"••" if len(val)>6 else val
            file   = s.get("file","")[-35:] if s.get("file") else ""
            use    = next(
                (u for k,u in secret_use.items()
                 if k.lower() in stype.lower()),
                "-> test against discovered endpoints"
            )
            console.print(
                f"  [red]>[/]  [white]{stype}[/]  "
                f"[red]{masked}[/]  "
                f"[dim]{use}[/]"
            )
            if file:
                console.print(f"  [dim]     {file}[/]")
        console.print()

    # internal IPs separately — different category
        if internal_ips:
            console.print(
                "  [bright_blue]Internal infrastructure references:[/]"
            )
            for s in internal_ips[:4]:
                console.print(
                    f"  [bright_blue]>[/]  "
                     f"[white]{s.get('value','')[:40]}[/]  "
                    f"[dim]-> map internal network / pivot targets[/]"
                )
            console.print()
    else:
        console.print("  [dim]JS Analysis — no findings[/]")
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

def endpoint_label(path):
    """
    returns a specific label for an endpoint path.
    avoids generic 'auth bypass' for every sensitive path.
    """
    p = path.lower()
    if "wp-admin" in p or "wp-login" in p:
        return "WordPress admin — test auth controls"
    if "xmlrpc" in p:
        return "WordPress XMLRPC — test brute-force / DoS"
    if "admin-ajax" in p:
        return "WordPress AJAX — review authorization"
    if "config" in p:
        return "Config endpoint — check if auth required"
    if "debug" in p or "trace" in p:
        return "Debug endpoint — should not be public"
    if "backup" in p or ".bak" in p:
        return "Backup file — check if accessible"
    if "internal" in p:
        return "Internal endpoint — verify access controls"
    if "secret" in p or "key" in p:
        return "Sensitive path — check response content"
    return "Sensitive path — review access controls"

for e in crit_eps[:3]:
    console.print(
        f"  [red]>[/]  [white]{e}[/]  "
        f"[dim]<- {endpoint_label(e)}[/]"
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

 # emails — one lin
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
    analysis engine — tech + findings already shown
    in executive summary. this section shows:
    - attack scenarios (correlations only)
    - attacker POV (realistic, not scripted)
    no repetition of what executive summary showed.
    """

    section("Analysis Engine")

    hints     = results.get("vuln_hints", [])
    waf       = results.get("waf", [])
    tech      = results.get("tech_stack", [])
    endpoints = results.get("js_endpoints", [])
    secrets   = results.get("js_secrets", [])
    ports     = results.get("open_ports", [])
    http      = results.get("http_services", [])
    emails    = results.get("emails", [])
    takeovers = results.get("takeovers", [])
    dns       = results.get("dns_records", {})

    # ── WAF — one line ─────────────────────────────────
    waf = results.get("waf", [])
    cdn = results.get("cdn", [])

    if waf:
       console.print(
          f"  [dim]WAF[/]  [red]{' + '.join(waf)}[/]  "
          f"[dim]-> confirmed security filtering[/]"
       )
    if cdn:
       console.print(
          f"  [dim]CDN[/]  [yellow]{' + '.join(cdn)}[/]  "
          f"[dim]-> traffic acceleration, not WAF[/]"
       )
    if not waf and not cdn:
       console.print(
          "  [dim]WAF / CDN  none detected[/]"
       )
    console.print()

    # ── Tech — mapped to attack direction ──────────────
   

    # ── Risk findings — compact format ─────────────────
    has_no_csp   = any("CSP"   in h.get("title","") for h in hints)
    has_no_dmarc = any("DMARC" in h.get("title","") for h in hints)
    has_no_hsts  = any("HSTS"  in h.get("title","") for h in hints)
    login_pages  = [s for s in http if s.get("is_login")]
    sens_ports   = [
        p for p in ports
        if p.get("port") in {2375,6379,27017,9200,6443}
    ]
    real_secrets = [
        s for s in secrets
        if "Internal IP" not in s.get("type","")
        and s.get("type","") not in ["Generic API Key","Generic Secret"]
    ]

    # ── attack scenarios — correlations only ───────────
    # only show combinations — single findings
    # already shown in executive summary
    scenarios = []

    if has_no_csp and endpoints:
        scenarios.append((
            "red",
            f"No CSP + {len(endpoints)} endpoints",
            "XSS unrestricted -> inject via input -> steal session"
        ))

    # only show DMARC scenario if there are actual emails
    # "0 targets" looks bad and is not actionable
    if has_no_dmarc and emails:
        scenarios.append((
            "yellow",
            f"No DMARC + {len(emails)} emails harvested",
            "spoof domain -> targeted phishing -> credential theft"
        ))
    elif has_no_dmarc and not emails:
        # DMARC missing but no emails found
        # show as standalone note, not a full scenario
        scenarios.append((
            "bright_blue",
            "No DMARC",
            "domain spoofable — harvest emails via LinkedIn first"
        ))

    if has_no_hsts and login_pages:
        scenarios.append((
            "yellow",
            f"No HSTS + {len(login_pages)} login page(s)",
            "SSL strip on local network -> creds in cleartext"
        ))

    if real_secrets and endpoints:
        scenarios.append((
            "red",
            f"{len(real_secrets)} JS credential(s) + "
            f"{len(endpoints)} API endpoints",
            "auth with key -> API access -> enumerate / escalate"
        ))

    if sens_ports and not waf:
        svc_list = ", ".join(
            str(p.get("port","")) for p in sens_ports[:2]
        )
        scenarios.append((
            "red",
            f"No WAF + port(s) {svc_list}",
            "direct connect -> test default auth -> data access"
        ))

    if takeovers and has_no_dmarc:
        scenarios.append((
            "red",
            "Takeover candidate + No DMARC",
            "own subdomain + spoof email -> undetectable phishing"
        ))

    if scenarios:
        console.print("  [bold bright_green]Attack Scenarios[/]")
        console.print()
        for color, condition, chain in scenarios:
            console.print(
                f"  [{color}]>[/{color}]  [white]{condition}[/]"
            )
            console.print(
                f"  [dim]     -> {chain}[/]"
            )
            console.print()
    else:
        # clean target — say it clearly
        console.print(
            "  [dim]No compound attack scenarios identified.[/]\n"
            "  [dim]Target shows standard web exposure — "
            "focus on manual testing.[/]"
        )
        console.print()

    # ── attacker POV — realistic sequence ─────────────
    console.print("  [bold bright_green]Attacker POV[/]")
    console.print()
    console.print(
        "  [dim]Most likely test sequence:[/]"
    )
    console.print()

    steps = []

    if takeovers:
        steps.append(
            f"Register {takeovers[0].get('service','')} "
            f"resource -> claim "
            f"`{takeovers[0].get('subdomain','')}`"
        )
    if real_secrets:
        s = real_secrets[0]
        steps.append(
            f"Validate {s.get('type','')} from JS "
            f"-> test against its service"
        )
    if sens_ports:
        p   = sens_ports[0]
        lbl, _, opp = port_intel(p.get("port",""))
        steps.append(
            f"Connect to {p.get('host','')}:{p.get('port','')} "
            f"({lbl}) -> {opp}"
        )
    if not steps and waf:
        steps.append(
            f"WAF detected ({', '.join(waf)}) — "
            f"find origin IP via cert history / DNS"
        )
        steps.append(
            "Test business logic and IDOR on API endpoints"
        )
    if has_no_dmarc and emails:
        steps.append(
            f"Use {len(emails)} harvested emails — "
            f"craft spoofed phishing campaign"
        )
    if endpoints and not steps:
        steps.append(
            f"Probe {len(endpoints)} API endpoints — "
            f"IDOR / auth bypass / rate limiting"
        )

    # default for clean targets — honest, not scripted
    if not steps:
        steps = [
            "Run Burp Suite on live HTTP services",
            "Check robots.txt, sitemap.xml on all subdomains",
            "Test session management and auth flows manually",
        ]

    for i, step in enumerate(steps[:4], 1):
        console.print(f"  [dim]{i}.  {step}[/]")
    console.print()
   


def print_executive_summary(results, config, elapsed):
    """
    prints first — executive summary at top.
    risk level + reason, fingerprinting,
    recommended testing focus, top findings.
    no repetition of what raw sections will show.
    """

    section("Executive Summary")

    hints      = results.get("vuln_hints", [])
    waf        = results.get("waf", [])
    tech       = results.get("tech_stack", [])
    secrets    = results.get("js_secrets", [])
    takeovers  = results.get("takeovers", [])
    ports      = results.get("open_ports", [])
    endpoints  = results.get("js_endpoints", [])
    emails     = results.get("emails", [])
    subdomains = results.get("subdomains", [])
    http       = results.get("http_services", [])
    dns        = results.get("dns_records", {})
    int_txt    = dns.get("interesting_txt", [])

    def sev(s):
        return sum(1 for h in hints if h.get("severity") == s)

    # helpers
    sens_ports = [
        p for p in ports
        if p.get("port") in {2375,6379,27017,9200,6443,2379,23,3389,5900}
    ]
    real_secrets = [
        s for s in secrets
        if "Internal IP" not in s.get("type","")
        and s.get("type","") not in ["Generic API Key","Generic Secret"]
    ]
    admin_svcs = [s for s in http if s.get("is_admin")]
    has_no_dmarc = any(
        "DMARC" in h.get("title","") for h in hints
    )
    has_no_csp = any(
        "CSP" in h.get("title","") for h in hints
    )

    # ── target line ────────────────────────────────────
    console.print(
        f"  [dim]Target[/]    "
        f"[bold white]{config['target']}[/]  "
        f"[dim]IP[/] [white]{results.get('ip','?')}[/]  "
        f"[dim]Server[/] [white]{results.get('server','?')}[/]"
    )
    console.print()

    # ── risk level + reasons ───────────────────────────
    # calculate
    if (sev("Critical") > 0 or takeovers
            or real_secrets or sens_ports):
        risk     = "HIGH"
        risk_clr = "red"
    elif sev("High") > 0 or sev("Medium") >= 3:
        risk     = "MEDIUM"
        risk_clr = "yellow"
    else:
        risk     = "LOW"
        risk_clr = "bright_green"

    console.print(
        f"  [dim]Risk[/]      "
        f"[{risk_clr}]{risk}[/{risk_clr}]  "
        f"[dim]·  {sev('Critical')} crit  "
        f"{sev('High')} high  "
        f"{sev('Medium')} med[/]"
    )
    console.print()

    # reasons — only show real ones, skip empty
    reasons = []
    if takeovers:
        reasons.append(
            f"{len(takeovers)} subdomain takeover candidate(s)"
        )
    if real_secrets:
        reasons.append(
            f"{len(real_secrets)} credential(s) in JS files"
        )
    if sens_ports:
        names = []
        for p in sens_ports[:2]:
            lbl, _, _ = port_intel(p.get("port",""))
            names.append(lbl or str(p.get("port","")))
        reasons.append(
            f"sensitive service(s) exposed: {', '.join(names)}"
        )
    if sev("Critical") > 0:
        reasons.append(f"{sev('Critical')} critical finding(s)")
    if has_no_dmarc:
        reasons.append("no DMARC — domain spoofable")

    if reasons:
        console.print("  [dim]Reason[/]")
        for r in reasons:
            console.print(f"  [dim]    -  {r}[/]")
        console.print()

    # ── fingerprinting ─────────────────────────────────
    
    waf = results.get("waf", [])
    cdn = results.get("cdn", [])

    console.print("  [bold bright_green]Fingerprinting[/]")
    console.print()

    # WAF — only if true WAF detected
    if waf:
       strong = any(
          w in waf
          for w in ["Cloudflare WAF","Akamai WAF",
                  "Imperva","AWS WAF","F5 BIG-IP ASM"]
       )
       console.print(
            f"  [dim]WAF[/]       [red]{' + '.join(waf)}[/]  "
            f"[dim]-> "
            + ("strong — focus IDOR / logic / origin IP"
               if strong else
               "present — injection may be filtered")
            + "[/]"
       )
    else:
         console.print(
          "  [dim]WAF[/]       [dim]none detected[/]"
         )

    # CDN — separate from WAF
    if cdn:
         console.print(
         f"  [dim]CDN[/]       [yellow]{' + '.join(cdn)}[/]  "
         f"[dim]-> real IP hidden — find origin[/]"
         )
    else:
         console.print(
         "  [dim]CDN[/]       [dim]none detected[/]"
         )   
    if tech:
         console.print()

        # group by category
              categories = {
                  "Web Server": ["Nginx","Apache","IIS","Litespeed","Tomcat"],
                  "Framework":  ["Laravel","Django","Ruby on Rails","ASP.NET",
                                 "Spring Boot","Symfony","Flask","PHP"],
                  "Frontend":   ["React","Vue.js","Angular","Next.js",
                                  "jQuery","Bootstrap"],
                  "CMS":        ["WordPress","Drupal","Joomla","Magento",
                                   "Shopify","Wix","Squarespace","WooCommerce"],
                  "CDN / Host": ["Cloudflare Pages","AWS CloudFront","Fastly",
                                "Vercel","Netlify","GitHub Pages","Cloudflare"],
              }

              tech_attack = {
                   "WordPress":       "xmlrpc.php · plugin CVEs · /wp-admin BF",
                    "Drupal":          "Drupalgeddon CVEs · module exploits",
                   "Joomla":          "component vulns · admin panel BF",
                   "Magento":         "admin panel · Magmi upload · SQLi history",
                    "Laravel":         ".env leak · APP_DEBUG=true",
                   "Django":          "DEBUG mode · /admin BF · CSRF on APIs",
                   "ASP.NET":         "ViewState deser · IIS shortname",
                   "Next.js":         "/_next/data/ unauthed · API route auth",
                  "React":           "secrets in bundle · JWT in localStorage",
                   "Angular":         "env vars in bundle · source maps",
                  "PHP":             "LFI / RFI · type juggling",
                   "Nginx":           "alias traversal · proxy open redirect",
                   "Apache":          "dir listing · .htaccess bypass",
                   "IIS":             "shortname vuln · WebDAV",
                 "Spring Boot":     "/actuator — info disclosure",
                   "Tomcat":          "manager default creds · PUT method",
                  "Shopify":         "IDOR · checkout bypass · discount abuse",
                  "Cloudflare Pages":"find origin IP · focus app logic",
                  "Cloudflare":      "find origin IP · bypass CDN",
                   "Vercel":          "find origin · env var leaks in JS",
                  "Netlify":         "find origin · build log exposure",
                  "AWS CloudFront":  "find origin · S3 bucket check",
               }

        all_cat_members = [m for ms in categories.values() for m in ms]
        shown = set()

        for cat, members in categories.items():
            matching = [t for t in tech if t in members]
            for t in matching:
                if t in shown:
                    continue
                shown.add(t)
                vec = tech_attack.get(t, "check CVEs / defaults")
                console.print(
                    f"  [dim]{cat:<12}[/]  "
                    f"[white]{t}[/]  "
                    f"[dim]-> {vec}[/]"
                )

        for t in tech:
            if t not in shown:
                console.print(
                    f"  [dim]{'Other':<12}[/]  [white]{t}[/]"
                )

    console.print()

    # ── recommended testing focus ──────────────────────
    console.print("  [bold bright_green]Recommended Testing Focus[/]")
    console.print()

    high_f   = []
    medium_f = []
    low_f    = []

    # high — based on real findings only
    if takeovers:
        high_f.append(
            "Subdomain takeover — register service, test cookie scope"
        )
    if real_secrets:
        high_f.append(
            "Credential validation — test leaked keys against services"
        )
    if sens_ports:
        high_f.append(
            "Unauthenticated service access — "
            + ", ".join(
                str(p.get("port","")) for p in sens_ports[:2]
            )
        )
    if admin_svcs:
        high_f.append(
            "Admin panel — default creds / brute-force"
        )
    if any(t in tech for t in
           ["React","Angular","Vue.js","Next.js"]):
        high_f.append(
            "API authorization — JS app relies on backend API"
        )
    if any(t in tech for t in
           ["WordPress","Drupal","Magento","Joomla"]):
        high_f.append(
            "CMS exploits — plugin CVEs / admin panel access"
        )

    # medium
    if waf and any(
        w in waf
        for w in ["Cloudflare","Akamai","AWS CloudFront","Fastly"]
    ):
        medium_f.append(
            "Origin IP discovery — bypass CDN to reach real server"
        )
    if endpoints:
        medium_f.append(
            f"API endpoint testing — {len(endpoints)} paths "
            f"(IDOR / auth bypass)"
        )
    if has_no_dmarc:
        medium_f.append(
            "Email spoofing — domain has no DMARC protection"
        )
    if any(t in tech for t in
           ["Laravel","Django","ASP.NET","Spring Boot","PHP"]):
        medium_f.append(
            "Framework misconfig — debug mode / config exposure"
        )

    # low
    missing_hdr_svcs = [
        s for s in http if s.get("missing_headers")
    ]
    if missing_hdr_svcs:
        low_f.append(
            "Security headers — CSP / HSTS / X-Frame-Options"
        )
    if len(subdomains) > 5:
        low_f.append(
            f"Subdomain review — {len(subdomains)} found, "
            f"check each for auth gaps"
        )

    if high_f:
        console.print("  [red]High[/]")
        for f in high_f[:4]:
            console.print(f"  [dim]    -  {f}[/]")
        console.print()
    if medium_f:
        console.print("  [yellow]Medium[/]")
        for f in medium_f[:3]:
            console.print(f"  [dim]    -  {f}[/]")
        console.print()
    if low_f:
        console.print("  [bright_blue]Low[/]")
        for f in low_f[:2]:
            console.print(f"  [dim]    -  {f}[/]")
        console.print()

    if not high_f and not medium_f:
        console.print(
            "  [dim]-  No critical automated findings[/]\n"
            "  [dim]-  Manual testing: auth flows, IDOR, business logic[/]"
        )
        console.print()

    # ── top findings — evidence-backed, no repetition ──
    if hints:
        console.print("  [bold bright_green]Findings[/]")
        console.print()

        evidence_map = {
            "HDR-001": "Strict-Transport-Security absent in response",
            "HDR-002": "Content-Security-Policy absent in response",
            "HDR-003": "X-Frame-Options absent in response",
            "HDR-004": "X-Content-Type-Options absent in response",
            "DNS-001": "Expiry date within 90 days per WHOIS",
            "DNS-002": "No SPF TXT record found for domain",
            "DNS-003": "_dmarc TXT record lookup returned empty",
            "JS-001":  "AWS key pattern matched in JS bundle",
            "JS-002":  "Secret pattern matched in client-side JS",
            "PORT-001":"Port 2375 TCP connect confirmed",
            "PORT-002":"Port 6379 responded without auth",
            "PORT-003":"Port 27017 responded without auth",
            "PORT-004":"Port 9200 responded without auth",
            "PORT-005":"Port 6443 TCP connect confirmed",
            "PORT-006":"Port 23 Telnet responded",
            "PORT-007":"Port 3389 RDP responded",
            "ADM-001": "Login keywords in page title or URL path",
            "SUB-001": "CNAME target returned unclaimed service page",
            "CVE-001": "CVE IDs returned by Shodan for this IP",
            "TECH-001":"WordPress paths in HTML source",
            "TECH-002":"__VIEWSTATE field in HTML",
        }

        impact_map = {
            "HDR-001": "SSL stripping possible on local network",
            "HDR-002": "XSS payload execution unrestricted",
            "HDR-003": "Clickjacking via iframe embed",
            "HDR-004": "MIME-type confusion attacks",
            "DNS-001": "Domain hijack if not renewed",
            "DNS-002": "Domain spoofable for email phishing",
            "DNS-003": "Phishing email lands in inbox — no SPF check",
            "JS-001":  "Direct AWS access without exploit",
            "JS-002":  "Authenticated service access via leaked key",
            "PORT-001":"Full server takeover via container escape",
            "PORT-002":"Read/write all data — potential RCE",
            "PORT-003":"Full database access without credentials",
            "PORT-004":"Full Elasticsearch access",
            "PORT-005":"Kubernetes cluster control",
            "PORT-006":"Credentials visible on network",
            "PORT-007":"Brute-force / known exploit surface",
            "ADM-001": "Credential attack surface exposed",
            "SUB-001": "Subdomain claimable for phishing",
            "CVE-001": "Known exploits may apply",
            "TECH-001":"Plugin CVEs / admin panel exposure",
            "TECH-002":"Deserialization risk if MAC check disabled",
        }

        # sort critical first
        ordered = sorted(
            hints,
            key=lambda h: {
                "Critical":0,"High":1,
                "Medium":2,"Low":3,"Info":4
            }.get(h.get("severity","Info"), 5)
        )

        for h in ordered[:8]:
            sev_s  = h.get("severity","Info")
            title  = h.get("title","")
            hid    = h.get("id","")

            sev_clr = {
                "Critical": "red",
                "High":     "yellow",
                "Medium":   "bright_blue",
                "Low":      "dim",
                "Info":     "dim",
            }.get(sev_s, "dim")

            ev  = evidence_map.get(hid, "detected via automated scan")
            imp = impact_map.get(hid, "")

            console.print(
                f"  [{sev_clr}][{sev_s}][/{sev_clr}]  "
                f"[white]{title}[/]"
            )
            if imp:
                console.print(
                    f"  [dim]           Impact:   {imp}[/]"
                )
            console.print(
                f"  [dim]           Evidence: {ev}[/]"
            )
            console.print()

    # ── divider before raw sections ────────────────────
    console.print(
        f"  [dim]── raw recon data below  ·  "
        f"{round(elapsed,1)}s ──[/]"
    )
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

    # ── validation ─────────────────────────────────────
    with Progress(
        SpinnerColumn(spinner_name="dots2", style="bright_green"),
        TextColumn("  [dim]resolving target...[/]"),
        transient=True, console=console,
    ) as p:
        p.add_task("", total=None)
        validation = validate_target(config["target"], config)

    if not validation.get("is_valid"):
        console.print(
            f"\n  [red]-  "
            f"{validation.get('error','invalid target')}[/]\n"
        )
        sys.exit(1)

    results.update(validation)

    console.print(
        f"  [bright_green]+[/]  "
        f"[bold white]{config['target']}[/]  "
        f"[dim]->[/]  [white]{validation.get('ip','?')}[/]  "
        f"[dim]server[/] [white]{validation.get('server','?')}[/]  "
        f"[dim]https[/] "
        + ("[bright_green]yes[/]"
           if validation.get("https") else "[red]no[/]")
    )
    console.print()

    # ── run all stages silently ────────────────────────
    try:
        run_stage("Passive Recon", run_passive_recon,
                  (config["target"],), config, results)

        run_stage("Active Recon", run_active_recon,
                  (config["target"], config["wordlist"]),
                  config, results)

        targets_to_scan = (
            results.get("subdomains", [])[:5] + [config["target"]]
        )
        run_stage("Service Discovery", run_service_discovery,
                  (targets_to_scan,), config, results)

        run_stage("Analysis Engine", run_analysis,
                  (results,), config, results)

    except KeyboardInterrupt:
        console.print("\n  [yellow]!  interrupted[/]\n")

    elapsed = time.time() - total_start

    # ── save report silently ───────────────────────────
    report_path = None
    try:
        report_paths = generate_report(results, config)
        if report_paths:
            # just store path for footer line
            report_path = list(report_paths.values())[0]
    except Exception:
        pass

    # ── print in correct order ─────────────────────────
    # executive summary FIRST — most important at top
    if not config["quiet"]:
        print_executive_summary(results, config, elapsed)
        print_passive_results(results)
        print_active_results(results)
        print_services_results(results)
        print_analysis_results(results)

    # single footer line — no section header
    console.print(
        f"  [dim]done  ·  {config['target']}  ·  "
        f"{round(elapsed,1)}s"
        + (f"  ·  report -> {report_path}" if report_path else "")
        + "[/]\n"
    )

if __name__ == "__main__":
    main()
