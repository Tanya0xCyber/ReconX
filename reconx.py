#!/usr/bin/env python3
"""
reconx.py —
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
    console.print("  [bold white]Automated Reconnaissance Framework[/]")
    console.print()

    console.print(
       "  [dim]recon pipeline[/]  "
       "[green]•[/]  "
       "[dim]attack surface[/]  "
       "[green]•[/]  "
       "[dim]pentest[/]"
    )

    console.print("  [dim]Author :[/] Tanya Singh" 
        "[green]|[/]  "
        "[dim]Version:[/] v1.0")

    console.print("[green]" + "="*90 + "[/]")
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
                f"  [red]-  {name} failed — {e}[/]"
            )
            if config.get("verbose"):
                import traceback
                traceback.print_exc()
            results[f"{name}_error"] = str(e)
            return False

    elapsed = round(time.time() - stage_start, 2)
    # store stage timing silently — shown in final summary
    results[f"_stage_time_{name.lower().replace(' ','')}"] = elapsed
    return True

# ══════════════════════════════════════════════════════
#  INTELLIGENCE HELPERS
#  used by all print functions below
# ══════════════════════════════════════════════════════

def tag_subdomain(name):
    """categorizes subdomain — returns (tag, color, priority)"""
    n = name.lower()
    if any(x in n for x in ["admin","panel","manage","dashboard","cms","cpanel"]):
         # exclude known email security subdomains that contain "manage"
        if any(skip in n for skip in ["mta-sts","managed.","management-mail"]):
           pass  # fall through to other checks
        else:
           return "Admin", "red", 3
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
    if any(x in n for x in ["login","signin","auth","sso","oauth","account"]):
        return "Auth", "yellow", 2
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
    
def subsection(title):
    """smaller divider for sub-sections inside Attack Surface"""
    console.print(f"  [bold green]{title}[/]")
    console.print()
# ══════════════════════════════════════════════════════
#  SECTION 1 — EXECUTIVE SUMMARY
#  Risk + Top Findings + Recommended Testing Focus
# ══════════════════════════════════════════════════════

def print_executive_summary(results, config, elapsed):
    section("Executive Summary")
    hints      = results.get("vuln_hints", [])
    secrets    = results.get("js_secrets", [])
    takeovers  = results.get("takeovers", [])
    ports      = results.get("open_ports", [])
    http       = results.get("http_services", [])

    def sev(s):
        return sum(1 for h in hints if h.get("severity") == s)

    real_secrets = [
        s for s in secrets
        if "Internal IP" not in s.get("type","")
        and s.get("type","") not in ["Generic API Key","Generic Secret"]
    ]
    sens_ports = [
        p for p in ports
        if p.get("port") in {2375,6379,27017,9200,6443,2379,23,3389,5900}
    ]
    admin_svcs = [s for s in http if s.get("is_admin")]
    bf        = results.get("subdomain_bruteforce",{})
    live_subs = bf.get("live",[])
    has_no_dmarc = any("DMARC" in h.get("title","") for h in hints)

    
    non_header_medium = sum(
        1 for h in hints
        if h.get("severity") == "Medium"
        and "header" not in h.get("title","").lower()
        and "expires"  not in h.get("title","").lower()
        and "clickjack" not in h.get("title","").lower()
    )

    if sev("Critical") > 0 or takeovers or real_secrets or sens_ports:
        risk, risk_clr = "HIGH",   "red"
    elif sev("High") > 0 or non_header_medium >= 2:
        risk, risk_clr = "MEDIUM", "yellow"
    else:
        risk, risk_clr = "LOW",    "bright_green"

    # ── Risk ──────────────────────────────────────────
    console.print(
       "[bright_cyan]◆[/] [bold bright_green] Risk Assessment[/]"
    )
    console.print()
    console.print(
       f"[cyan]  Critical[/] : [white]{sev('Critical')}[/]"
    )
    console.print(
       f"[cyan]  High[/]     : [white]{sev('High')}[/]"
    )
    console.print(
       f"[cyan]  Medium[/]   : [white]{sev('Medium')}[/]"
    )
    console.print(
       f"[cyan]  Low[/]      : [white]{sev('Low')}[/]"
    ) 
    
    # ── Top Findings ──────────────────────────────────
    console.print(
      "[bright_cyan]◆[/] [bold bright_green]Top findings[/]"
    )
    if hints:
        ordered = sorted(
            hints,
            key=lambda h: {
                "Critical":0,"High":1,"Medium":2,"Low":3,"Info":4
            }.get(h.get("severity","Info"), 5)
        )
        has_real = any(h.get("severity") != "Info" for h in ordered)

        evidence_map = {
            "HDR-001": "Strict-Transport-Security absent in response",
            "HDR-002": "Content-Security-Policy absent in response",
            "HDR-003": "X-Frame-Options absent in response",
            "HDR-004": "X-Content-Type-Options absent in response",
            "DNS-001": "Expiry date within 90 days per WHOIS",
            "DNS-002": "No SPF TXT record — DNS lookup confirmed",
            "DNS-003": "_dmarc TXT record absent — DNS lookup confirmed",
            "JS-001":  "AWS key pattern matched in JS bundle",
            "JS-002":  "Secret pattern matched in client-side JS",
            "PORT-001":"Port 2375 TCP connect confirmed",
            "PORT-002":"Port 6379 TCP connect confirmed",
            "PORT-003":"Port 27017 TCP connect confirmed",
            "PORT-004":"Port 9200 TCP connect confirmed",
            "PORT-005":"Port 6443 TCP connect confirmed",
            "PORT-006":"Port 23 TCP connect confirmed",
            "PORT-007":"Port 3389 TCP connect confirmed",
            "ADM-001": "URL path or page title matched admin pattern",
            "SUB-001": "CNAME points to unclaimed external service",
            "CVE-001": "CVE IDs returned by Shodan for this IP",
            "TECH-001":"WordPress path pattern in HTML source",
            "TECH-002":"__VIEWSTATE field in HTML form",
        }

        impact_map = {
            "HDR-001": "SSL stripping possible on local network",
            "HDR-002": "XSS payloads execute without restriction",
            "HDR-003": "Page embeddable in iframe — clickjacking",
            "HDR-004": "MIME-type confusion attacks possible",
            "DNS-001": "Domain hijackable if registration lapses",
            "DNS-002": "Anyone can send email as this domain",
            "DNS-003": "Spoofed email passes inbox delivery checks",
            "JS-001":  "Direct AWS access — S3, IAM, EC2 enumeration",
            "JS-002":  "Potential authenticated access via leaked key",
            "PORT-001":"Mount host filesystem — full server takeover",
            "PORT-002":"Read/write all data — RCE via SLAVEOF possible",
            "PORT-003":"Full database read/write without credentials",
            "PORT-004":"Full Elasticsearch index access",
            "PORT-005":"Kubernetes cluster control if misconfigured",
            "PORT-006":"Credentials transmitted in cleartext",
            "PORT-007":"Brute-force / known exploit entry point",
            "ADM-001": "Credential attacks on admin interface",
            "SUB-001": "Attacker can claim subdomain for phishing",
            "CVE-001": "Known exploits may apply — verify patch status",
            "TECH-001":"Plugin CVEs and admin panel exposure",
            "TECH-002":"Deserialization risk if MAC check disabled",
        }

        confidence_map = {
            "HDR-001":"High", "HDR-002":"High",
            "HDR-003":"High", "HDR-004":"High",
            "DNS-001":"High", "DNS-002":"High", "DNS-003":"High",
            "JS-001": "High", "JS-002": "Medium",
            "PORT-001":"High","PORT-002":"High","PORT-003":"High",
            "PORT-004":"High","PORT-005":"Medium",
            "PORT-006":"High","PORT-007":"High",
            "ADM-001":"Medium","SUB-001":"Medium",
            "CVE-001":"Medium","TECH-001":"High","TECH-002":"High",
        }
          
        
        if has_real:
            # table for findings
            t = Table(
                show_header=False,
                box=None,
                padding=(0, 2),
                show_edge=False,
            )
            t.add_column("sev",   width=10)
            t.add_column("title", style="white")
                   
        for h in ordered[:6]:
            if h.get("severity") == "Info":
                continue
            sev_s = h.get("severity","Info")
            hid   = h.get("id","")

            sev_clr = {
                "Critical":"red","High":"yellow",
                "Medium":"bright_blue","Low":"dim"
            }.get(sev_s,"dim")
            t.add_row(
                f"[{sev_clr}][{sev_s}][/{sev_clr}]",
                h.get("title","")
            )
      
        console.print(t)
        console.print()
    else:
        console.print( "  [dim]  No confirmed findings from automated scan.[/]" )
        console.print()

    # ── Recommended Testing Focus ──────────────────────
    console.print(
       "[bright_cyan]◆[/] [bold bright_green] Recommended Testing Focus [/]"
    )
    console.print()
    tech      = results.get("tech_stack",[])
    endpoints = results.get("js_endpoints",[])
    emails    = results.get("emails",[])
    cdn       = results.get("cdn",[])
    waf       = results.get("waf",[])
    admin_svcs = [s for s in http if s.get("is_admin")]
    bf        = results.get("subdomain_bruteforce",{})
    live_subs = bf.get("live",[])
    has_no_dmarc = any("DMARC" in h.get("title","") for h in hints)

    interesting_subs = [
        s for s in live_subs
        if tag_subdomain(s.get("subdomain",""))[2] >= 2  # priority >= 2
        and s.get("status") != 404
    ]
    high_f   = []
    medium_f = []
    low_f    = []


    # high — only when something concrete found
    if takeovers:
        high_f.append("Subdomain takeover — claim service, test cookie scope")
    if real_secrets:
        high_f.append("Validate leaked credentials against their services")
    if sens_ports:
        port_list = ", ".join(str(p.get("port","")) for p in sens_ports[:2])
        high_f.append(f"Unauthenticated service access — port(s) {port_list}")
    if admin_svcs:
        high_f.append("Admin panel credential testing — default creds / BF")
    if any(t in tech for t in ["WordPress","Drupal","Magento","Joomla"]):
        high_f.append("CMS-specific testing — plugin CVEs, admin panel")
    if any(t in tech for t in ["React","Angular","Vue.js","Next.js"]):
        high_f.append("API authorization testing — JS app relies on APIs")

    # medium — useful but not urgent
    if cdn:
        medium_f.append("Origin IP discovery — cert history, SPF, DNS records")
    if endpoints:
        medium_f.append(
            f"API endpoint testing — {len(endpoints)} path(s) found "
            f"(IDOR, auth bypass, rate limiting)"
        )
    if has_no_dmarc and emails:
        medium_f.append(
            f"Email spoofing test — no DMARC, "
            f"{len(emails)} address(es) available"
        )
    if any(t in tech for t in ["Laravel","Django","ASP.NET","Spring Boot","PHP"]):
        medium_f.append("Framework misconfiguration — debug mode, config exposure")
    if interesting_subs:
        medium_f.append(
           f"Subdomain access control — {len(interesting_subs)} interesting subdomains found"
        )
    elif len(live_subs) > 3:
        low_f.append(
           f"Review {len(live_subs)} live subdomains — ")
        

    # low — worth noting
    missing_hdrs = [s for s in http if s.get("missing_headers")]
    if missing_hdrs:
        low_f.append("Security header review — CSP, HSTS, X-Frame-Options")
    if waf:
        low_f.append("WAF bypass testing — header manipulation, encoding")

    if not high_f and not medium_f and not low_f:
        console.print(
            "  [dim]-  No automated shortcuts found[/]\n"
            "  [dim]-  Manual testing: auth flows, IDOR, business logic[/]"
        )
        console.print()
        return
        
    rec_table = Table(
        show_header=False,
        box=None,
        padding=(0, 2),
        show_edge=False,
    )
    rec_table.add_column("priority", width=12)
    rec_table.add_column("item",     style="dim")

    for f in high_f[:4]:
        rec_table.add_row("[red]HIGH[/]", f)
    for f in medium_f[:3]:
        rec_table.add_row("[yellow]MEDIUM[/]", f)
    for f in low_f[:2]:
        rec_table.add_row("[bright_blue]LOW[/]", f)

    console.print(rec_table)
    console.print()


# ══════════════════════════════════════════════════════
#  SECTION 2 — TARGET INFORMATION
#  Domain, IP, HTTPS, Server, CDN, WAF
# ══════════════════════════════════════════════════════

def print_target_info(results, config):

    section("Target Information")

    waf = results.get("waf", [])
    cdn = results.get("cdn", [])

    raw_server = results.get("server","—")

    cdn_server_values = {
        "cloudflare", "fastly", "cloudfront",
        "vercel", "netlify", "akamai", "github.com"
    }
    server_is_cdn = any(
        cdn_val in raw_server.lower()
        for cdn_val in cdn_server_values
    )

    display_server = (
        "Unknown (hidden behind CDN)"
        if server_is_cdn and cdn
        else raw_server
    )

    

    t = Table(
        show_header=False,
        box=None,
        padding=(0, 2),
        show_edge=False,
    )
    t.add_column("label", style="cyan",  width=12)
    t.add_column("value", style="white")

    t.add_row("Domain",  config["target"])
    t.add_row("IP",      results.get("ip","—"))
    t.add_row("HTTPS",   "Yes" if results.get("https") else "No")
    t.add_row("Server",  display_server)
    
    # CDN — shown only if detected
    if cdn:
        t.add_row(
            "CDN",
            f"[yellow]{' + '.join(cdn)}[/]  [dim]→ origin IP hidden[/]"
        )
    else:
        t.add_row("CDN", "[dim]none detected[/]")

    if waf:
        t.add_row(
            "WAF",
            f"[red]{' + '.join(waf)}[/]  [dim]→ security filtering active[/]"
        )

    console.print(t)
    console.print()

    # WHOIS — domain registration context
    whois = results.get("whois",{})
    if whois and not whois.get("error"):
        has_any = any([
            whois.get("registrar"), whois.get("registrant_org"),
            whois.get("created"),   whois.get("expires"),
        ])
        if has_any:
            console.print("  [cyan]Registration[/]")
            console.print()

            reg = Table(
                show_header=False,
                box=None,
                padding=(0, 2),
                show_edge=False,
            )
            reg.add_column("label", style="dim",   width=14)
            reg.add_column("value", style="white")

            for k, v in [
                ("Registrar", whois.get("registrar","")),
                ("Org",       whois.get("registrant_org","")),
                ("Created",   whois.get("created","")),
                ("Expires",   whois.get("expires","")),
            ]:
                if v:
                    reg.add_row(k, v)

            console.print(reg)

            expires = whois.get("expires","")
            if expires:
                try:
                    from datetime import datetime as dt
                    days = (dt.strptime(expires,"%Y-%m-%d") - dt.now()).days
                    if days < 90:
                        console.print()
                        console.print(
                            f"  [red]!  Expires in {days}d[/]  "
                            f"[dim]→ domain hijack risk[/]"
                        )
                except Exception:
                    pass
            console.print()

    # NS context
    ns = whois.get("name_servers",[]) if whois else []
    if ns:
        ns_str = " ".join(ns).lower()
        hint   = ""
        if "cloudflare" in ns_str:
            hint = "[dim]-> Cloudflare DNS — origin IP hidden[/]"
        elif "awsdns" in ns_str:
            hint = "[dim]-> AWS Route53 — check for S3 buckets[/]"
        console.print(
            f"  [cyan]NS[/]  [white]{' · '.join(ns[:2])}[/]{hint}"
        )
        console.print()

    # DNS records
    dns = results.get("dns_records",{})
    if dns:
        dns_t = Table(
            show_header=False,
            box=None,
            padding=(0, 2),
            show_edge=False,
        )
        dns_t.add_column("type",  style="green", width=8)
        dns_t.add_column("value", style="white")

        for rtype in ["A","MX","NS","CNAME"]:
            records = dns.get(rtype,[])
            if not records:
                continue
            vals = []
            for r in records[:2]:
                if isinstance(r, dict):
                    vals.append(f"[{r.get('priority','')}] {r.get('host','')}")
                else:
                    vals.append(str(r)[:55])
            dns_t.add_row(rtype, " · ".join(vals))

        console.print(dns_t)

        mx = dns.get("MX",[])
        if mx:
            mx_str = str(mx).lower()
            if "google" in mx_str:
                console.print("  [dim]  Google Workspace[/]")
            elif "outlook" in mx_str or "microsoft" in mx_str:
                console.print("  [dim]  Microsoft 365[/]")
        console.print()


    # email security
    email_sec  = results.get("email_security",{})
    spf_data   = email_sec.get("spf",{})
    dmarc_data = email_sec.get("dmarc",{})
    spf_conf   = spf_data.get("confidence","low")
    dmarc_conf = dmarc_data.get("confidence","low")

    email_t = Table(
        show_header=False,
        box=None,
        padding=(0, 2),
        show_edge=False,
    )
    email_t.add_column("label", style="cyan", width=8)
    email_t.add_column("value")
     
    if spf_conf == "high":
        spf_val = (
            "[green]present[/]"
            if spf_data.get("present") else
            "[red]missing[/]  [dim]→ domain spoofable[/]"
        )
        email_t.add_row("SPF", spf_val)

    if dmarc_conf == "high":
        dmarc_val = (
            "[green]present[/]"
            if dmarc_data.get("present") else
            "[red]missing[/]  [dim]→ spoofed email passes delivery[/]"
        )
        email_t.add_row("DMARC", dmarc_val)

    if spf_conf == "high" or dmarc_conf == "high":
        console.print(email_t)
        console.print()

    # ISP / ASN
    geo = results.get("geo_asn",{})
    if geo and not geo.get("error"):
        console.print(
            f"  [cyan]ISP[/]  "
            f"[white]{geo.get('isp','—')}[/]  "
            f"[dim]{geo.get('asn','—')}[/]"
        )
        console.print() 
    # crt.sh — high value subs from cert logs
    crt  = results.get("crtsh",{})
    subs = crt.get("subdomains",[])
    if subs:
        tagged = [(s, *tag_subdomain(s)) for s in subs]
        hv = [(s,t,c,p) for s,t,c,p in tagged if p >= 2]
        console.print(
            f"  [cyan]crt.sh[/]  "
            f"[white]{len(subs)}[/] [dim]in cert logs  ·  "
            f"{len(hv)} high-value[/]"
        )
        
        if hv:
            console.print()
            crt_t = Table(
                show_header=False,
                box=None,
                padding=(0, 2),
                show_edge=False,
            )
            crt_t.add_column("sub",  style="white")
            crt_t.add_column("tag")
            crt_t.add_column("note", style="dim")
            for name, tag, color, _ in hv[:5]:
               crt_t.add_row(
                    name,
                    f"[{color}][{tag}][/{color}]",
                    "cert log — not verified live"
                )
            console.print(crt_t)
        if len(subs) > 5:
            console.print(f"  [dim]  + {len(subs)-5} more in report[/]")
    console.print()

    # Shodan
    shodan = results.get("shodan",{})
    if shodan and not shodan.get("skipped") and not shodan.get("error"):
        vulns   = shodan.get("vulns",[])
        ports_s = shodan.get("ports",[])
        if vulns:
            console.print(
                "  [red]Shodan CVEs[/]  "
                + "  ".join(f"[red]{v}[/]" for v in vulns[:4])
            )
        if ports_s:
            console.print(
                f"  [dim]Shodan ports[/]  "
                f"[white]{' · '.join(str(p) for p in ports_s[:8])}[/]"
            )
        console.print()

# ══════════════════════════════════════════════════════
#  SECTION 3 — ATTACK SURFACE
#  Subdomains, Ports, APIs, Login/Admin, Endpoints,
#  Emails , exposed files 
# ══════════════════════════════════════════════════════
def print_asset_table(title, columns, rows):
    console.print()

    console.print(f"[bold bright_green]{title}[/]")

    table = Table(
        show_header=True,
        header_style="bright_cyan",
        border_style="green",
        expand=True,
        pad_edge=False
    )

    for c in columns:
        table.add_column(c)

    if rows:
        for row in rows:
            table.add_row(*row)
    else:
        table.add_row(
            *(
                ["None detected"]
                + [""] * (len(columns)-1)
            )
        )

    console.print(table)
def print_attack_surface(results):

    section("Attack Surface")
     

    bf        = results.get("subdomain_bruteforce",{})
    live      = bf.get("live",[])
    takeovers = results.get("takeovers",[])
    ports     = results.get("open_ports",[])
    banners   = results.get("banners",[])
    http      = results.get("http_services",[])
    endpoints = results.get("js_endpoints",[])
    emails    = results.get("emails",[])
   
    # ── Live Subdomains ────────────────────────────────
    if live or takeovers:
        rows = []
        for s in live:
          rows.append((
            s.get("subdomain",""),
            str(s.get("status","")),
            tag_subdomain(s.get("subdomain",""))[0]
          ))

        print_asset_table(
           "Subdomains",
           ["Subdomain","Status","Tag"],
        rows
        )
        

        if takeovers:
            for t in takeovers:
                console.print(
                    f"  [red]TAKEOVER[/]  "
                    f"[bold white]{t.get('subdomain','')}[/]  "
                    f"[red]{t.get('service','')}[/]  "
                    f"[dim]unclaimed external service[/]"
                )
            console.print()

        if live:
            tagged = []
            for s in live:
                name = s.get("subdomain","")
                tag, color, pri = tag_subdomain(name)
                tagged.append((s, tag, color, pri))

            critical = [
                (s,t,c,p) for s,t,c,p in tagged
                if p == 3 and s.get("status") != 404
            ]
            medium = [
                (s,t,c,p) for s,t,c,p in tagged
                if p == 2 and s.get("status") != 404
            ]
            standard = [
                (s,t,c,p) for s,t,c,p in tagged
                if p <= 1 or s.get("status") == 404
            ]

            console.print(
                f"  [dim]Total[/]  "
                f"[white]{len(live)}[/]  [dim]·[/]  "
                f"[red]{len(critical)} critical[/]  [dim]·[/]  "
                f"[yellow]{len(medium)} medium[/]  [dim]·[/]  "
                f"[dim]{len(standard)} standard[/]"
            )
            console.print()

            # show ALL critical
            for s, tag, color, _ in critical:
                name   = s.get("subdomain","")
                status = s.get("status","—")
                title  = (s.get("title") or "")[:35]
                st = (
                    f"[bright_green]{status}[/]" if status == 200
                    else f"[yellow]{status}[/]" if str(status).startswith("3")
                    else f"[red]{status}[/]"    if status in [401,403]
                    else f"[dim]{status}[/]"
                )
                console.print(
                    f"  [red]>[/]  [white]{name}[/]  "
                    f"{st}  [{color}][{tag}][/{color}]"
                    + (f"  [dim]{title}[/]" if title else "")
                )

            # show ALL medium — separate loop, NOT nested in critical
            for s, tag, color, _ in medium:
                name   = s.get("subdomain","")
                status = s.get("status","—")
                title  = (s.get("title") or "")[:35]
                st = (
                    f"[bright_green]{status}[/]" if status == 200
                    else f"[yellow]{status}[/]" if str(status).startswith("3")
                    else f"[red]{status}[/]"    if status in [401,403]
                    else f"[dim]{status}[/]"
                )
                console.print(
                    f"  [yellow]·[/]  [white]{name}[/]  "
                    f"{st}  [{color}][{tag}][/{color}]"
                    + (f"  [dim]{title}[/]" if title else "")
                )

            # show standard compact
            if standard:
                console.print()
                console.print(f"  [dim]Standard ({len(standard)}):[/]")
                for s, tag, color, _ in standard:
                    name   = s.get("subdomain","")
                    status = s.get("status","—")
                    if status == 404:
                        console.print(f"  [dim]  · {name}  404  (resolves, no content)[/]")
                    else:
                        console.print(f"  [dim]  · {name}  {status}[/]")

        console.print()

    # ── Open Ports ─────────────────────────────────────
    # ── Open Ports ─────────────────────────────────────
    console.print("[bright_cyan]▶[/] [bold bright_green]Open Ports[/]")
    console.print()
    rows = []

    for p in deduped:
       rows.append((
           f"{p['port']}/tcp",
           port_intel(p["port"])[0],
           port_intel(p["port"])[2]
       ))

       print_asset_table(
          "Open Ports",
          ["Port","Service","Notes"],
          rows
       )

    if not ports:
        console.print("  [dim]  no ports scanned[/]")
        console.print()
    else:
        PORT_INFO = {
            21:    ("FTP",          "high", "anon login / cleartext creds"),
            22:    ("SSH",          "med",  "brute-force / key reuse"),
            23:    ("Telnet",       "crit", "creds in cleartext"),
            25:    ("SMTP",         "med",  "mail relay / enumeration"),
            53:    ("DNS",          "med",  "zone transfer possible"),
            80:    ("HTTP",         "std",  ""),
            443:   ("HTTPS",        "std",  ""),
            445:   ("SMB",          "high", "EternalBlue / file share"),
            3306:  ("MySQL",        "high", "brute-force -> data exfil"),
            3389:  ("RDP",          "crit", "ransomware entry / BlueKeep"),
            5432:  ("PostgreSQL",   "high", "brute-force -> SQL pivot"),
            5900:  ("VNC",          "crit", "often no auth"),
            6379:  ("Redis",        "crit", "no auth -> RCE"),
            8080:  ("HTTP-Alt",     "med",  "dev server / less hardened"),
            8443:  ("HTTPS-Alt",    "med",  "alt HTTPS"),
            8000:  ("HTTP-Dev",     "med",  "dev server"),
            8888:  ("HTTP-Dev",     "crit", "Jupyter — often no auth"),
            9090:  ("Prometheus",   "med",  "metrics leak infra details"),
            9200:  ("Elasticsearch","crit", "no auth -> read/write all"),
            27017: ("MongoDB",      "crit", "no auth -> full DB dump"),
            2375:  ("Docker API",   "crit", "mount host fs -> takeover"),
            6443:  ("K8s API",      "crit", "cluster takeover"),
            3000:  ("Node/Dev",     "med",  "dev server"),
            4848:  ("GlassFish",    "high", "default admin:adminadmin"),
            8161:  ("ActiveMQ",     "high", "default admin:admin"),
            15672: ("RabbitMQ",     "high", "default guest:guest"),
            389:   ("LDAP",         "high", "directory enum / cred attacks"),
            11211: ("Memcached",    "high", "amplification / data exposure"),
        }

        # deduplicate by port number
        seen_ports = set()
        deduped = []
        for p in ports:
            num = p.get("port","")
            if num not in seen_ports:
                seen_ports.add(num)
                deduped.append(p)

        crit_lines = []
        high_lines = []
        med_lines  = []
        std_lines  = []

        for p in deduped:
            num  = p.get("port","")
            host = p.get("host","")
            info = PORT_INFO.get(num)
            svc  = info[0] if info else (p.get("service","") or "unknown")
            risk = info[1] if info else "std"
            opp  = info[2] if info else ""

            entry = (num, host, svc, risk, opp)
            if risk == "crit":
                crit_lines.append(entry)
            elif risk == "high":
                high_lines.append(entry)
            elif risk == "med":
                med_lines.append(entry)
            else:
                std_lines.append(entry)

        if crit_lines:
            for num, host, svc, risk, opp in crit_lines:
                console.print(
                    f"  [red]{num}/tcp[/]  "
                    f"[red]open[/]  "
                    f"[bold white]{svc}[/]  "
                    f"[dim]{host}[/]"
                )
                if opp:
                    console.print(f"  [dim]           -> {opp}[/]")
            console.print()

        if high_lines:
            for num, host, svc, risk, opp in high_lines:
                console.print(
                    f"  [yellow]{num}/tcp[/]  "
                    f"[yellow]open[/]  "
                    f"[white]{svc}[/]  "
                    f"[dim]{host}[/]"
                )
                if opp:
                    console.print(f"  [dim]           -> {opp}[/]")
            console.print()

        if med_lines:
            for num, host, svc, risk, opp in med_lines:
                console.print(
                    f"  [bright_blue]{num}/tcp[/]  "
                    f"[bright_blue]open[/]  "
                    f"[white]{svc}[/]  "
                    f"[dim]{host}[/]"
                )
                if opp:
                    console.print(f"  [dim]           -> {opp}[/]")
            console.print()

        if std_lines:
            std_fmt = [
                f"[dim]{num}/tcp {svc}[/]"
                for num, host, svc, risk, opp in std_lines
            ]
            console.print("  " + "  ·  ".join(std_fmt))
            console.print()
    # ── APIs ──────────────────────────────────────────
    console.print("[bright_cyan]▶[/] [bold bright_green]Api [/]")
    api_endpoints = [
        e for e in endpoints
        if "/api/" in e.lower()
        or e.lower().startswith("/v1")
        or e.lower().startswith("/v2")
        or e.lower().startswith("/v3")
    ]

    if api_endpoints:
        console.print("[bright_cyan]▶[/] [bold bright_green]API Endpoints[/]")
        console.print()
        for e in api_endpoints:
            console.print(f"  [yellow]>[/]  [white]{e}[/]")
        console.print()
       
    # ── Login Pages ────────────────────────────────────
    console.print("[bright_cyan]▶[/] [bold bright_green]Login Pages[/]")
    console.print()
    login_pages = [
        s for s in http
        if s.get("is_login") and not s.get("is_admin")
    ]
    if login_pages:
        for s in login_pages:
            console.print(
                f"  [yellow]>[/]  [white]{s.get('url','')}[/]  "
                f"[dim]{s.get('status','')}[/]"
            )
    else:
        console.print("  [dim]  none detected[/]")
    console.print()
    
    # ── Admin Pages ────────────────────────────────────
    console.print("[bright_cyan]▶[/] [bold bright_green]Admin Pages[/]")
    console.print()
    admin_pages = [s for s in http if s.get("is_admin")]
    if admin_pages:
        for s in admin_pages:
            console.print(
                f"  [red]>[/]  [white]{s.get('url','')}[/]  "
                f"[dim]{s.get('status','')}[/]"
            )
    else:
        console.print("  [dim]  none detected[/]")
    console.print()

    # ── Sensitive Endpoints ────────────────────────────
    def endpoint_label(path):
        p = path.lower()
        if "wp-admin" in p or "wp-login" in p:
            return "WordPress admin path"
        if "xmlrpc" in p:
            return "WordPress XMLRPC"
        if "admin-ajax" in p:
            return "WordPress AJAX"
        if "config" in p:
            return "Config endpoint"
        if "debug" in p or "trace" in p:
            return "Debug endpoint"
        if "backup" in p or ".bak" in p:
            return "Backup file"
        if "internal" in p:
            return "Internal endpoint"
        if "secret" in p or "key" in p:
            return "Secret/key path"
        if "auth" in p or "login" in p or "token" in p:
            return "Auth endpoint"
        if "password" in p or "reset" in p:
            return "Password endpoint"
        return "Sensitive path"
        
    console.print("[bright_cyan]▶[/] [bold bright_green]Sensitive Endpoints[/]")
    console.print()

    sens_eps = [
        e for e in endpoints
        if any(x in e.lower()
               for x in ["admin","config","debug","internal",
                          "secret","backup","root","xmlrpc"])
    ]
    auth_eps = [
        e for e in endpoints
        if any(x in e.lower()
               for x in ["auth","login","token","oauth",
                          "password","reset","register"])
        and e not in sens_eps
    ]

    
    api_eps = [
        e for e in endpoints
        if ("/api/" in e.lower()
            or e.lower().startswith("/v"))
        and e not in sens_eps
        and e not in auth_eps
    ]
    other_eps = [
        e for e in endpoints
        if e not in sens_eps and e not in auth_eps
        and "/api/" not in e.lower()
        and not e.lower().startswith("/v")
    ]

    if sens_eps:
        console.print("  [dim]Sensitive:[/]")
        for e in sens_eps:
            console.print(
                f"  [red]>[/]  [white]{e}[/]  "
                f"[dim]{endpoint_label(e)}[/]"
            )
        console.print()

    if auth_eps:
        console.print("  [dim]Auth-related:[/]")
        for e in auth_eps:
            console.print(
                f"  [yellow]>[/]  [white]{e}[/]  "
                f"[dim]{endpoint_label(e)}[/]"
            )
        console.print()

    if api_eps:
        console.print("  [dim]API paths:[/]")
        for e in api_eps:
            console.print(f"  [dim]·  {e}[/]")
        console.print()

    if other_eps:
        console.print("  [dim]Other endpoints:[/]")
        for e in other_eps:
            console.print(f"  [dim]·  {e}[/]")
        console.print()

    # ── Missing Security Headers (attack surface context) ──
    if http:
        from collections import Counter
        all_missing = []
        for s in http:
            all_missing.extend(s.get("missing_headers",[]))
        # exclude Referrer-Policy — low value
        all_missing = [h for h in all_missing if h != "Referrer-Policy"]

        if all_missing:
            common = Counter(all_missing).most_common(3)
            header_explain = {
                "Strict-Transport-Security":
                    "HSTS missing — browser may downgrade to HTTP",
                "Content-Security-Policy":
                    "CSP missing  — XSS payloads execute unrestricted",
                "X-Frame-Options":
                    "XFO missing  — page embeddable in iframe",
                "X-Content-Type-Options":
                    "XCTO missing — MIME sniffing possible",
            }
            console.print("  [bold bright_green]Missing Security Headers[/]")
            console.print()
            for hdr, count in common:
                explain = header_explain.get(hdr, f"{hdr} missing")
                console.print(
                    f"  [bright_blue]·[/]  [white]{explain}[/]  "
                    f"[dim]({count} service(s))[/]"
                )
            console.print()

    # ── JS Findings ────────────────────────────────────
    console.print("[bright_cyan]▶[/] [bold bright_green]JS findings[/]")
    console.print()
    secrets = results.get("js_secrets",[])
    if secrets:
        real_secrets = [
            s for s in secrets
            if "Internal IP" not in s.get("type","")
            and s.get("type","") not in ["Generic API Key","Generic Secret"]
        ]
        internal_ips = [
            s for s in secrets
            if "Internal IP" in s.get("type","")
        ]
        generic = [
            s for s in secrets
            if s.get("type","") in ["Generic API Key","Generic Secret"]
        ]

        console.print("  [bold bright_green]JS Analysis[/]")
        console.print()
        console.print(
            f"  [dim]  Credentials / Keys[/]  "
            + (f"[red]{len(real_secrets)}[/]"
               if real_secrets else f"[dim]0[/]")
        )
        console.print(
            f"  [dim]  Generic references[/]  "
            + (f"[yellow]{len(generic)}[/]"
               if generic else f"[dim]0[/]")
        )
        console.print(
            f"  [dim]  Internal IPs      [/]  "
            f"[bright_blue]{len(internal_ips)}[/]"
            + ("  [dim](infra references, not secrets)[/]"
               if internal_ips else "")
        )
        console.print()

        secret_use = {
            "AWS":      "aws cli enumeration",
            "GitHub":   "private repo access",
            "Stripe":   "payment data access",
            "Firebase": "database read/write",
            "JWT":      "token forge / alg confusion",
            "Slack":    "message access",
        }

        for s in real_secrets[:5]:
            stype  = s.get("type","")
            val    = s.get("value","")
            masked = val[:6]+"••" if len(val)>6 else val
            file   = s.get("file","")[-35:] if s.get("file") else ""
            use    = next(
                (u for k,u in secret_use.items()
                 if k.lower() in stype.lower()),
                "test against discovered endpoints"
            )
            console.print(
                f"  [red]>[/]  [white]{stype}[/]  "
                f"[red]{masked}[/]  [dim]-> {use}[/]"
            )
            if file:
                console.print(f"  [dim]     {file}[/]")

        if internal_ips:
            console.print()
            for s in internal_ips[:3]:
                console.print(
                    f"  [bright_blue]>[/]  "
                    f"[white]{s.get('value','')[:40]}[/]  "
                    f"[dim]internal network reference[/]"
                )
        console.print()

    # ── Emails ─────────────────────────────────────────
    console.print("[bright_cyan]▶[/] [bold bright_green]Emails found[/]")
    if emails:
        cat       = results.get("email_harvest",{}).get("categorized",{})
        sec_mails = cat.get("security",[])
        console.print(
            f"  [bold bright_green]Emails Found[/]  "
            f"[white]{len(emails)}[/]"
            + (f"  [dim]·  {len(sec_mails)} security contact(s)[/]"
               if sec_mails else "")
        )
        console.print()
        for e in (sec_mails or emails)[:4]:
            console.print(f"  [dim]·  {e}[/]")
        console.print()


# ══════════════════════════════════════════════════════
#  SECTION 4 — TECHNOLOGY FINGERPRINTING
#  Web Server, Framework, CMS, Frontend, CDN
#  Every detection includes Confidence + Evidence
# ══════════════════════════════════════════════════════

def print_tech_fingerprinting(results):

    section("Technology Fingerprinting")

    tech = results.get("tech_stack",[])
    cdn  = results.get("cdn",[])
    waf  = results.get("waf",[])

    if not tech and not cdn and not waf:
        console.print("  [dim]No technology fingerprints detected.[/]")
        console.print()
        return

    categories = {
        "Web Server": ["Nginx","Apache","IIS","Litespeed","Tomcat"],
        "Framework":  ["Laravel","Django","Ruby on Rails","ASP.NET",
                      "Spring Boot","Symfony","Flask","PHP"],
        "Frontend":   ["React","Vue.js","Angular","Next.js",
                      "jQuery","Bootstrap"],
        "CMS":        ["WordPress","Drupal","Joomla","Magento",
                      "Shopify","Wix","Squarespace","WooCommerce"],
    }

    tech_attack = {
        "WordPress":   "xmlrpc.php · plugin CVEs · /wp-admin BF",
        "Drupal":      "Drupalgeddon CVEs · module exploits",
        "Laravel":     ".env exposure · APP_DEBUG=true",
        "Django":      "DEBUG mode · /admin BF",
        "ASP.NET":     "ViewState deser · IIS shortname",
        "Next.js":     "/_next/data/ unauthed · API route auth",
        "React":       "secrets in bundle · JWT in localStorage",
        "Angular":     "env vars in bundle · source maps",
        "PHP":         "LFI / RFI · type juggling",
        "Nginx":       "check: alias misconfiguration, proxy headers",
        "Apache":      "check: directory listing, .htaccess",
        "IIS":         "check: shortname vuln, WebDAV",
        "Spring Boot": "/actuator endpoints — info disclosure",
        "Tomcat":      "manager default creds · PUT method",
    }

    tech_evidence = {
        "Nginx":       ("High",   "Server: nginx in response header"),
        "Apache":      ("High",   "Server: apache in response header"),
        "IIS":         ("High",   "Server: microsoft-iis in header"),
        "Litespeed":   ("High",   "Server: litespeed in header"),
        "Tomcat":      ("High",   "Server: apache-coyote in header"),
        "WordPress":   ("High",   "/wp-content/ path in HTML source"),
        "Drupal":      ("Medium", "x-drupal-cache header or body pattern"),
        "Joomla":      ("High",   "/components/com_ path in HTML"),
        "Magento":     ("High",   "mage/cookies or varien in HTML"),
        "Shopify":     ("High",   "cdn.shopify.com in HTML"),
        "React":       ("Medium", "data-reactroot or __react in DOM"),
        "Next.js":     ("High",   "__NEXT_DATA__ in HTML source"),
        "Angular":     ("High",   "ng-version attribute in HTML"),
        "Vue.js":      ("Medium", "data-v- or __vue__ in DOM"),
        "Django":      ("High",   "csrfmiddlewaretoken in HTML form"),
        "Laravel":     ("High",   "laravel_session cookie present"),
        "ASP.NET":     ("High",   "__VIEWSTATE field in HTML form"),
        "PHP":         ("High",   "X-Powered-By: PHP in header"),
        "Spring Boot": ("High",   "x-application-context header"),
        "Ruby on Rails":("High",  "x-runtime header present"),
        "Cloudflare":  ("High",   "cf-ray header in response"),
        "Fastly":      ("High",   "x-served-by / fastly header"),
        "AWS CloudFront":("High", "x-amz-cf-id header present"),
        "Vercel":      ("High",   "x-vercel-id header present"),
        "Netlify":     ("High",   "x-nf-request-id header present"),
    }

    cdn_tech_names = {
        "Cloudflare","Cloudflare Pages","Fastly","AWS CloudFront",
        "Vercel","Netlify","GitHub Pages","Akamai CDN"
    }

    shown = set()

    # print by category
    for cat, members in categories.items():
        matching = [t for t in tech if t in members]
        for t in matching:
            if t in shown:
                continue
            shown.add(t)
            conf, evidence = tech_evidence.get(t, ("Medium","pattern match"))
            attack  = tech_attack.get(t, "")
            conf_clr = (
                "bright_green" if conf == "High"
                else "yellow"
            )
            console.print(
                f"  [dim]{cat:<12}[/]  "
                f"[white]{t}[/]  "
                f"[{conf_clr}][{conf}][/{conf_clr}]  "
                f"[dim]{evidence}[/]"
            )
            
    # anything not in categories and not CDN
    for t in tech:
        if t not in shown and t not in cdn_tech_names:
            conf, evidence = tech_evidence.get(t, ("Medium","pattern match"))
            conf_clr = "bright_green" if conf == "High" else "yellow"
            console.print(
                f"  [dim]{'Other':<12}[/]  "
                f"[white]{t}[/]  "
                f"[{conf_clr}][{conf}][/{conf_clr}]  "
                f"[dim]{evidence}[/]"
            )

    # CDN/Hosting — shown here under Hosting/CDN category
    if cdn:
        for c in cdn:
            conf, evidence = tech_evidence.get(c, ("High","header detection"))
            console.print(
                f"  [dim]{'CDN / Host':<12}[/]  "
                f"[yellow]{c}[/]  "
                f"[bright_green][{conf}][/bright_green]  "
                f"[dim]{evidence}[/]"
            )

    # WAF under fingerprinting
    if waf:
        for w in waf:
            console.print(
                f"  [dim]{'WAF':<12}[/]  "
                f"[red]{w}[/]  "
                f"[bright_green][High][/bright_green]  "
                f"[dim]WAF-specific response headers / block page[/]"
            )

    console.print()


# ══════════════════════════════════════════════════════
#  SECTION 5 — FINDINGS
#  Full finding list with Severity/Confidence/Impact/Evidence
#  Only verified findings shown
# ══════════════════════════════════════════════════════

def print_findings(results):

    section("Findings")

    hints = results.get("vuln_hints",[])

    if not hints:
        console.print(
            "  [dim]No confirmed findings from automated scan.[/]\n"
            "  [dim]Proceed to manual testing.[/]"
        )
        console.print()
        return

    evidence_map = {
        "HDR-001": "Strict-Transport-Security absent in response headers",
        "HDR-002": "Content-Security-Policy absent in response headers",
        "HDR-003": "X-Frame-Options absent in response headers",
        "HDR-004": "X-Content-Type-Options absent in response headers",
        "DNS-001": "Domain expiry date within 90 days — confirmed via WHOIS",
        "DNS-002": "SPF TXT record absent — confirmed via DNS TXT query",
        "DNS-003": "_dmarc TXT record absent — confirmed via DNS query",
        "JS-001":  "AWS key regex (AKIA[0-9A-Z]{16}) matched in JS file",
        "JS-002":  "Secret/token pattern matched in client-side JavaScript",
        "PORT-001":"TCP connect to port 2375 succeeded",
        "PORT-002":"TCP connect to port 6379 succeeded",
        "PORT-003":"TCP connect to port 27017 succeeded",
        "PORT-004":"TCP connect to port 9200 succeeded",
        "PORT-005":"TCP connect to port 6443 succeeded",
        "PORT-006":"TCP connect to port 23 succeeded",
        "PORT-007":"TCP connect to port 3389 succeeded",
        "ADM-001": "Admin URL path or page title matched admin keyword",
        "SUB-001": "CNAME target returned service-specific unclaimed response",
        "CVE-001": "CVE identifiers returned by Shodan for target IP",
        "TECH-001":"WordPress content path pattern found in HTML",
        "TECH-002":"ASP.NET __VIEWSTATE field found in HTML form",
    }

    impact_map = {
        "HDR-001": "SSL stripping possible on same network segment",
        "HDR-002": "XSS payloads execute without browser-level restriction",
        "HDR-003": "Page embeddable in attacker-controlled iframe",
        "HDR-004": "MIME-type confusion — browser may execute non-script as script",
        "DNS-001": "Domain claimable by attacker if registration lapses",
        "DNS-002": "Attacker can send email appearing to be from this domain",
        "DNS-003": "Spoofed email passes inbox delivery — no policy enforcement",
        "JS-001":  "Direct AWS API access without any vulnerability to exploit",
        "JS-002":  "Potential authenticated API access via leaked credential",
        "PORT-001":"Container escape to host filesystem — full server takeover",
        "PORT-002":"Read/write all cached data — RCE via SLAVEOF command",
        "PORT-003":"Full database read/write/delete without credentials",
        "PORT-004":"Full Elasticsearch index access — data exfiltration",
        "PORT-005":"Kubernetes cluster control if anonymous access enabled",
        "PORT-006":"All traffic including credentials transmitted in cleartext",
        "PORT-007":"Known exploit surface — BlueKeep and brute-force attacks",
        "ADM-001": "Credential attacks directly on admin interface",
        "SUB-001": "Attacker claims subdomain — phishing under target domain",
        "CVE-001": "Known public exploits may apply to running software version",
        "TECH-001":"WordPress-specific attacks: plugin CVEs, xmlrpc, /wp-admin",
        "TECH-002":"ViewState deserialization RCE if MAC validation disabled",
    }

    confidence_map = {
        "HDR-001":"High","HDR-002":"High","HDR-003":"High","HDR-004":"High",
        "DNS-001":"High","DNS-002":"High","DNS-003":"High",
        "JS-001": "High","JS-002":"Medium",
        "PORT-001":"High","PORT-002":"High","PORT-003":"High",
        "PORT-004":"High","PORT-005":"Medium","PORT-006":"High","PORT-007":"High",
        "ADM-001":"Medium","SUB-001":"Medium",
        "CVE-001":"Medium","TECH-001":"High","TECH-002":"High",
    }

    ordered = sorted(
        [h for h in hints if h.get("severity") != "Info"],
        key=lambda h: {
            "Critical":0,"High":1,"Medium":2,"Low":3
        }.get(h.get("severity","Low"),4)
    )

    if not ordered:
        console.print(
            "  [dim]No confirmed findings from automated scan.[/]\n"
            "  [dim]Proceed to manual testing.[/]"
        )
        console.print()
        return

    for h in ordered:
        sev_s = h.get("severity","Info")
        hid   = h.get("id","")
        conf  = confidence_map.get(hid,"Medium")

        sev_clr  = {
            "Critical":"red","High":"yellow",
            "Medium":"bright_blue","Low":"dim"
        }.get(sev_s,"dim")
        conf_clr = {
            "High":"bright_green","Medium":"yellow","Low":"dim"
        }.get(conf,"dim")

        console.print(
            f"  [{sev_clr}][{sev_s}][/{sev_clr}]  "
            f"[dim]Confidence:[/] [{conf_clr}]{conf}[/{conf_clr}]  "
            f"[white]{h.get('title','')}[/]"
        )
        console.print(
            f"  [dim]           Impact:   "
            f"{impact_map.get(hid,'manual verification required')}[/]"
        )
        console.print(
            f"  [dim]           Evidence: "
            f"{evidence_map.get(hid,'automated detection')}[/]"
        )
        console.print()

    

# ══════════════════════════════════════════════════════
#  SECTION 6 — RECOMMENDED NEXT TESTS
#  Concrete, specific, based on actual findings
# ══════════════════════════════════════════════════════

def print_next_tests(results, config):

    section("Recommended Next Tests")

    hints     = results.get("vuln_hints",[])
    tech      = results.get("tech_stack",[])
    endpoints = results.get("js_endpoints",[])
    emails    = results.get("emails",[])
    cdn       = results.get("cdn",[])
    waf       = results.get("waf",[])
    secrets   = results.get("js_secrets",[])
    takeovers = results.get("takeovers",[])
    ports     = results.get("open_ports",[])
    http      = results.get("http_services",[])
    bf        = results.get("subdomain_bruteforce",{})
    live_subs = bf.get("live",[])

    real_secrets = [
        s for s in secrets
        if "Internal IP" not in s.get("type","")
        and s.get("type","") not in ["Generic API Key","Generic Secret"]
    ]
    sens_ports = [
        p for p in ports
        if p.get("port") in {2375,6379,27017,9200,6443,2379,23,3389}
    ]
    admin_svcs   = [s for s in http if s.get("is_admin")]
    login_svcs   = [s for s in http if s.get("is_login")]
    has_no_dmarc = any("DMARC" in h.get("title","") for h in hints)

    # interesting subs = non-standard, non-404
    interesting_subs = [
        s for s in live_subs
        if tag_subdomain(s.get("subdomain",""))[2] >= 2
        and s.get("status") != 404
    ]

    steps = []

    # priority 1 — immediate
    if takeovers:
        steps.append((
            "red", "Subdomain Takeover",
            f"Register `{takeovers[0].get('service','')}` resource — "
            f"verify you can claim `{takeovers[0].get('subdomain','')}`"
        ))

    if real_secrets:
        s = real_secrets[0]
        steps.append((
            "red", "Credential Validation",
            f"Test {s.get('type','')} against its service — "
            f"confirm validity before reporting"
        ))

    if sens_ports:
        p   = sens_ports[0]
        lbl, _, opp = port_intel(p.get("port",""))
        steps.append((
            "red", "Unauthenticated Service",
            f"Connect to {p.get('host','')}:{p.get('port','')} ({lbl}) — "
            f"{opp}"
        ))

    # priority 2 — auth
    if admin_svcs:
        steps.append((
            "yellow", "Admin Panel Testing",
            f"Test {admin_svcs[0].get('url','')} — "
            f"default credentials, credential stuffing"
        ))

    if login_svcs:
        steps.append((
            "yellow", "Authentication Testing",
            f"Test {len(login_svcs)} login page(s) — "
            f"brute-force protection, account lockout, password policy"
        ))

    # priority 3 — api
    if endpoints:
        steps.append((
            "yellow", "API Authorization",
            f"Test {len(endpoints)} discovered endpoint(s) — "
            f"IDOR, missing auth, rate limiting, method override"
        ))

    # priority 4 — cdn
    if cdn:
        steps.append((
            "yellow", "Origin IP Discovery",
            f"CDN detected ({', '.join(cdn)}) — "
            f"check: crt.sh history, SPF includes, "
            f"old DNS records, email headers"
        ))
    has_expiry = any(
        "expires" in h.get("title","").lower()
        for h in hints
    )
    if has_expiry:
        steps.append((
             "bright_blue", "Domain Renewal Check",
             "Domain expires soon — confirm renewal is scheduled, "
             "verify registrar lock is enabled"
        ))    
        

    # priority 5 — subdomains
    if interesting_subs:
        steps.append((
            "bright_blue", "Subdomain Access Control",
            f"Test {len(interesting_subs)} interesting subdomain(s) — "
            f"each may have different auth controls than main domain"
        ))
    elif len(live_subs) > 3:
        steps.append((
            "dim", "Subdomain Review",
            f"Review {len(live_subs)} live subdomains — "
            f"check for auth differences"
        ))

    # priority 6 — email spoofing
    if has_no_dmarc and emails:
        steps.append((
            "bright_blue", "Email Spoofing",
            f"No DMARC — test with swaks: "
            f"swaks --to target --from spoof@{config['target']}"
        ))
    # In print_next_tests():
    if "Nginx" in tech and (
        endpoints or admin_svcs or len(live_subs) > 3
    ):
        steps.append((
            "dim", "Nginx Configuration Review",
            "Check alias path traversal: "
            "test /static../etc/passwd — "
            "verify proxy_pass header handling"
        ))
    # priority 7 — CMS
    if "WordPress" in tech:
        steps.append((
            "bright_blue", "WordPress Testing",
            "wpscan --url target --enumerate p,u — "
            "check plugins, users, xmlrpc"
        ))

    if "Drupal" in tech:
        steps.append((
            "bright_blue", "Drupal Testing",
            "Check Drupalgeddon2 (CVE-2018-7600) — "
            "verify patched version"
        ))
    # always ensure minimum 2 useful tests
    if len(steps) < 2:
        steps.append((
            "dim", "Manual Application Review",
            "Browse application — map auth flows, "
            "identify user roles, test session management"
        ))

    if len(steps) < 3:
        steps.append((
            "dim", "Information Disclosure",
            "Check /.well-known/security.txt, "
            "robots.txt, sitemap.xml, error pages"
        ))

    # full default only if literally nothing found
    if not steps:
        steps = [
            ("dim", "Manual Browse",
             "Map application flows — auth, state changes, user roles"),
            ("dim", "Business Logic",
             "Test: price manipulation, workflow bypass, "
             "privilege escalation"),
            ("dim", "Information Disclosure",
             "Check robots.txt, sitemap.xml, "
             "/.well-known/security.txt, error pages"),
        ]

    for i, (color, label, detail) in enumerate(steps[:8], 1):
        console.print(
            f"  [{color}]{i}.[/{color}]  "
            f"[white]{label}[/]"
        )
        console.print(
            f"  [dim]     {detail}[/]"
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

    raw_srv = validation.get("server","?")
    cdn_vals = {
        "cloudflare","fastly","cloudfront",
        "vercel","netlify","akamai","github.com"
    }
    srv_display = (
        "CDN (real server hidden)"
        if any(c in raw_srv.lower() for c in cdn_vals)
        else raw_srv
    )
    console.print(
        Panel.fit(
           f"[bold white]Target[/]   : {config['target']}\n"
           f"[bold white]IP[/]       : {validation.get('ip','?')}\n"
           f"[bold white]HTTPS[/]    : "
           f"{'[bright_green]Yes[/]' if validation.get('https') else '[red]No[/]'}\n"
           f"[bold white]Server[/]   : {srv_display}",
           border_style="green",
           padding=(0,2),
           title="[bold green]Recon[/]"
        )
    )

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
    console.print(
        f"[bold bright_green]Recon Completed[/]  "
        f"[dim]in[/] "
        f"[white]{round(elapsed,1)}s[/]"
    )

    console.rule(style="green")

    # ── save report silently ───────────────────────────
    report_path = None
    try:
        report_paths = generate_report(results, config)
        if report_paths:
            # just store path for footer line
            report_path = list(report_paths.values())[0]
    except Exception:
        pass

    if not config["quiet"]:
        print_executive_summary(results, config, elapsed)
        print_target_info(results, config)
        print_attack_surface(results)
        print_tech_fingerprinting(results)
        print_findings(results)
        print_next_tests(results, config)

    # single footer line
    console.print("[green]" + "="*90 + "[/]")
    console.print(
        f"[bold bright_green]Scan Finished[/]  "
        f"[white]{config['target']}[/]"
    )

    if report_path:
        console.print(
            f"[dim]Report:[/] [white]{report_path}[/]"
        )

    console.print("[green]" + "="*90 + "[/]")
    console.print()

if __name__ == "__main__":
    main()
