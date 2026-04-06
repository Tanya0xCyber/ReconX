#!/usr/bin/env python3
"""
reconx.py — main entry point for the ReconX tool
"""

import argparse
import sys
import os
import json
import time
import threading
from datetime import datetime
from pathlib import Path

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich.layout import Layout
    from rich.text import Text
    from rich import print as rprint
    from rich.rule import Rule
    from rich.columns import Columns
    from rich.padding import Padding
except ImportError:
    print("[!] Run: pip install rich")
    sys.exit(1)

from modules.validator    import validate_target
from modules.passive      import run_passive_recon
from modules.active       import run_active_recon
from modules.services     import run_service_discovery
from modules.analysis     import run_analysis
from modules.reporter     import generate_report

console = Console()


# ══════════════════════════════════════════════════════
#  BANNER
# ══════════════════════════════════════════════════════

def print_banner():
    os.system("cls" if os.name == "nt" else "clear")

    art = """
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝"""

    console.print(art, style="bold red")
    console.print(
        "  ╔─────────────────────────────────────────────────────╗",
        style="dim red"
    )
    console.print(
        "  │  [bold white]recon pipeline[/] · [bold white]bug bounty[/] · [bold white]pentest[/]"
        "                    │",
        style="dim red"
    )
    console.print(
        "  │  [bold cyan]YOUR_NAME[/]"
        "                               [dim]v1.0 · 2026[/]  │",
        style="dim red"
    )
    console.print(
        "  ╚─────────────────────────────────────────────────────╝",
        style="dim red"
    )
    console.print()


# ══════════════════════════════════════════════════════
#  ARGUMENT PARSER
# ══════════════════════════════════════════════════════

def build_arg_parser():
    parser = argparse.ArgumentParser(
        prog="reconx",
        description="ReconX — Automated Recon Pipeline",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 reconx.py -t example.com\n"
            "  python3 reconx.py -t example.com --only passive\n"
            "  python3 reconx.py -t example.com --output all --threads 30\n"
        )
    )

    parser.add_argument("-t", "--target",   required=True,  metavar="TARGET",
                        help="Target domain or IP")
    parser.add_argument("--threads",        type=int, default=20,
                        help="Thread count (default: 20)")
    parser.add_argument("--timeout",        type=int, default=5,
                        help="Request timeout in seconds (default: 5)")
    parser.add_argument("--rate-limit",     type=float, default=0.05,
                        dest="rate_limit",
                        help="Delay between requests (default: 0.05)")
    parser.add_argument("--only",           metavar="STAGE",
                        help="Run one stage: passive / active / services / analysis")
    parser.add_argument("--skip",           metavar="STAGE",
                        help="Skip a stage")
    parser.add_argument("--no-ports",       action="store_true", dest="no_ports",
                        help="Skip port scanning")
    parser.add_argument("--no-active",      action="store_true", dest="no_active",
                        help="Skip active recon")
    parser.add_argument("--shodan",         metavar="KEY",
                        help="Shodan API key")
    parser.add_argument("--wordlist",       metavar="FILE",
                        default="wordlists/subdomains.txt",
                        help="Subdomain wordlist path")
    parser.add_argument("--output",         choices=["html","json","md","all"],
                        default="html", metavar="FORMAT",
                        help="Report format: html / json / md / all")
    parser.add_argument("--output-dir",     metavar="DIR", default="reports",
                        dest="output_dir",
                        help="Report save directory (default: ./reports)")
    parser.add_argument("-v", "--verbose",  action="store_true")
    parser.add_argument("-q", "--quiet",    action="store_true")
    parser.add_argument("--version",        action="version", version="ReconX v1.0")

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
#  STAGE RUNNER — with live spinner
# ══════════════════════════════════════════════════════

def run_stage(name, func, args, config, results):
    """runs one pipeline stage with a live spinner"""

    stage_key = name.lower().replace(" ", "")

    # check if skipped
    for skip in config["skip_stages"]:
        if skip in stage_key:
            console.print(f"  [dim]⊘  {name} skipped[/]")
            return False

    stage_start = time.time()

    # live spinner while stage runs
    with Progress(
        SpinnerColumn(spinner_name="dots", style="bold cyan"),
        TextColumn(f"  [bold cyan]{name}[/] [dim]running...[/]"),
        TimeElapsedColumn(),
        console=console,
        transient=True,   # disappears after done — clean output
    ) as progress:
        task = progress.add_task("", total=None)

        try:
            stage_results = func(*args, config)
            results.update(stage_results)

        except KeyboardInterrupt:
            console.print(f"\n  [yellow]⚠  {name} interrupted[/]")
            raise

        except Exception as e:
            elapsed = round(time.time() - stage_start, 2)
            console.print(
                f"  [bold red]✗[/]  [red]{name}[/] "
                f"[dim]failed in {elapsed}s[/] — [red]{e}[/]"
            )
            if config["verbose"]:
                import traceback
                traceback.print_exc()
            results[f"{name}_error"] = str(e)
            return False

    elapsed = round(time.time() - stage_start, 2)
    console.print(
        f"  [bold green]✓[/]  [bold white]{name}[/] "
        f"[dim]done in[/] [bold cyan]{elapsed}s[/]"
    )
    return True


# ══════════════════════════════════════════════════════
#  TARGET INFO BOX — shown before scan starts
# ══════════════════════════════════════════════════════

def print_target_info(config, validation):
    """prints a clean info box about the target"""

    console.print()
    console.rule("[bold cyan]Target Info[/]", style="cyan")
    console.print()

    # build info grid
    info = [
        ("Target",    config["target"]),
        ("IP",        validation.get("ip", "—")),
        ("Type",      validation.get("target_type", "—")),
        ("Server",    validation.get("server", "—")),
        ("Status",    str(validation.get("status_code", "—"))),
        ("HTTPS",     "Yes" if validation.get("https") else "No"),
        ("Threads",   str(config["threads"])),
        ("Output",    config["output_fmt"].upper()),
    ]

    # two columns layout
    left  = info[:4]
    right = info[4:]

    left_text  = "\n".join(
        f"  [dim]{k:<10}[/] [bold white]{v}[/]" for k, v in left
    )
    right_text = "\n".join(
        f"  [dim]{k:<10}[/] [bold white]{v}[/]" for k, v in right
    )

    console.print(Columns([left_text, right_text], equal=True))
    console.print()


# ══════════════════════════════════════════════════════
#  LIVE FINDING TICKER — shows findings as they come in
# ══════════════════════════════════════════════════════

def print_quick_finds(results):
    """
    prints a quick ticker of interesting things found
    called after each stage so user sees progress
    """

    finds = []

    subs = results.get("subdomains", [])
    if subs:
        finds.append(f"[green]{len(subs)}[/] subdomains")

    secrets = results.get("js_secrets", [])
    if secrets:
        finds.append(f"[red]{len(secrets)}[/] JS secrets")

    ports = results.get("open_ports", [])
    if ports:
        finds.append(f"[yellow]{len(ports)}[/] open ports")

    takeovers = results.get("takeovers", [])
    if takeovers:
        finds.append(f"[bold red]{len(takeovers)} TAKEOVER(S)[/]")

    emails = results.get("emails", [])
    if emails:
        finds.append(f"[cyan]{len(emails)}[/] emails")

    if finds:
        console.print(
            f"  [dim]↳ found so far:[/] " + " · ".join(finds)
        )


# ══════════════════════════════════════════════════════
#  FINAL SUMMARY TABLE
# ══════════════════════════════════════════════════════

def print_summary(results, config, elapsed_total):

    console.print()
    console.rule("[bold cyan]Scan Complete[/]", style="cyan")
    console.print()

    hints  = results.get("vuln_hints", [])
    chains = results.get("chains", [])

    def count(key):
        val = results.get(key, [])
        return str(len(val)) if isinstance(val, (list, dict, set)) else "0"

    def strval(key, fallback="none"):
        val = results.get(key, fallback)
        if isinstance(val, list):
            return ", ".join(str(x) for x in val[:3]) or fallback
        return str(val) if val else fallback

    def sev_count(severity):
        return str(sum(1 for h in hints if h.get("severity") == severity))

    # ── findings table ─────────────────────────────────
    table = Table(
        show_header=True,
        header_style="bold cyan",
        border_style="dim",
        expand=False,
        show_lines=False,
        padding=(0, 1),
    )
    table.add_column("Category",  style="dim white", width=20)
    table.add_column("Found",     justify="right",   width=8)
    table.add_column("Notes",     style="dim",       width=32)

    table.add_row("Subdomains",    count("subdomains"),    "passive + brute-force")
    table.add_row("Open ports",    count("open_ports"),    "TCP targeted scan")
    table.add_row("HTTP services", count("http_services"), "live web servers")
    table.add_row("JS secrets",    count("js_secrets"),    "tokens · keys · URIs")
    table.add_row("JS endpoints",  count("js_endpoints"),  "API paths from JS")
    table.add_row("Emails",        count("emails"),        "harvested from pages")
    table.add_row("Takeovers",     count("takeovers"),     "subdomain takeover")
    table.add_row("Attack chains", str(len(chains)),       "combined findings")

    # ── severity table ─────────────────────────────────
    sev_table = Table(
        show_header=True,
        header_style="bold cyan",
        border_style="dim",
        expand=False,
        show_lines=False,
        padding=(0, 1),
    )
    sev_table.add_column("Severity",  width=12)
    sev_table.add_column("Count",     justify="right", width=8)

    sev_table.add_row(
        "[bold red]Critical[/]",  sev_count("Critical"))
    sev_table.add_row(
        "[bold yellow]High[/]",   sev_count("High"))
    sev_table.add_row(
        "[bold blue]Medium[/]",   sev_count("Medium"))
    sev_table.add_row(
        "[dim]Low / Info[/]",
        str(
            sum(1 for h in hints if h.get("severity") in ["Low","Info"])
        )
    )
    sev_table.add_row(
        "[bold white]Total[/]",   str(len(hints)))

    # print both tables side by side
    console.print(Columns([table, sev_table], equal=False, expand=False))

    # ── meta info ──────────────────────────────────────
    console.print()
    console.print(
        f"  [dim]Target[/]    [bold cyan]{config['target']}[/]  "
        f"[dim]WAF[/] [bold white]{strval('waf')}[/]  "
        f"[dim]Tech[/] [bold white]{strval('tech_stack')}[/]"
    )
    console.print(
        f"  [dim]Scan time[/] [bold cyan]{round(elapsed_total, 2)}s[/]  "
        f"[dim]Started[/] [bold white]{config['scan_start'][:19].replace('T',' ')}[/]"
    )
    console.print()

    # ── show critical findings inline ──────────────────
    crits = [h for h in hints if h.get("severity") == "Critical"]
    if crits:
        console.print("  [bold red]Critical findings:[/]")
        for c in crits[:5]:   # show max 5
            console.print(f"  [red]  ✗[/] {c['title']}")
        console.print()

    # ── show takeovers inline ──────────────────────────
    takeovers = results.get("takeovers", [])
    if takeovers:
        console.print("  [bold red]Subdomain takeovers:[/]")
        for t in takeovers:
            console.print(
                f"  [red]  ⚑[/] [bold]{t.get('subdomain','')}[/] "
                f"[dim]→[/] {t.get('service','')}"
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

    # make output dir
    Path(config["output_dir"]).mkdir(parents=True, exist_ok=True)

    results = {
        "target":     config["target"],
        "scan_start": config["scan_start"],
    }

    total_start = time.time()

    # ── validation ─────────────────────────────────────
    console.print()
    console.rule("[bold cyan]Validation[/]", style="cyan")
    console.print()

    with Progress(
        SpinnerColumn(spinner_name="dots", style="cyan"),
        TextColumn("  [cyan]Validating target...[/]"),
        transient=True,
        console=console,
    ) as p:
        p.add_task("", total=None)
        validation = validate_target(config["target"], config)

    if not validation.get("is_valid"):
        console.print(
            f"  [bold red]✗[/]  Invalid target: "
            f"[red]{validation.get('error', 'unknown error')}[/]"
        )
        sys.exit(1)

    results.update(validation)

    console.print(
        f"  [bold green]✓[/]  [bold white]{config['target']}[/] "
        f"[dim]→[/] [cyan]{validation.get('ip','?')}[/]  "
        f"[dim]status[/] [bold white]{validation.get('status_code','?')}[/]  "
        f"[dim]server[/] [bold white]{validation.get('server','?')}[/]"
    )

    print_target_info(config, validation)

    try:
        # ── stage 1: passive ───────────────────────────
        console.rule("[bold cyan]Passive Recon[/]", style="cyan")
        console.print()
        run_stage(
            "Passive Recon",
            run_passive_recon,
            (config["target"],),
            config, results
        )
        print_quick_finds(results)
        console.print()

        # ── stage 2: active ────────────────────────────
        console.rule("[bold cyan]Active Recon[/]", style="cyan")
        console.print()
        run_stage(
            "Active Recon",
            run_active_recon,
            (config["target"], config["wordlist"]),
            config, results
        )
        print_quick_finds(results)
        console.print()

        # ── stage 3: services ──────────────────────────
        console.rule("[bold cyan]Service Discovery[/]", style="cyan")
        console.print()
        targets_to_scan = (
            results.get("subdomains", [])[:5] + [config["target"]]
        )
        run_stage(
            "Service Discovery",
            run_service_discovery,
            (targets_to_scan,),
            config, results
        )
        print_quick_finds(results)
        console.print()

        # ── stage 4: analysis ──────────────────────────
        console.rule("[bold cyan]Analysis Engine[/]", style="cyan")
        console.print()
        run_stage(
            "Analysis Engine",
            run_analysis,
            (results,),
            config, results
        )
        print_quick_finds(results)
        console.print()

    except KeyboardInterrupt:
        console.print(
            "\n  [yellow]⚠  Scan interrupted — generating partial report...[/]"
        )

    # ── reporting ──────────────────────────────────────
    console.rule("[bold cyan]Reporting[/]", style="cyan")
    console.print()

    try:
        report_paths = generate_report(results, config)
        for fmt, path in report_paths.items():
            console.print(
                f"  [bold green]✓[/]  [dim]{fmt.upper()}[/] "
                f"[bold white]{path}[/]"
            )
    except Exception as e:
        console.print(f"  [bold red]✗[/]  Report failed: [red]{e}[/]")

    # ── summary ────────────────────────────────────────
    print_summary(results, config, time.time() - total_start)

    console.print(
        "  [dim]ReconX done — open your HTML report in a browser[/]\n"
    )


if __name__ == "__main__":
    main()
