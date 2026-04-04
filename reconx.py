#!/usr/bin/env python3
"""
reconx.py — main entry point for the ReconX tool
run it like: python reconx.py -t example.com
"""

# ─── standard library imports ───────────────────────────────────────────────
import argparse          # handles command-line flags like -t, --threads, etc.
import sys               # lets us exit the program cleanly
import os                # file/folder operations
import json              # saving results as JSON
import time              # timing how long the scan takes
import threading         # run multiple tasks at the same time
from datetime import datetime   # timestamp for reports
from pathlib import Path        # cleaner file path handling

# ─── third-party imports (pip install these) ────────────────────────────────
try:
    from rich.console import Console        # pretty terminal output with colors
    from rich.panel import Panel            # bordered boxes in terminal
    from rich.table import Table            # neat tables in terminal
    from rich.progress import Progress, SpinnerColumn, TextColumn  # loading spinners
    from rich import print as rprint        # colored print()
    from rich.rule import Rule              # horizontal divider line
except ImportError:
    print("[!] Missing 'rich' library. Run: pip install rich")
    sys.exit(1)

# ─── our own modules (we'll build these next) ────────────────────────────────
# each of these is a file inside the modules/ folder
from modules.validator    import validate_target      # stage: validation
from modules.passive      import run_passive_recon    # stage: passive recon
from modules.active       import run_active_recon     # stage: active recon
from modules.services     import run_service_discovery  # stage: service discovery
from modules.analysis     import run_analysis         # stage: analysis engine
from modules.reporter     import generate_report      # stage: reporting

# ─── create a global console object (used everywhere for printing) ───────────
console = Console()


# ════════════════════════════════════════════════════════════════════════════
#  BANNER  — the cool ASCII art that shows when the tool starts
# ════════════════════════════════════════════════════════════════════════════

def print_banner():
    os.system("cls" if os.name == "nt" else "clear")
    console.print(f"""
  [bold red]██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗[/]
  [bold red]██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝[/]
  [bold red]██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝ [/]
  [bold red]██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗ [/]
  [bold red]██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗[/]
  [bold red]╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝[/]
""")
    console.print(
        Panel.fit(
            "[bold white]ReconX v1.0[/] [dim]—[/] [cyan]Automated Recon & Enumeration Pipeline[/]\n"
            "[dim]Passive → Active → Services → Analysis → Report[/]\n"
            "[bold red]⚠  For authorized security testing only[/]",
            border_style="red",
            padding=(0, 2),
        )
    )
    console.print()


# ════════════════════════════════════════════════════════════════════════════
#  ARGUMENT PARSER  — defines all the flags the user can pass in
# ════════════════════════════════════════════════════════════════════════════

def build_arg_parser():
    """
    Sets up all the command-line arguments.
    Example usage:
        python reconx.py -t example.com
        python reconx.py -t 192.168.1.1 --threads 20 --only passive
        python reconx.py -t example.com --output json --no-ports
    """

    parser = argparse.ArgumentParser(
        prog="reconx",
        description="ReconX — Automated Recon & Enumeration Tool",
        formatter_class=argparse.RawTextHelpFormatter,   # preserves newlines in help text
        epilog=(
            "Examples:\n"
            "  python reconx.py -t example.com\n"
            "  python reconx.py -t example.com --threads 30 --output html\n"
            "  python reconx.py -t example.com --only passive,active\n"
            "  python reconx.py -t example.com --no-ports --no-active\n"
        )
    )

    # ── required argument ──────────────────────────────────────────────────
    parser.add_argument(
        "-t", "--target",
        required=True,
        metavar="TARGET",
        help="Target domain or IP address (e.g. example.com or 192.168.1.1)"
    )

    # ── optional: performance ──────────────────────────────────────────────
    parser.add_argument(
        "--threads",
        type=int,
        default=10,
        metavar="N",
        help="Number of threads for brute-force tasks (default: 10)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=5,
        metavar="SEC",
        help="Timeout in seconds for each network request (default: 5)"
    )
    parser.add_argument(
        "--rate-limit",
        type=float,
        default=0.1,
        metavar="SEC",
        dest="rate_limit",
        help="Delay between requests to avoid getting blocked (default: 0.1s)"
    )

    # ── optional: what stages to run ──────────────────────────────────────
    parser.add_argument(
        "--only",
        metavar="STAGES",
        help=(
            "Run only specific stages (comma-separated):\n"
            "  passive, active, services, analysis\n"
            "  Example: --only passive,active"
        )
    )
    parser.add_argument(
        "--skip",
        metavar="STAGES",
        help="Skip specific stages (comma-separated, same names as --only)"
    )

    # ── optional: toggle specific features on/off ─────────────────────────
    parser.add_argument(
        "--no-ports",
        action="store_true",   # if flag is present, value is True
        dest="no_ports",
        help="Skip port scanning (faster run)"
    )
    parser.add_argument(
        "--no-active",
        action="store_true",
        dest="no_active",
        help="Skip active recon (subdomain brute-force, JS crawl)"
    )
    parser.add_argument(
        "--shodan",
        metavar="API_KEY",
        help="Shodan API key for passive recon (optional)"
    )

    # ── optional: wordlist for subdomain brute-force ───────────────────────
    parser.add_argument(
        "--wordlist",
        metavar="FILE",
        default="wordlists/subdomains.txt",
        help="Path to subdomain wordlist (default: wordlists/subdomains.txt)"
    )

    # ── optional: output format ───────────────────────────────────────────
    parser.add_argument(
        "--output",
        choices=["html", "json", "md", "all"],  # only these values allowed
        default="html",
        metavar="FORMAT",
        help="Report format: html, json, md, all (default: html)"
    )
    parser.add_argument(
        "--output-dir",
        metavar="DIR",
        default="reports",
        dest="output_dir",
        help="Directory to save reports (default: ./reports/)"
    )

    # ── optional: verbosity ───────────────────────────────────────────────
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed output as the scan runs"
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Only show final summary (suppress stage output)"
    )
    parser.add_argument(
        "--version",
        action="version",
        version="ReconX v1.0.0"
    )

    return parser


# ════════════════════════════════════════════════════════════════════════════
#  CONFIG BUILDER  — turns parsed args into a clean config dict
# ════════════════════════════════════════════════════════════════════════════

def build_config(args):
    """
    Takes the raw argparse result and returns a clean dictionary.
    This dict gets passed into every module so they all share the same settings.
    
    Think of it like a 'settings object' that travels through the whole scan.
    """

    # figure out which stages to skip
    # if user said --only passive,active → skip everything else
    all_stages = {"passive", "active", "services", "analysis"}

    if args.only:
        # --only means: run JUST these stages
        run_stages = set(args.only.lower().split(","))
        skip_stages = all_stages - run_stages
    elif args.skip:
        # --skip means: run everything EXCEPT these
        skip_stages = set(args.skip.lower().split(","))
    else:
        skip_stages = set()

    # also add stages disabled by specific flags
    if args.no_active:
        skip_stages.add("active")
    if args.no_ports:
        skip_stages.add("services")  # port scanning is in services stage

    config = {
        "target":      args.target.strip().lower(),   # normalize the target
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
        "scan_start":  datetime.now().isoformat(),   # timestamp for report
    }

    return config


# ════════════════════════════════════════════════════════════════════════════
#  STAGE RUNNER  — runs each pipeline stage in order
# ════════════════════════════════════════════════════════════════════════════

def run_stage(name, func, args, config, results):
    """
    Generic wrapper for running a single pipeline stage.
    
    - name:    display name like "Passive Recon"
    - func:    the function to call (imported from modules/)
    - args:    the stage-specific arguments to pass in
    - config:  shared config dict
    - results: shared results dict (we add our findings to this)
    
    Returns True if stage ran OK, False if it was skipped or errored.
    """

    stage_key = name.lower().replace(" ", "")

    for skip in config["skip_stages"]:
        if skip in stage_key:
            console.print(f"  [dim]⊘  Skipping {name}[/]")
            return False

    if not config["quiet"]:
        console.print()
        console.rule(f"[bold cyan]{name}[/]", style="cyan")

    stage_start = time.time()

    try:
        with Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[cyan]{task.description}"),
            transient=True,   # disappears after done
            console=console,
        ) as progress:
            task = progress.add_task(f"  Running {name}...", total=None)
            stage_results = func(*args, config)
            progress.update(task, completed=True)

        results.update(stage_results)
        elapsed = round(time.time() - stage_start, 2)

        if not config["quiet"]:
            console.print(
                f"  [bold green]✓[/]  {name} done in "
                f"[bold cyan]{elapsed}s[/]"
            )
        return True

    except KeyboardInterrupt:
        console.print(f"\n  [yellow]⚠  {name} interrupted[/]")
        raise

    except Exception as e:
        console.print(f"  [bold red]✗[/]  {name} failed: [red]{e}[/]")
        if config["verbose"]:
            import traceback
            traceback.print_exc()
        results[f"{name}_error"] = str(e)
        return False

# ════════════════════════════════════════════════════════════════════════════
#  RESULTS SUMMARY  — prints a quick summary table in the terminal
# ════════════════════════════════════════════════════════════════════════════

def print_summary(results, config, elapsed_total):
    console.print()
    console.rule("[bold cyan]Scan Summary[/]", style="cyan")
    console.print()

    table = Table(show_header=True, header_style="bold cyan", expand=False)
    table.add_column("Category",  style="dim", width=22)
    table.add_column("Found",     justify="right", width=10)
    table.add_column("Details",   style="dim", width=36)

    def count(key):
        val = results.get(key, [])
        return str(len(val)) if isinstance(val, (list, dict, set)) else "0"

    def strval(key, fallback="none"):
        val = results.get(key, fallback)
        # always convert to plain string — rich can't render lists
        if isinstance(val, list):
            return ", ".join(str(x) for x in val[:3]) or fallback
        return str(val) if val else fallback

    table.add_row("Subdomains",    count("subdomains"),    "crt.sh + brute-force")
    table.add_row("Open ports",    count("open_ports"),    "TCP top ports")
    table.add_row("HTTP services", count("http_services"), "live web servers")
    table.add_row("JS endpoints",  count("js_endpoints"),  "from JS files")
    table.add_row("JS secrets",    count("js_secrets"),    "keys/tokens found")
    table.add_row("Emails",        count("emails"),        "harvested")
    table.add_row("Vuln hints",    count("vuln_hints"),    "sorted by severity")
    table.add_row("Takeovers",     count("takeovers"),     "subdomain takeover")
    table.add_row("WAF detected",  strval("waf"),          "")
    table.add_row("Tech stack",    strval("tech_stack"),   "")

    console.print(table)
    console.print()
    console.print(f"  [dim]Total scan time:[/] [bold]{round(elapsed_total, 2)}s[/]")
    console.print(f"  [dim]Target:[/]          [bold]{config['target']}[/]")
    console.print()


# ════════════════════════════════════════════════════════════════════════════
#  MAIN  — entry point, orchestrates everything
# ════════════════════════════════════════════════════════════════════════════

def main():
    """
    The main function — this is what runs when you do: python reconx.py
    
    Flow:
      1. Parse arguments
      2. Build config
      3. Validate target
      4. Run each pipeline stage in order
      5. Generate report
      6. Print summary
    """

    # ── step 0: show banner ────────────────────────────────────────────────
    print_banner()

    # ── step 1: parse args ────────────────────────────────────────────────
    parser = build_arg_parser()

    # if user ran the script with NO arguments, show help and exit
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    # ── step 2: build config dict ─────────────────────────────────────────
    config = build_config(args)

    if not config["quiet"]:
        console.print(f"[bold]Target:[/]  [cyan]{config['target']}[/]")
        console.print(f"[bold]Threads:[/] {config['threads']}   "
                      f"[bold]Timeout:[/] {config['timeout']}s   "
                      f"[bold]Output:[/] {config['output_fmt']}")
        if config["skip_stages"]:
            console.print(f"[yellow]Skipping:[/] {', '.join(config['skip_stages'])}")

    # ── step 3: make sure the output folder exists ────────────────────────
    Path(config["output_dir"]).mkdir(parents=True, exist_ok=True)

    # ── step 4: shared results dict — every stage writes into this ─────────
    results = {
        "target":     config["target"],
        "scan_start": config["scan_start"],
    }

    total_start = time.time()

    try:
        # ── STAGE 0: Validation ───────────────────────────────────────────
        # check the target is real before doing anything else
        console.print()
        console.rule("[bold]Validation[/]", style="dim")

        validation = validate_target(config["target"], config)
        # validate_target returns a dict like:
        # { "target_type": "domain", "ip": "93.184.216.34", "is_valid": True }

        if not validation.get("is_valid"):
            console.print(f"[red][!] Invalid target: {config['target']}[/]")
            sys.exit(1)

        results.update(validation)
        console.print(f"  [green]✓[/] Target resolved: "
                      f"[cyan]{config['target']}[/] → [dim]{validation.get('ip', 'N/A')}[/]")

        # ── STAGE 1: Passive Recon ────────────────────────────────────────
        run_stage(
            name    = "Passive Recon",
            func    = run_passive_recon,
            args    = (config["target"],),   # positional args before config
            config  = config,
            results = results
        )

        # ── STAGE 2: Active Recon ─────────────────────────────────────────
        run_stage(
            name    = "Active Recon",
            func    = run_active_recon,
            args    = (config["target"], config["wordlist"]),
            config  = config,
            results = results
        )

        # ── STAGE 3: Service Discovery ────────────────────────────────────
        # pass in the list of subdomains we found in stage 2
        # so we can scan ports on all of them
        targets_to_scan = results.get("subdomains", []) + [config["target"]]

        run_stage(
            name    = "Service Discovery",
            func    = run_service_discovery,
            args    = (targets_to_scan,),
            config  = config,
            results = results
        )

        # ── STAGE 4: Analysis Engine ──────────────────────────────────────
        run_stage(
            name    = "Analysis Engine",
            func    = run_analysis,
            args    = (results,),    # analysis looks at ALL previous results
            config  = config,
            results = results
        )

    except KeyboardInterrupt:
        # user hit Ctrl+C — still generate a partial report
        console.print("\n[yellow]\n[!] Scan interrupted. Generating partial report...[/]")

    # ── STAGE 5: Reporting ─────────────────────────────────────────────────
    console.print()
    console.rule("[bold]Reporting[/]", style="dim")

    try:
        report_paths = generate_report(results, config)
        # generate_report returns a dict like:
        # { "html": "reports/example.com_2024.html", "json": "..." }

        for fmt, path in report_paths.items():
            console.print(f"  [green]✓[/] {fmt.upper()} report: [underline]{path}[/]")

    except Exception as e:
        console.print(f"  [red]✗[/] Report generation failed: {e}")

    # ── Final Summary ──────────────────────────────────────────────────────
    elapsed_total = time.time() - total_start
    print_summary(results, config, elapsed_total)

    console.print("[dim]ReconX done. Always scan with permission.[/]\n")


# ════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT  — only runs if this file is executed directly
# ════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    main()