# modules/passive.py
# ─────────────────────────────────────────────────────
# PASSIVE RECON — we never touch the target directly here.
# All data comes from third-party sources:
#   → WHOIS registries
#   → DNS record lookups
#   → crt.sh (certificate transparency logs)
#   → ip-api.com (geo + ASN info)
#   → Shodan (optional, needs API key)
#
# Why passive? No logs on target server. Safe. Legal.
# ─────────────────────────────────────────────────────

import socket           # DNS lookups
import json             # parsing API responses
import time             # small delays between requests
import re               # regex for cleaning data

import requests
requests.packages.urllib3.disable_warnings()

# dnspython — better DNS library than socket
# if not installed, we fall back to socket
try:
    import dns.resolver
    import dns.reversename
    DNS_LIB = True
except ImportError:
    DNS_LIB = False

# python-whois — for WHOIS lookups
try:
    import whois
    WHOIS_LIB = True
except ImportError:
    WHOIS_LIB = False


# shared headers for all requests in this module
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) "
        "AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36"
    ),
    "Accept": "application/json, text/html, */*",
}


# ══════════════════════════════════════════════════════
#  SECTION 1 — WHOIS LOOKUP
# ══════════════════════════════════════════════════════

def run_whois(domain, config):
    """
    WHOIS = the "who owns this domain?" database.

    Every domain registration is publicly recorded.
    We can find: registrar, creation date, expiry date,
    name servers, and sometimes registrant contact info.

    Why useful for pentest?
    - Expiry date close? Domain hijack opportunity.
    - Name servers reveal DNS provider (Route53, Cloudflare, etc.)
    - Creation date helps gauge org maturity
    - Registrant org name useful for social engineering recon
    """

    result = {
        "registrar":      None,
        "created":        None,
        "expires":        None,
        "updated":        None,
        "name_servers":   [],
        "registrant_org": None,
        "registrant_country": None,
        "emails":         [],
        "status":         [],
        "raw":            None,
        "error":          None,
    }

    if not WHOIS_LIB:
        result["error"] = "python-whois not installed (pip install python-whois)"
        return result

    try:
        w = whois.whois(domain)

        # helper: convert whois dates to readable string
        # whois returns either a datetime or a list of datetimes
        def fmt_date(d):
            if not d:
                return None
            if isinstance(d, list):
                d = d[0]  # take first date if multiple
            try:
                return d.strftime("%Y-%m-%d")
            except Exception:
                return str(d)

        # name servers — normalize to list of lowercase strings
        ns = w.name_servers or []
        if isinstance(ns, str):
            ns = [ns]
        ns = [n.lower().rstrip(".") for n in ns if n]

        # emails — whois sometimes exposes registrant emails
        emails = w.emails or []
        if isinstance(emails, str):
            emails = [emails]

        # domain status (can be multiple like "clientTransferProhibited")
        status = w.status or []
        if isinstance(status, str):
            status = [status]
        # clean up — strip URLs that sometimes appear after status codes
        status = [s.split(" ")[0] for s in status]

        result.update({
            "registrar":          str(w.registrar or ""),
            "created":            fmt_date(w.creation_date),
            "expires":            fmt_date(w.expiration_date),
            "updated":            fmt_date(w.updated_date),
            "name_servers":       ns,
            "registrant_org":     str(w.org or w.registrant or ""),
            "registrant_country": str(w.country or ""),
            "emails":             list(set(emails)),  # dedupe
            "status":             status,
        })

    except Exception as e:
        result["error"] = f"WHOIS failed: {str(e)}"

    return result


# ══════════════════════════════════════════════════════
#  SECTION 2 — DNS RECORDS
# ══════════════════════════════════════════════════════

def run_dns_records(domain, config):
    """
    DNS records reveal a LOT about a target's infrastructure.

    Record types we check:
    - A     → IPv4 address the domain points to
    - AAAA  → IPv6 address
    - MX    → mail servers (who handles their email?)
    - NS    → name servers (who manages their DNS?)
    - TXT   → text records — often contains SPF, DKIM, verification tokens
    - CNAME → aliases (is this domain pointing to another service?)
    - SOA   → start of authority (primary DNS server info)
    - CAA   → certificate authority authorization (who can issue SSL certs?)

    Why useful for pentest?
    - TXT records leak: Google verification, Stripe, AWS, Atlassian tokens
    - MX records reveal email provider (Gmail, O365, custom?)
    - CNAME to external services = potential subdomain takeover
    - SPF records in TXT show all authorized mail senders
    """

    records = {
        "A":     [],
        "AAAA":  [],
        "MX":    [],
        "NS":    [],
        "TXT":   [],
        "CNAME": [],
        "SOA":   [],
        "CAA":   [],
        "error": None,
    }

    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]

    if DNS_LIB:
        # use dnspython — more reliable and detailed
        resolver = dns.resolver.Resolver()
        resolver.timeout     = config.get("timeout", 5)
        resolver.lifetime    = config.get("timeout", 5)

        for rtype in record_types:
            try:
                answers = resolver.resolve(domain, rtype)

                for rdata in answers:
                    val = str(rdata).rstrip(".")

                    # MX records have a priority number — include it
                    if rtype == "MX":
                        records[rtype].append({
                            "priority": rdata.preference,
                            "host":     str(rdata.exchange).rstrip(".")
                        })
                    else:
                        records[rtype].append(val)

            except dns.resolver.NXDOMAIN:
                # domain doesn't exist
                records["error"] = "Domain does not exist (NXDOMAIN)"
                break

            except dns.resolver.NoAnswer:
                # no records of this type — normal, just skip
                pass

            except dns.resolver.Timeout:
                pass

            except Exception:
                pass

    else:
        # fallback to socket — only gets A records
        try:
            infos = socket.getaddrinfo(domain, None)
            for info in infos:
                ip = info[4][0]
                if ":" in ip:
                    # IPv6 addresses contain colons
                    if ip not in records["AAAA"]:
                        records["AAAA"].append(ip)
                else:
                    if ip not in records["A"]:
                        records["A"].append(ip)
        except Exception as e:
            records["error"] = str(e)

    # ── bonus: scan TXT records for interesting tokens ─────────────────────
    # TXT records often contain secrets left by devs verifying services
    interesting_txt = []
    txt_patterns = {
        "SPF record":           r"v=spf1",
        "DKIM record":          r"v=DKIM1",
        "DMARC record":         r"v=DMARC1",
        "Google verification":  r"google-site-verification",
        "Stripe verification":  r"stripe-verification",
        "AWS SES":              r"amazonses",
        "Atlassian/Jira":       r"atlassian-domain-verification",
        "Facebook domain":      r"facebook-domain-verification",
        "Zoho mail":            r"zoho-verification",
        "Mailgun":              r"mailgun",
        "SendGrid":             r"sendgrid",
        "HubSpot":              r"hubspot",
        "MS Office365":         r"MS=ms",
        "Docusign":             r"docusign",
    }

    for txt_val in records["TXT"]:
        for service, pattern in txt_patterns.items():
            if re.search(pattern, txt_val, re.I):
                interesting_txt.append({
                    "service": service,
                    "value":   txt_val[:120]
                })

    records["interesting_txt"] = interesting_txt

    return records


# ══════════════════════════════════════════════════════
#  SECTION 3 — GEO + ASN INFO
# ══════════════════════════════════════════════════════

def run_geo_asn(ip, config):
    """
    Given an IP address, finds:
    - Country / city / region
    - ISP name
    - ASN (Autonomous System Number) — identifies the network owner
    - Organization name
    - Whether it's a hosting/datacenter IP

    Why useful?
    - ASN tells you if they're on AWS, Cloudflare, Azure, etc.
    - Hosting IP = WAF/CDN likely in front
    - Org name helps confirm you have the right target
    - Country = jurisdiction context

    Uses ip-api.com (free, no key needed, 45 req/min limit)
    """

    result = {
        "ip":           ip,
        "country":      None,
        "country_code": None,
        "region":       None,
        "city":         None,
        "isp":          None,
        "org":          None,
        "asn":          None,
        "hosting":      False,
        "error":        None,
    }

    try:
        # ip-api.com free tier — returns JSON with geo + ASN data
        # fields param = only request what we need (saves bandwidth)
        fields = "status,country,countryCode,regionName,city,isp,org,as,hosting"
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields={fields}",
            headers=HEADERS,
            timeout=config.get("timeout", 8)
        )

        if r.status_code == 200:
            data = r.json()

            if data.get("status") == "success":
                result.update({
                    "country":      data.get("country"),
                    "country_code": data.get("countryCode"),
                    "region":       data.get("regionName"),
                    "city":         data.get("city"),
                    "isp":          data.get("isp"),
                    "org":          data.get("org"),
                    "asn":          data.get("as"),   # format: "AS13335 Cloudflare Inc."
                    "hosting":      data.get("hosting", False),
                })
            else:
                result["error"] = "ip-api returned non-success status"

        # small delay to respect ip-api rate limit (45/min free tier)
        time.sleep(0.2)

    except Exception as e:
        result["error"] = f"Geo/ASN lookup failed: {str(e)}"

    return result


# ══════════════════════════════════════════════════════
#  SECTION 4 — CRT.SH SUBDOMAIN DISCOVERY
# ══════════════════════════════════════════════════════

def run_crtsh(domain, config):
    """
    crt.sh = certificate transparency log search engine.

    When ANY SSL certificate is issued for a domain, it gets
    permanently logged in public certificate transparency logs.
    crt.sh indexes all of them and lets us search for free.

    This finds subdomains that:
    - Were never meant to be public
    - Have been decommissioned but still resolve
    - Belong to dev/staging environments

    Why it's powerful:
    - Completely passive (we never touch the target)
    - Finds subdomains brute-force would miss
    - Certificates are issued for real hostnames

    Example findings:
    - dev.example.com
    - staging-api.example.com
    - internal.example.com  ← gold
    - vpn.example.com       ← gold
    """

    result = {
        "subdomains":  [],
        "total_certs": 0,
        "error":       None,
    }

    try:
        # query crt.sh for all certificates issued for *.domain
        # the % is SQL wildcard meaning "any subdomain"
        r = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            headers=HEADERS,
            timeout=15  # crt.sh can be slow — give it time
        )

        if r.status_code != 200:
            result["error"] = f"crt.sh returned status {r.status_code}"
            return result

        certs = r.json()
        result["total_certs"] = len(certs)

        # extract all unique subdomains from all certificates
        subdomains = set()

        for cert in certs:
            # name_value can contain multiple names separated by newlines
            # e.g. "*.example.com\nexample.com\napi.example.com"
            name_value = cert.get("name_value", "")

            for name in name_value.split("\n"):
                name = name.strip().lower()

                # skip wildcards like *.example.com
                # (they don't tell us specific subdomains)
                if name.startswith("*"):
                    name = name.lstrip("*.")

                # only keep names that are subdomains of our target
                if name.endswith(f".{domain}") and name != domain:
                    subdomains.add(name)

                # also keep the exact domain itself
                elif name == domain:
                    pass  # skip — we already know the main domain

        # sort alphabetically for clean output
        result["subdomains"] = sorted(list(subdomains))

    except json.JSONDecodeError:
        result["error"] = "crt.sh returned invalid JSON (may be rate limited)"

    except requests.exceptions.Timeout:
        result["error"] = "crt.sh request timed out"

    except Exception as e:
        result["error"] = f"crt.sh lookup failed: {str(e)}"

    return result


# ══════════════════════════════════════════════════════
#  SECTION 5 — SHODAN LOOKUP (optional)
# ══════════════════════════════════════════════════════

def run_shodan(ip, api_key, config):
    """
    Shodan = search engine for internet-connected devices.
    It constantly scans the entire internet and stores:
    - Open ports on every IP
    - Service banners (what software is running)
    - SSL certificate info
    - Known vulnerabilities (CVEs)
    - Geographic info

    This is PASSIVE — we're just querying Shodan's database,
    not touching the target ourselves.

    Requires a Shodan API key (free tier available at shodan.io)
    Pass it with: python reconx.py -t example.com --shodan YOUR_KEY
    """

    result = {
        "ports":      [],
        "services":   [],
        "vulns":      [],
        "os":         None,
        "hostnames":  [],
        "tags":       [],
        "error":      None,
        "skipped":    False,
    }

    # if no API key provided, skip silently
    if not api_key:
        result["skipped"] = True
        result["error"]   = "No Shodan API key provided (use --shodan KEY)"
        return result

    try:
        r = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}?key={api_key}",
            headers=HEADERS,
            timeout=config.get("timeout", 10)
        )

        if r.status_code == 401:
            result["error"] = "Invalid Shodan API key"
            return result

        if r.status_code == 404:
            result["error"] = f"IP {ip} not found in Shodan database"
            return result

        if r.status_code != 200:
            result["error"] = f"Shodan returned status {r.status_code}"
            return result

        data = r.json()

        # extract open ports
        ports = data.get("ports", [])

        # extract service info from each port's data
        services = []
        for item in data.get("data", []):
            svc = {
                "port":      item.get("port"),
                "transport": item.get("transport", "tcp"),
                "product":   item.get("product", ""),
                "version":   item.get("version", ""),
                "banner":    item.get("data", "")[:200],
            }
            services.append(svc)

        # extract known CVEs if any
        vulns = list(data.get("vulns", {}).keys())
        # vulns looks like: ["CVE-2021-44228", "CVE-2020-1234"]

        result.update({
            "ports":     ports,
            "services":  services,
            "vulns":     vulns,
            "os":        data.get("os"),
            "hostnames": data.get("hostnames", []),
            "tags":      data.get("tags", []),
            # tags can be: ["cdn", "self-signed", "vpn", "tor", etc.]
        })

    except Exception as e:
        result["error"] = f"Shodan lookup failed: {str(e)}"

    return result


# ══════════════════════════════════════════════════════
#  MAIN FUNCTION — called by reconx.py
# ══════════════════════════════════════════════════════

def run_passive_recon(domain, config):
    """
    Main entry point — reconx.py calls this as:
        run_passive_recon(config["target"], config)

    Runs all passive recon sections in order and returns
    one big dict that gets merged into the global results.

    Order matters here:
    1. WHOIS  — get registrar/NS info
    2. DNS    — get all record types
    3. Geo    — get IP location/ASN (needs IP from DNS)
    4. crt.sh — get subdomains from certificates
    5. Shodan — get port/vuln data (needs IP, optional)
    """

    results = {}

    # ── 1. WHOIS ──────────────────────────────────────────────────────────
    if config.get("verbose"):
        print("    running WHOIS...")

    whois_data = run_whois(domain, config)
    results["whois"] = whois_data

    # ── 2. DNS records ────────────────────────────────────────────────────
    if config.get("verbose"):
        print("    running DNS records...")

    dns_data = run_dns_records(domain, config)
    results["dns_records"] = dns_data

    # grab the IP from DNS A records for later use
    # fall back to socket if DNS module didn't get it
    ip = None
    if dns_data.get("A"):
        ip = dns_data["A"][0]  # use first A record IP
    else:
        try:
            ip = socket.gethostbyname(domain)
        except Exception:
            pass

    results["resolved_ip"] = ip

    # ── 3. Geo + ASN ──────────────────────────────────────────────────────
    if ip:
        if config.get("verbose"):
            print(f"    running Geo/ASN for {ip}...")

        geo_data = run_geo_asn(ip, config)
        results["geo_asn"] = geo_data
    else:
        results["geo_asn"] = {"error": "No IP resolved — skipping geo lookup"}

    # ── 4. crt.sh subdomains ──────────────────────────────────────────────
    if config.get("verbose"):
        print("    running crt.sh lookup...")

    crt_data = run_crtsh(domain, config)
    results["crtsh"] = crt_data

    # expose subdomains at top level so active.py can use them
    # active recon will ADD to this list via brute-force
    results["subdomains"] = crt_data.get("subdomains", [])

    # ── 5. Shodan (optional) ──────────────────────────────────────────────
    shodan_key = config.get("shodan_key")

    if ip:
        if config.get("verbose"):
            print("    running Shodan lookup...")

        shodan_data = run_shodan(ip, shodan_key, config)
        results["shodan"] = shodan_data

        # if Shodan found known CVEs, surface them at top level
        # so analysis.py can pick them up
        if shodan_data.get("vulns"):
            results["shodan_vulns"] = shodan_data["vulns"]
    else:
        results["shodan"] = {"skipped": True, "error": "No IP resolved"}

    return results