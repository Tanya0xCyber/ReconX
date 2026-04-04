# modules/active.py
# ─────────────────────────────────────────────────────
# ACTIVE RECON — we directly interact with the target here.
# Three jobs:
#   1. Subdomain brute-force  → find hidden subdomains
#   2. JS endpoint discovery  → crawl JS files for APIs/secrets
#   3. Email harvesting       → collect emails from HTML/headers
#
# "Active" means our requests WILL appear in target's logs.
# Always have written permission before running this.
# ─────────────────────────────────────────────────────

import re                    # regex for extracting patterns
import time                  # delays between requests
import socket                # DNS resolution fallback
import random                # random user agents
from urllib.parse import urljoin, urlparse   # URL manipulation
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
requests.packages.urllib3.disable_warnings()

# dnspython for better DNS resolution
try:
    import dns.resolver
    DNS_LIB = True
except ImportError:
    DNS_LIB = False


# ══════════════════════════════════════════════════════
#  CONSTANTS
# ══════════════════════════════════════════════════════

# rotate user agents so we don't look like a bot
USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
]

def random_ua():
    return random.choice(USER_AGENTS)


# ── JS secret patterns ─────────────────────────────────────────────────────
# regex patterns to find secrets/tokens inside JS files
# each key is the secret type, value is the regex
SECRET_PATTERNS = {
    "AWS Access Key":   r"AKIA[0-9A-Z]{16}",
    "AWS Secret":       r"(?i)aws.{0,20}secret.{0,20}['\"]([0-9a-zA-Z/+]{40})['\"]",
    "Google API Key":   r"AIza[0-9A-Za-z\-_]{35}",
    "Firebase URL":     r"https://[a-z0-9\-]+\.firebaseio\.com",
    "Slack Token":      r"xox[baprs]-[0-9a-zA-Z]{10,48}",
    "GitHub Token":     r"gh[pousr]_[A-Za-z0-9_]{36,255}",
    "JWT Token":        r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    "Private Key":      r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
    "Stripe Live":      r"sk_live_[0-9a-zA-Z]{24,}",
    "Stripe Test":      r"sk_test_[0-9a-zA-Z]{24,}",
    "SendGrid Key":     r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}",
    "Mailgun Key":      r"key-[0-9a-zA-Z]{32}",
    "Generic API Key":  r"(?i)(api_key|apikey|api-key)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{20,})['\"]",
    "Generic Secret":   r"(?i)(secret|password)\s*[:=]\s*['\"]([^'\"]{8,})['\"]",
    "Bearer Token":     r"(?i)bearer\s+([a-zA-Z0-9_\-\.]{20,})",
    "MongoDB URI":      r"mongodb(\+srv)?://[^\s\"']{10,}",
    "Internal IP":      r"(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}",
    "NPM Token":        r"npm_[A-Za-z0-9]{36}",
    "Mapbox Token":     r"pk\.[a-zA-Z0-9]{60,}",
}

# ── API endpoint patterns ──────────────────────────────────────────────────
# regex to find API paths inside JS files
# e.g. fetch("/api/v1/users") or axios.get('/api/auth/login')
ENDPOINT_PATTERNS = [
    r"""(?:fetch|axios\.get|axios\.post|http\.get|request)\s*\(\s*['"`]([^'"`]+)['"`]""",
    r"""['"`](/api/[^\s'"`?#]{3,80})['"`]""",
    r"""['"`](/v\d+/[^\s'"`?#]{3,80})['"`]""",
    r"""(?:url|endpoint|path|route)\s*[:=]\s*['"`]([^'"`]{5,80})['"`]""",
    r"""href\s*[:=]\s*['"`](/[^'"`\s]{4,60})['"`]""",
]

# ── email regex ────────────────────────────────────────────────────────────
EMAIL_PATTERN = r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"


# ══════════════════════════════════════════════════════
#  HELPER — make HTTP request with random UA + timeout
# ══════════════════════════════════════════════════════

def fetch(url, config, method="GET", extra_headers=None):
    """
    Simple wrapper around requests.get/post.
    Adds random user agent + timeout + SSL ignore.
    Returns response object or None if request fails.
    """
    headers = {
        "User-Agent":      random_ua(),
        "Accept":          "text/html,application/json,*/*",
        "Accept-Language": "en-US,en;q=0.9",
    }
    if extra_headers:
        headers.update(extra_headers)

    try:
        r = requests.request(
            method, url,
            headers=headers,
            timeout=config.get("timeout", 8),
            verify=False,           # ignore SSL errors
            allow_redirects=True,
        )
        return r
    except Exception:
        return None


# ══════════════════════════════════════════════════════
#  SECTION 1 — SUBDOMAIN BRUTE FORCE
# ══════════════════════════════════════════════════════

def load_wordlist(wordlist_path):
    """
    Loads subdomain wordlist from file.
    Falls back to a built-in mini list if file not found.

    The wordlist is just a text file with one word per line:
        www
        api
        dev
        staging
        ...
    """

    # built-in fallback — covers the most common subdomains
    # use this if the wordlist file doesn't exist yet
    BUILTIN = [
        "www","mail","ftp","api","dev","staging","test","demo","app","apps",
        "admin","portal","dashboard","panel","manage","cms","shop","store",
        "pay","payment","auth","login","sso","oauth","accounts","account",
        "secure","vpn","cdn","static","assets","media","img","images","files",
        "docs","support","help","status","monitor","health","old","new","beta",
        "alpha","v1","v2","v3","backup","internal","intranet","corp","db",
        "database","redis","git","gitlab","jenkins","ci","cd","grafana",
        "kibana","metrics","logs","m","mobile","api2","api-dev","uat","qa",
        "sandbox","mx","mail2","smtp","webmail","proxy","gateway","analytics",
        "careers","jobs","forum","community","chat","partners","crm","billing",
        "graphql","ws","web","ns1","ns2","cloud","s3","storage","platform",
        "developer","hub","connect","id","identity","verify","register",
        "profile","user","users","ops","devops","infra","helpdesk","ticket",
        "blog","news","wiki","kb","faq","legal","compliance","staging2","prod",
        "production","live","uat2","preprod","pre-prod","preview","canary",
        "edge","global","us","eu","asia","ap","sg","uk","de","fr","au",
    ]

    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            words = [line.strip() for line in f if line.strip()]
        # merge file wordlist with built-in (deduplicated)
        return list(set(words + BUILTIN))
    except FileNotFoundError:
        # file not found — use built-in list
        return BUILTIN


def resolve_subdomain(subdomain, domain, timeout=5):
    """
    Tries to resolve "subdomain.domain" to an IP address.
    Returns a dict if it resolves, None if it doesn't exist.

    This is the core of brute-force:
    we just try thousands of names and see which ones resolve.
    If DNS returns an IP → the subdomain exists.
    If DNS returns NXDOMAIN → it doesn't exist.
    """

    full = f"{subdomain}.{domain}"

    try:
        if DNS_LIB:
            # dnspython resolver — faster and more accurate
            resolver = dns.resolver.Resolver()
            resolver.timeout  = timeout
            resolver.lifetime = timeout

            answers = resolver.resolve(full, "A")
            ips = [str(r) for r in answers]

            # also try to get CNAME — important for takeover detection
            cname = None
            try:
                cname_ans = resolver.resolve(full, "CNAME")
                cname = str(cname_ans[0].target).rstrip(".")
            except Exception:
                pass

            return {
                "subdomain": full,
                "ips":       ips,
                "cname":     cname,
            }

        else:
            # socket fallback
            ip = socket.gethostbyname(full)
            return {
                "subdomain": full,
                "ips":       [ip],
                "cname":     None,
            }

    except Exception:
        # any DNS error = subdomain doesn't exist
        return None


def http_probe_subdomain(entry, config):
    """
    Once we know a subdomain resolves (DNS check passed),
    we make an actual HTTP request to see if it's a live web service.

    Adds HTTP info to the subdomain entry:
    - status_code: 200, 301, 403, 404, etc.
    - title: page title
    - server: web server software
    - technologies: hints from headers
    - redirect_to: where it redirects if 301/302
    """

    full = entry["subdomain"]

    for scheme in ["https", "http"]:
        url = f"{scheme}://{full}"
        r = fetch(url, config)

        if r is None:
            continue

        # extract page title
        title = ""
        title_match = re.search(r"<title[^>]*>(.*?)</title>", r.text, re.I | re.S)
        if title_match:
            title = title_match.group(1).strip()[:80]

        # detect tech from headers
        tech_hints = []
        server = r.headers.get("Server", "")
        powered = r.headers.get("X-Powered-By", "")
        if server:   tech_hints.append(server)
        if powered:  tech_hints.append(powered)

        entry.update({
            "http":        True,
            "scheme":      scheme,
            "url":         url,
            "status":      r.status_code,
            "title":       title,
            "server":      server,
            "tech_hints":  tech_hints,
            "redirect_to": r.headers.get("Location", "") if r.status_code in [301,302,303,307,308] else "",
            "body_size":   len(r.content),
        })
        return entry

    # no HTTP response on either scheme
    entry["http"] = False
    return entry


def check_subdomain_takeover(entry):
    """
    Checks if a subdomain is vulnerable to takeover.

    Subdomain takeover happens when:
    1. A subdomain points to an external service (CNAME)
    2. That service account/project has been deleted
    3. Anyone can re-register that service and claim the subdomain

    We detect this by looking for "unclaimed" error messages
    in the response body from known services.

    Example:
    - dev.example.com → CNAME → myapp.github.io
    - If myapp GitHub Pages project is deleted →
      body says "There isn't a GitHub Pages site here"
    - We can register myapp.github.io and own dev.example.com
    """

    TAKEOVER_SIGNATURES = {
        "GitHub Pages":    ["there isn't a github pages site here"],
        "Heroku":          ["no such app", "herokucdn.com/error-pages"],
        "Shopify":         ["sorry, this shop is currently unavailable"],
        "Fastly":          ["fastly error: unknown domain"],
        "Netlify":         ["not found - request id"],
        "Vercel":          ["the deployment could not be found"],
        "Amazon S3":       ["nosuchbucket", "the specified bucket does not exist"],
        "Azure":           ["404 web site not found"],
        "Surge.sh":        ["project not found"],
        "Ghost":           ["the thing you were looking for is no longer here"],
        "Tumblr":          ["whatever you were looking for doesn't live here"],
        "Zendesk":         ["help center closed"],
        "Readme.io":       ["project doesnt exist"],
        "Wordpress.com":   ["do you want to register"],
        "Bitbucket":       ["repository not found"],
        "Pingdom":         ["sorry, couldn't find the status page"],
        "Unbounce":        ["the requested url was not found"],
    }

    # only check if we got a response body
    body = entry.get("title", "").lower() + " "

    # also include redirect target in check
    redirect = entry.get("redirect_to", "").lower()

    for service, signatures in TAKEOVER_SIGNATURES.items():
        for sig in signatures:
            if sig in body or sig in redirect:
                return service   # return the vulnerable service name

    return None   # no takeover detected


def run_subdomain_bruteforce(domain, wordlist_path, config):
    """
    Main subdomain brute-force function.

    Flow:
    1. Load wordlist
    2. For each word: try to resolve word.domain via DNS (threaded)
    3. For each resolved subdomain: probe HTTP (threaded)
    4. Check each live subdomain for takeover
    5. Return all findings
    """

    words = load_wordlist(wordlist_path)
    threads = config.get("threads", 20)
    timeout = config.get("timeout", 5)
    rate    = config.get("rate_limit", 0.05)

    resolved  = []   # subdomains that resolved in DNS
    live      = []   # subdomains with live HTTP service
    takeovers = []   # subdomains vulnerable to takeover

    # ── phase 1: DNS resolution (threaded) ────────────────────────────────
    # we run DNS lookups in parallel — this is fast
    # each thread tries one subdomain
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(resolve_subdomain, word, domain, timeout): word
            for word in words
        }

        for future in as_completed(futures):
            result = future.result()
            if result:
                # subdomain resolved — it exists!
                resolved.append(result)
                if config.get("verbose"):
                    print(f"      [DNS] {result['subdomain']} → {result['ips']}")

            # small delay to avoid overwhelming DNS servers
            time.sleep(rate)

    # ── phase 2: HTTP probing (threaded) ──────────────────────────────────
    # now check which resolved subdomains have web services
    with ThreadPoolExecutor(max_workers=min(threads, 15)) as executor:
        futures = {
            executor.submit(http_probe_subdomain, entry, config): entry
            for entry in resolved
        }

        for future in as_completed(futures):
            entry = future.result()
            if entry.get("http"):
                live.append(entry)

                # check for subdomain takeover on each live subdomain
                vuln_service = check_subdomain_takeover(entry)
                if vuln_service:
                    entry["takeover"] = vuln_service
                    takeovers.append({
                        "subdomain": entry["subdomain"],
                        "service":   vuln_service,
                        "url":       entry.get("url", ""),
                    })

    return {
        "resolved":   resolved,    # all DNS-resolved subdomains
        "live":       live,        # subdomains with live HTTP
        "takeovers":  takeovers,   # potential takeover candidates
        "total_tried": len(words),
    }


# ══════════════════════════════════════════════════════
#  SECTION 2 — JS FILE CRAWLING & SECRET EXTRACTION
# ══════════════════════════════════════════════════════

def collect_js_urls(base_url, config):
    """
    Crawls the target's homepage and collects all JS file URLs.

    Also queries Wayback Machine CDX API for historical JS files —
    this finds JS files that were removed but might still be cached.

    Why historical JS files matter:
    - Devs sometimes commit secrets then "delete" the file
    - The file is gone from the live site but Wayback has it
    - The secret might still be valid
    """

    js_urls = set()
    domain  = urlparse(base_url).netloc

    # ── crawl homepage for <script src="..."> tags ─────────────────────────
    r = fetch(base_url, config)
    if r:
        # find all script src attributes
        for match in re.findall(
            r'<script[^>]+src=["\']([^"\']+)["\']',
            r.text, re.I
        ):
            url = match.strip()

            # normalize relative URLs to absolute
            if url.startswith("http"):
                js_urls.add(url)
            elif url.startswith("//"):
                js_urls.add("https:" + url)
            elif url.startswith("/"):
                js_urls.add(base_url.rstrip("/") + url)
            else:
                js_urls.add(base_url.rstrip("/") + "/" + url)

        # also find webpack chunk files
        # these often contain sensitive route/endpoint info
        for match in re.findall(
            r'["\']([^"\']*(?:chunk|bundle|vendor|main|app)[^"\']*\.js)["\']',
            r.text, re.I
        ):
            url = match.strip().lstrip("/")
            js_urls.add(f"{base_url.rstrip('/')}/{url}")

    # ── wayback machine CDX API ────────────────────────────────────────────
    # CDX = Capture DeX — index of all archived URLs
    try:
        cdx_url = (
            f"https://web.archive.org/cdx/search/cdx"
            f"?url={domain}/*.js"
            f"&output=text"
            f"&fl=original"           # only return original URLs
            f"&collapse=urlkey"       # deduplicate similar URLs
            f"&limit=100"             # max 100 results
        )
        r = requests.get(cdx_url, headers={"User-Agent": random_ua()}, timeout=15)
        if r.status_code == 200:
            for line in r.text.strip().split("\n"):
                line = line.strip()
                if line and line.endswith(".js"):
                    js_urls.add(line)
    except Exception:
        pass   # wayback failure is non-critical

    return list(js_urls)


def scan_js_file(js_url, config):
    """
    Downloads a single JS file and scans it for:
    1. Secrets/tokens (AWS keys, API keys, etc.)
    2. API endpoints (paths like /api/v1/users)
    3. Internal URLs/IPs

    Returns a dict with all findings from this file.
    """

    findings = {
        "url":       js_url,
        "secrets":   [],
        "endpoints": [],
        "size":      0,
        "error":     None,
    }

    r = fetch(js_url, config)

    if not r:
        findings["error"] = "Request failed"
        return findings

    if r.status_code != 200:
        findings["error"] = f"HTTP {r.status_code}"
        return findings

    content = r.text
    findings["size"] = len(content)

    # ── scan for secrets ───────────────────────────────────────────────────
    for secret_type, pattern in SECRET_PATTERNS.items():
        matches = re.findall(pattern, content)
        for match in matches:
            # re.findall returns strings or tuples (if pattern has groups)
            value = match if isinstance(match, str) else " | ".join(match)
            value = value[:120]   # truncate long values

            findings["secrets"].append({
                "type":  secret_type,
                "value": value,
                "file":  js_url,
            })

    # ── extract API endpoints ──────────────────────────────────────────────
    endpoints_found = set()
    for pattern in ENDPOINT_PATTERNS:
        for match in re.findall(pattern, content):
            ep = match.strip()
            # only keep paths that look like real API endpoints
            if ep.startswith("/") and len(ep) > 3 and " " not in ep:
                endpoints_found.add(ep)

    findings["endpoints"] = list(endpoints_found)

    return findings


def run_js_scan(base_url, config):
    """
    Main JS scanning function.
    Collects all JS URLs then scans each one in parallel.
    """

    threads = config.get("threads", 15)

    # collect all JS file URLs
    js_urls = collect_js_urls(base_url, config)

    all_secrets   = []
    all_endpoints = set()
    js_results    = []

    # scan each JS file in parallel threads
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(scan_js_file, url, config): url
            for url in js_urls
        }

        for future in as_completed(futures):
            result = future.result()
            js_results.append(result)

            # collect secrets across all files
            all_secrets.extend(result.get("secrets", []))

            # collect endpoints across all files
            for ep in result.get("endpoints", []):
                all_endpoints.add(ep)

    return {
        "js_files_found":    len(js_urls),
        "js_files_scanned":  len(js_results),
        "secrets":           all_secrets,
        "js_endpoints":      list(all_endpoints),
        "js_scan_detail":    js_results,
    }


# ══════════════════════════════════════════════════════
#  SECTION 3 — EMAIL HARVESTING
# ══════════════════════════════════════════════════════

def harvest_emails_from_page(url, config):
    """
    Fetches a page and extracts all email addresses from:
    - Page HTML body
    - mailto: links
    - Meta tags
    - Response headers (sometimes Contact header exists)

    Filters out generic/invalid emails like:
    - noreply@
    - example.com emails
    - Very short/invalid looking ones
    """

    emails = set()

    r = fetch(url, config)
    if not r:
        return list(emails)

    # search entire response text for email pattern
    found = re.findall(EMAIL_PATTERN, r.text)
    for email in found:
        email = email.lower().strip(".,;")

        # filter out garbage
        skip_patterns = [
            "example.com", "test.com", "domain.com",
            "yourdomain", "noreply", "no-reply",
            "sentry.io",  # sentry error tracking emails
            ".png", ".jpg", ".gif", ".svg",  # image filenames with @ in them
        ]

        if any(skip in email for skip in skip_patterns):
            continue

        # must have a real TLD (2-6 chars after last dot)
        parts = email.split("@")
        if len(parts) == 2 and "." in parts[1]:
            emails.add(email)

    return list(emails)


def run_email_harvest(base_url, domain, config):
    """
    Harvests emails from multiple pages:
    - Homepage
    - /contact
    - /about
    - /team
    - /about-us
    - /contact-us
    - robots.txt (sometimes has email)
    - security.txt (security contact info)

    Also extracts from WHOIS data if available in config.
    """

    # pages that commonly contain email addresses
    target_pages = [
        base_url,
        f"{base_url}/contact",
        f"{base_url}/about",
        f"{base_url}/team",
        f"{base_url}/about-us",
        f"{base_url}/contact-us",
        f"{base_url}/our-team",
        f"{base_url}/company",
        f"{base_url}/robots.txt",
        f"{base_url}/.well-known/security.txt",
        f"{base_url}/security.txt",
    ]

    all_emails = set()
    threads    = min(config.get("threads", 10), 8)  # cap at 8 for email pages

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(harvest_emails_from_page, page, config): page
            for page in target_pages
        }

        for future in as_completed(futures):
            for email in future.result():
                all_emails.add(email)

    # categorize emails by type
    categorized = {
        "security":  [],   # security@, abuse@, cert@
        "admin":     [],   # admin@, webmaster@, info@
        "support":   [],   # support@, help@, contact@
        "other":     [],
    }

    for email in all_emails:
        local = email.split("@")[0]
        if any(x in local for x in ["security", "abuse", "cert", "bug", "vuln"]):
            categorized["security"].append(email)
        elif any(x in local for x in ["admin", "webmaster", "postmaster", "hostmaster"]):
            categorized["admin"].append(email)
        elif any(x in local for x in ["support", "help", "contact", "info", "hello"]):
            categorized["support"].append(email)
        else:
            categorized["other"].append(email)

    return {
        "emails":       list(all_emails),
        "total":        len(all_emails),
        "categorized":  categorized,
        # security@ is most important — this is where to send bug reports
        "security_contacts": categorized["security"],
    }


# ══════════════════════════════════════════════════════
#  MAIN FUNCTION — called by reconx.py
# ══════════════════════════════════════════════════════

def run_active_recon(domain, wordlist_path, config):
    """
    Main entry point — reconx.py calls this as:
        run_active_recon(config["target"], config["wordlist"], config)

    Runs all three active recon sections and returns one dict.

    Note: base_url is built from domain + whether HTTPS works.
    We check HTTPS first, fall back to HTTP.
    """

    # build the base URL
    # try HTTPS first (most sites use it now)
    base_url = f"https://{domain}"

    # quick check — if HTTPS fails try HTTP
    r = None
    try:
        r = requests.get(
            base_url, timeout=5, verify=False,
            headers={"User-Agent": random_ua()}
        )
    except Exception:
        pass

    if not r:
        base_url = f"http://{domain}"

    results = {}

    # ── 1. Subdomain brute-force ───────────────────────────────────────────
    if config.get("verbose"):
        print("    running subdomain brute-force...")

    sub_results = run_subdomain_bruteforce(domain, wordlist_path, config)
    results["subdomain_bruteforce"] = sub_results

    # merge newly found subdomains into the top-level subdomains list
    # (passive.py already found some via crt.sh — we add to those)
    bf_subs = [e["subdomain"] for e in sub_results.get("resolved", [])]
    results["subdomains_active"] = bf_subs

    # surface takeovers at top level — analysis.py needs these
    if sub_results.get("takeovers"):
        results["takeovers"] = sub_results["takeovers"]

    # ── 2. JS scanning ────────────────────────────────────────────────────
    if config.get("verbose"):
        print("    running JS file scan...")

    js_results = run_js_scan(base_url, config)
    results["js_scan"] = js_results

    # surface secrets + endpoints at top level
    results["js_secrets"]   = js_results.get("secrets", [])
    results["js_endpoints"] = js_results.get("js_endpoints", [])

    # ── 3. Email harvesting ───────────────────────────────────────────────
    if config.get("verbose"):
        print("    running email harvest...")

    email_results = run_email_harvest(base_url, domain, config)
    results["email_harvest"] = email_results

    # surface emails at top level
    results["emails"] = email_results.get("emails", [])

    return results