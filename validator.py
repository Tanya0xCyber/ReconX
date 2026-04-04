# modules/validator.py
# ─────────────────────────────────────────────────────
# This module runs FIRST in the pipeline.
# It checks: is the target valid? can we reach it?
# Returns a dict with target info that all other modules use.
# ─────────────────────────────────────────────────────

import socket       # for resolving domain → IP
import re           # for regex pattern matching
import time         # for measuring response time
import ipaddress    # for checking if input is an IP address

import requests
requests.packages.urllib3.disable_warnings()  # suppress SSL warnings


# ══════════════════════════════════════════════════════
#  HELPER — clean up whatever the user typed as target
# ══════════════════════════════════════════════════════

def normalize_target(raw):
    """
    Takes raw user input and returns a clean domain + base URL.

    Examples:
        "example.com"          → domain: "example.com"
        "https://example.com/" → domain: "example.com"
        "http://example.com"   → domain: "example.com"
        "192.168.1.1"          → domain: "192.168.1.1"
    """

    # strip whitespace and lowercase everything
    raw = raw.strip().lower()

    # remove protocol if present (https:// or http://)
    if raw.startswith("https://"):
        raw = raw[8:]
    elif raw.startswith("http://"):
        raw = raw[7:]

    # remove trailing slash and any path
    # e.g. "example.com/path/to/page" → "example.com"
    raw = raw.split("/")[0]

    # remove port if present
    # e.g. "example.com:8080" → "example.com"
    raw = raw.split(":")[0]

    return raw


# ══════════════════════════════════════════════════════
#  HELPER — figure out if input is domain or IP
# ══════════════════════════════════════════════════════

def detect_target_type(target):
    """
    Returns "ip" if target is an IP address, "domain" if it's a domain name.

    Examples:
        "192.168.1.1"  → "ip"
        "10.0.0.1"     → "ip"
        "example.com"  → "domain"
        "sub.test.org" → "domain"
    """

    try:
        # ipaddress.ip_address() throws ValueError if it's not a valid IP
        ipaddress.ip_address(target)
        return "ip"
    except ValueError:
        return "domain"


# ══════════════════════════════════════════════════════
#  HELPER — check if domain format looks valid
# ══════════════════════════════════════════════════════

def is_valid_domain_format(domain):
    """
    Basic regex check — does this LOOK like a real domain?
    Doesn't check if it actually exists, just the format.

    Valid:   "example.com", "sub.example.co.uk", "test-site.org"
    Invalid: "notadomain", "exam ple.com", "http://oops.com"
    """

    # domain regex pattern:
    # - starts with alphanumeric or hyphen groups
    # - separated by dots
    # - ends with a TLD of 2-6 characters (com, org, io, co.uk etc.)
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$"
    return bool(re.match(pattern, domain))


# ══════════════════════════════════════════════════════
#  HELPER — resolve domain to IP address
# ══════════════════════════════════════════════════════

def resolve_ip(domain):
    """
    Asks DNS: "what IP address does this domain point to?"
    Returns the IP string, or None if it can't be resolved.

    Example:
        resolve_ip("google.com") → "142.250.80.46"
        resolve_ip("notreal.xyz") → None
    """

    try:
        # socket.gethostbyname does a simple DNS A record lookup
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror:
        # gaierror = "get address info error" = DNS failed
        return None


# ══════════════════════════════════════════════════════
#  HELPER — check if target is reachable over HTTP/HTTPS
# ══════════════════════════════════════════════════════

def probe_http(domain, timeout=8):
    """
    Tries to make a real HTTP request to the target.
    First tries HTTPS, then falls back to HTTP.

    Returns a dict with:
        - base_url:      "https://example.com" (the working URL)
        - status_code:   200, 301, 403, etc.
        - server:        web server header (nginx, Apache, etc.)
        - response_time: how fast it responded in seconds
        - title:         page title from <title> tag
        - redirects_to:  final URL if it redirected somewhere
    """

    result = {
        "base_url":      None,
        "status_code":   None,
        "server":        None,
        "response_time": None,
        "title":         None,
        "redirects_to":  None,
        "https":         False,
    }

    # try HTTPS first, then HTTP
    for scheme in ["https", "http"]:
        url = f"{scheme}://{domain}"
        try:
            start = time.time()

            response = requests.get(
                url,
                timeout=timeout,
                verify=False,           # don't fail on bad SSL certs
                allow_redirects=True,   # follow redirects automatically
                headers={
                    "User-Agent": (
                        "Mozilla/5.0 (X11; Linux x86_64) "
                        "AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36"
                    )
                }
            )

            elapsed = round(time.time() - start, 2)

            # extract page title using simple string search
            title = None
            if "<title>" in response.text.lower():
                try:
                    start_idx = response.text.lower().index("<title>") + 7
                    end_idx   = response.text.lower().index("</title>")
                    title     = response.text[start_idx:end_idx].strip()[:80]
                except Exception:
                    title = None

            result.update({
                "base_url":      f"{scheme}://{domain}",
                "status_code":   response.status_code,
                "server":        response.headers.get("Server", "unknown"),
                "response_time": elapsed,
                "title":         title,
                "redirects_to":  str(response.url) if str(response.url) != url else None,
                "https":         scheme == "https",
            })

            # if we got a response (even 404/403), it's reachable — stop here
            return result

        except requests.exceptions.SSLError:
            # SSL error on HTTPS — try HTTP next
            continue

        except requests.exceptions.ConnectionError:
            # can't connect at all — try next scheme
            continue

        except requests.exceptions.Timeout:
            # took too long — try next scheme
            result["status_code"] = "TIMEOUT"
            continue

        except Exception:
            continue

    # if both schemes failed, return the empty result
    return result


# ══════════════════════════════════════════════════════
#  HELPER — basic network info (reverse DNS, hostname)
# ══════════════════════════════════════════════════════

def get_reverse_dns(ip):
    """
    Reverse DNS lookup: IP → hostname.
    Example: "8.8.8.8" → "dns.google"
    Returns None if no reverse DNS record exists.
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except Exception:
        return None


# ══════════════════════════════════════════════════════
#  MAIN FUNCTION — called by reconx.py
# ══════════════════════════════════════════════════════

def validate_target(raw_target, config):
    """
    Main entry point for this module.
    Called from reconx.py as: validate_target(config["target"], config)

    Takes the raw target string and config dict.
    Returns a dict with everything reconx.py needs to know about the target.

    The returned dict gets merged into the global `results` dict
    so every later module can access this info.
    """

    # ── step 1: clean up the target string ────────────────────────────────
    domain = normalize_target(raw_target)

    # ── step 2: figure out if it's an IP or domain ────────────────────────
    target_type = detect_target_type(domain)

    # ── step 3: validate the format ───────────────────────────────────────
    if target_type == "domain":
        if not is_valid_domain_format(domain):
            # format looks wrong — return is_valid=False so reconx.py exits
            return {
                "is_valid":    False,
                "domain":      domain,
                "target_type": target_type,
                "error":       f"'{domain}' doesn't look like a valid domain",
            }

    # ── step 4: resolve domain → IP ───────────────────────────────────────
    if target_type == "domain":
        ip = resolve_ip(domain)
        if not ip:
            return {
                "is_valid":    False,
                "domain":      domain,
                "target_type": target_type,
                "error":       f"Could not resolve '{domain}' — DNS lookup failed",
            }
    else:
        # target is already an IP
        ip = domain

    # ── step 5: reverse DNS lookup ────────────────────────────────────────
    rdns = get_reverse_dns(ip)

    # ── step 6: probe HTTP/HTTPS ──────────────────────────────────────────
    timeout = config.get("timeout", 8)
    http_info = probe_http(domain, timeout=timeout)

    # if neither HTTP nor HTTPS responded, target is unreachable
    if not http_info["base_url"]:
        return {
            "is_valid":    False,
            "domain":      domain,
            "ip":          ip,
            "target_type": target_type,
            "error":       f"'{domain}' resolved to {ip} but is not reachable over HTTP/HTTPS",
        }

    # ── step 7: build and return the full validation result ───────────────
    return {
        # is_valid = True tells reconx.py to continue the scan
        "is_valid":      True,

        # core target info used by all other modules
        "domain":        domain,
        "ip":            ip,
        "target_type":   target_type,   # "domain" or "ip"
        "base_url":      http_info["base_url"],   # "https://example.com"

        # HTTP probe results
        "status_code":   http_info["status_code"],
        "server":        http_info["server"],
        "response_time": http_info["response_time"],
        "page_title":    http_info["title"],
        "redirects_to":  http_info["redirects_to"],
        "https":         http_info["https"],

        # network info
        "reverse_dns":   rdns,
    }