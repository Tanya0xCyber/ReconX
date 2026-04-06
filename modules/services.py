# modules/services.py
# ─────────────────────────────────────────────────────
# SERVICE DISCOVERY — we scan for open ports and services.
# Three jobs:
#   1. Port scanning    → find open TCP ports
#   2. Banner grabbing  → what software is running on each port?
#   3. HTTP probing     → which ports have web services?
#
# This stage runs AFTER active recon so we have a full
# list of subdomains to scan, not just the main domain.
# ─────────────────────────────────────────────────────

import socket           # low-level TCP connections
import time             # timeouts + delays
import re               # regex for banner parsing
import ssl              # SSL/TLS connections for banner grab
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
requests.packages.urllib3.disable_warnings()


# ══════════════════════════════════════════════════════
#  PORT LIST
# ══════════════════════════════════════════════════════

# top ports — most common ports seen in real pentests
# ordered by how commonly they appear in the wild
TOP_PORTS = [
    # web
    80, 443, 8080, 8443, 8000, 8888, 8008, 3000, 4000, 5000,
    9000, 9090, 9443, 7000, 7001, 7443,
    # databases
    3306,   # MySQL
    5432,   # PostgreSQL
    27017,  # MongoDB
    6379,   # Redis
    11211,  # Memcached
    1433,   # MSSQL
    1521,   # Oracle
    5984,   # CouchDB
    9200,   # Elasticsearch
    9300,   # Elasticsearch cluster
    # remote access
    22,     # SSH
    23,     # Telnet
    3389,   # RDP (Windows Remote Desktop)
    5900,   # VNC
    5901,
    # mail
    25,     # SMTP
    587,    # SMTP submission
    465,    # SMTP SSL
    110,    # POP3
    995,    # POP3 SSL
    143,    # IMAP
    993,    # IMAP SSL
    # file transfer
    21,     # FTP
    990,    # FTPS
    # infrastructure
    53,     # DNS
    161,    # SNMP
    389,    # LDAP
    636,    # LDAPS
    2181,   # Zookeeper
    2375,   # Docker API (unprotected!)
    2376,   # Docker API SSL
    4243,   # Docker API alt
    # monitoring / devops
    4848,   # GlassFish admin
    8161,   # ActiveMQ admin
    61616,  # ActiveMQ
    9092,   # Kafka
    15672,  # RabbitMQ management
    5672,   # RabbitMQ
    # proxy / load balancer
    3128,   # Squid proxy
    8118,   # Privoxy
    1080,   # SOCKS proxy
    # misc
    6443,   # Kubernetes API
    10250,  # Kubernetes kubelet
    2379,   # etcd (Kubernetes)
    8500,   # Consul
    8600,   # Consul DNS
    4369,   # Erlang port mapper
    11300,  # Beanstalkd
]

# ports that are interesting from a security perspective
# if found open — flag them for analysis.py
INTERESTING_PORTS = {
    22:    "SSH",
    23:    "Telnet — unencrypted remote access",
    2375:  "Docker API — often unauthenticated!",
    2376:  "Docker API SSL",
    3389:  "RDP — Windows Remote Desktop",
    5900:  "VNC — remote desktop",
    6379:  "Redis — often no auth by default",
    9200:  "Elasticsearch — often no auth",
    27017: "MongoDB — often no auth",
    11211: "Memcached — often no auth",
    5984:  "CouchDB",
    9092:  "Kafka",
    2181:  "Zookeeper",
    4848:  "GlassFish admin panel",
    8161:  "ActiveMQ admin panel",
    15672: "RabbitMQ management panel",
    6443:  "Kubernetes API",
    10250: "Kubernetes kubelet API",
    2379:  "etcd — Kubernetes secrets store",
}

# service name map — port number → common service name
SERVICE_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    161: "SNMP", 389: "LDAP", 443: "HTTPS", 465: "SMTPS",
    587: "SMTP", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 2375: "Docker",
    2376: "Docker-SSL", 3000: "Web/Node", 3306: "MySQL",
    3389: "RDP", 3128: "Squid", 4848: "GlassFish",
    5432: "PostgreSQL", 5672: "RabbitMQ", 5900: "VNC",
    5984: "CouchDB", 6379: "Redis", 6443: "K8s-API",
    7001: "WebLogic", 8000: "Web", 8008: "Web",
    8080: "HTTP-Alt", 8161: "ActiveMQ", 8443: "HTTPS-Alt",
    8500: "Consul", 8888: "Web", 9000: "Web/PHP",
    9090: "Web/Prometheus", 9200: "Elasticsearch",
    9300: "Elasticsearch", 9443: "Web-SSL", 10250: "K8s-Kubelet",
    11211: "Memcached", 15672: "RabbitMQ-Mgmt",
    27017: "MongoDB", 61616: "ActiveMQ-MQ",
}


# ══════════════════════════════════════════════════════
#  SECTION 1 — PORT SCANNER
# ══════════════════════════════════════════════════════

def scan_port(host, port, timeout=2):
    """
    Tries to open a TCP connection to host:port.
    If connection succeeds → port is open.
    If connection refused or times out → port is closed/filtered.

    This is a "TCP connect scan" — the simplest and most reliable
    port scanning method. We complete the full TCP handshake.

    Returns dict if open, None if closed.
    """

    try:
        # create a new TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # set how long to wait for connection
        sock.settimeout(timeout)

        # try to connect — returns 0 if successful
        result = sock.connect_ex((host, port))

        sock.close()

        if result == 0:
            # connection succeeded → port is open
            return {
                "port":    port,
                "state":   "open",
                "service": SERVICE_NAMES.get(port, "unknown"),
            }
        return None

    except socket.gaierror:
        # hostname couldn't be resolved
        return None

    except Exception:
        return None


def run_port_scan(host, ports, config):
    """
    Scans a list of ports on a single host.
    Runs all port checks in parallel threads for speed.

    Returns list of open port dicts.
    """

    threads = config.get("threads", 25)
    timeout = min(config.get("timeout", 3), 1.5)  # cap at 1.5s for port scan
    open_ports = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(scan_port, host, port, timeout): port
            for port in ports
        }

        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    # sort by port number for clean output
    open_ports.sort(key=lambda x: x["port"])

    return open_ports


# ══════════════════════════════════════════════════════
#  SECTION 2 — BANNER GRABBING
# ══════════════════════════════════════════════════════

def grab_banner(host, port, timeout=4):
    """
    Connects to an open port and reads the first bytes the
    service sends back — this is the "banner".

    Many services announce themselves immediately:
    - SSH:   "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
    - FTP:   "220 vsFTPd 3.0.3"
    - SMTP:  "220 mail.example.com ESMTP Postfix"
    - MySQL: "5.7.38-0ubuntu0.20.04.1"

    This tells us:
    - Exact software version → look up CVEs
    - OS hints (Ubuntu, Windows, etc.)
    - Configuration details

    For HTTPS/SSL ports we do a TLS handshake and read
    the certificate for more info.
    """

    banner_info = {
        "port":        port,
        "banner":      None,
        "version":     None,
        "ssl":         False,
        "ssl_subject": None,
        "ssl_issuer":  None,
        "ssl_expiry":  None,
        "error":       None,
    }

    # ── SSL ports — grab certificate info ─────────────────────────────────
    ssl_ports = [443, 8443, 9443, 465, 993, 995, 636, 2376, 6443]

    if port in ssl_ports:
        try:
            # create SSL context that accepts any certificate
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()

                    # extract certificate subject (who is it for?)
                    subject = dict(
                        x[0] for x in cert.get("subject", [])
                    ) if cert else {}

                    # extract issuer (who signed it?)
                    issuer = dict(
                        x[0] for x in cert.get("issuer", [])
                    ) if cert else {}

                    banner_info.update({
                        "ssl":         True,
                        "ssl_subject": subject.get("commonName", ""),
                        "ssl_issuer":  issuer.get("organizationName", ""),
                        "ssl_expiry":  cert.get("notAfter", "") if cert else "",
                    })

                    # try to read banner after SSL handshake
                    try:
                        ssock.settimeout(2)
                        data = ssock.recv(1024)
                        if data:
                            banner_info["banner"] = data.decode(
                                "utf-8", errors="replace"
                            ).strip()[:300]
                    except Exception:
                        pass

            return banner_info

        except Exception as e:
            banner_info["error"] = str(e)[:100]
            return banner_info

    # ── regular TCP banner grab ────────────────────────────────────────────
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # some services (HTTP, SMTP) need a probe to respond
        # send a generic HTTP request — harmless
        if port in [80, 8080, 8000, 8008, 8888]:
            sock.send(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
        else:
            # for other services just wait for their banner
            # most services send something immediately on connect
            pass

        sock.settimeout(3)
        data = sock.recv(1024)
        sock.close()

        if data:
            banner = data.decode("utf-8", errors="replace").strip()[:300]
            banner_info["banner"] = banner

            # try to extract version from banner
            # common patterns: "OpenSSH_8.9", "vsFTPd 3.0.3", "Apache/2.4.41"
            version_match = re.search(
                r"([\w\-]+)[/\s_]([\d]+\.[\d]+[\.\d]*)",
                banner
            )
            if version_match:
                banner_info["version"] = (
                    f"{version_match.group(1)} {version_match.group(2)}"
                )

    except socket.timeout:
        banner_info["error"] = "timeout"

    except Exception as e:
        banner_info["error"] = str(e)[:100]

    return banner_info


def run_banner_grab(host, open_ports, config):
    """
    Grabs banners for all open ports on a host.
    Runs in parallel threads.
    """

    timeout = config.get("timeout", 4)
    threads = min(config.get("threads", 10), 10)  # cap at 10
    banners = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(grab_banner, host, p["port"], timeout): p
            for p in open_ports
        }

        for future in as_completed(futures):
            result = future.result()
            if result:
                banners.append(result)

    banners.sort(key=lambda x: x["port"])
    return banners


# ══════════════════════════════════════════════════════
#  SECTION 3 — HTTP SERVICE PROBING
# ══════════════════════════════════════════════════════

# ports that commonly run HTTP/HTTPS services
HTTP_PORTS = [
    80, 443, 8080, 8443, 8000, 8888, 8008,
    3000, 4000, 5000, 9000, 9090, 9443,
    7000, 7001, 4848, 8161, 15672, 8500,
]

def probe_http_service(host, port, config):
    """
    Probes a specific host:port for HTTP/HTTPS service.

    Collects:
    - Status code
    - Page title
    - Server header
    - Security headers (or lack of them)
    - Tech stack hints
    - Interesting paths (/admin, /api, etc.)
    - Whether it's a login page
    - Whether it's an admin panel
    """

    result = {
        "host":            host,
        "port":            port,
        "url":             None,
        "status":          None,
        "title":           None,
        "server":          None,
        "tech_hints":      [],
        "security_headers": {},
        "missing_headers": [],
        "is_login":        False,
        "is_admin":        False,
        "interesting":     False,
        "error":           None,
    }

    # try HTTPS first for common SSL ports, HTTP for others
    schemes = ["https", "http"] if port in [443, 8443, 9443] else ["http", "https"]

    for scheme in schemes:
        url = f"{scheme}://{host}:{port}"

        # skip redundant URL if it's the default port
        if (scheme == "http"  and port == 80)  : url = f"http://{host}"
        if (scheme == "https" and port == 443) : url = f"https://{host}"

        try:
            r = requests.get(
                url,
                timeout=config.get("timeout", 6),
                verify=False,
                allow_redirects=True,
                headers={
                    "User-Agent": (
                        "Mozilla/5.0 (X11; Linux x86_64) "
                        "AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36"
                    )
                }
            )

            result["url"]    = url
            result["status"] = r.status_code

            # ── page title ─────────────────────────────────────────────────
            title_match = re.search(
                r"<title[^>]*>(.*?)</title>",
                r.text, re.I | re.S
            )
            if title_match:
                result["title"] = title_match.group(1).strip()[:80]

            # ── server + tech headers ──────────────────────────────────────
            result["server"] = r.headers.get("Server", "")

            tech = []
            for h in ["Server", "X-Powered-By", "X-Generator",
                      "X-AspNet-Version", "X-Runtime"]:
                v = r.headers.get(h, "")
                if v:
                    tech.append(f"{h}: {v}")
            result["tech_hints"] = tech

            # ── security headers check ─────────────────────────────────────
            # check which security headers are present or missing
            security_headers = {
                "Strict-Transport-Security": "HSTS",
                "Content-Security-Policy":   "CSP",
                "X-Frame-Options":           "Clickjacking protection",
                "X-Content-Type-Options":    "MIME sniffing protection",
                "Referrer-Policy":           "Referrer policy",
            }

            present  = {}
            missing  = []

            for header, desc in security_headers.items():
                val = r.headers.get(header, "")
                if val:
                    present[header] = val
                else:
                    missing.append(header)

            result["security_headers"] = present
            result["missing_headers"]  = missing

            # ── detect login pages ─────────────────────────────────────────
            body_lower = r.text.lower()
            login_keywords = [
                "password", "login", "sign in", "signin",
                "username", "email", "log in", "authenticate",
            ]
            result["is_login"] = any(k in body_lower for k in login_keywords)

            # ── detect admin panels ────────────────────────────────────────
            admin_keywords = [
                "admin", "administrator", "dashboard", "control panel",
                "management", "backend", "cms", "phpmyadmin",
                "grafana", "kibana", "jenkins", "gitlab",
            ]
            title_lower = (result["title"] or "").lower()
            result["is_admin"] = any(
                k in body_lower[:2000] or k in title_lower
                for k in admin_keywords
            )

            # ── flag interesting ports ─────────────────────────────────────
            # ports that shouldn't normally be internet-facing
            result["interesting"] = port in INTERESTING_PORTS

            return result

        except requests.exceptions.SSLError:
            continue   # try next scheme

        except requests.exceptions.ConnectionError:
            continue

        except requests.exceptions.Timeout:
            result["error"] = "timeout"
            return result

        except Exception as e:
            result["error"] = str(e)[:100]
            return result

    result["error"] = "no response on http or https"
    return result


def run_http_probe(hosts_with_ports, config):
    """
    Takes a list of (host, open_ports) pairs and probes
    all HTTP-like ports for web services.

    Returns list of HTTP service findings.
    """

    threads = min(config.get("threads", 15), 15)
    tasks   = []

    # build task list: (host, port) for all HTTP-likely open ports
    for host, open_ports in hosts_with_ports:
        for port_info in open_ports:
            port = port_info["port"]
            # probe if it's a known HTTP port OR any open port
            # (sometimes web services run on unusual ports)
            if port in HTTP_PORTS or port_info.get("service") in ["HTTP", "HTTPS"]:
                tasks.append((host, port))

    http_services = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(probe_http_service, host, port, config): (host, port)
            for host, port in tasks
        }

        for future in as_completed(futures):
            result = future.result()
            if result and result.get("status"):
                http_services.append(result)

    return http_services


# ══════════════════════════════════════════════════════
#  MAIN FUNCTION — called by reconx.py
# ══════════════════════════════════════════════════════

def run_service_discovery(targets, config):
    """
    Main entry point — reconx.py calls this as:
        run_service_discovery(targets_to_scan, config)

    targets = list of hostnames/IPs to scan
    (built from main domain + all subdomains found earlier)

    Flow:
    1. Port scan every target
    2. Banner grab all open ports
    3. HTTP probe all web-like ports
    4. Flag interesting/dangerous open ports
    """

    results = {
        "hosts_scanned":  0,
        "open_ports":     [],    # flat list of all open ports
        "banners":        [],    # banner info per port
        "http_services":  [],    # HTTP service details
        "interesting":    [],    # dangerous open ports
        "per_host":       {},    # detailed results per host
    }

    # limit targets to avoid scanning too many hosts
    # in a real pentest you'd scan all, but for a portfolio
    # tool we cap it to keep it fast
    max_targets = 10
    targets     = list(set(targets))[:max_targets]

    results["hosts_scanned"] = len(targets)

    all_host_ports = []   # used for HTTP probing step

    # ── scan each target ───────────────────────────────────────────────────
    for host in targets:

        if config.get("verbose"):
            print(f"    scanning {host}...")

        host_result = {
            "host":       host,
            "open_ports": [],
            "banners":    [],
        }

        # ── step 1: port scan ──────────────────────────────────────────────
        open_ports = run_port_scan(host, TOP_PORTS, config)
        host_result["open_ports"] = open_ports

        # add to flat list for summary
        for p in open_ports:
            results["open_ports"].append({
                "host":    host,
                "port":    p["port"],
                "service": p["service"],
            })

            # flag interesting ports
            if p["port"] in INTERESTING_PORTS:
                results["interesting"].append({
                    "host":    host,
                    "port":    p["port"],
                    "service": p["service"],
                    "note":    INTERESTING_PORTS[p["port"]],
                })

        # ── step 2: banner grabbing ────────────────────────────────────────
        if open_ports:
            banners = run_banner_grab(host, open_ports, config)
            host_result["banners"] = banners

            for b in banners:
                results["banners"].append({
                    "host":    host,
                    **b        # spread all banner fields
                })

        # store per-host results
        results["per_host"][host] = host_result

        # collect (host, open_ports) for HTTP probing step
        if open_ports:
            all_host_ports.append((host, open_ports))

        # small delay between hosts to be polite
        time.sleep(config.get("rate_limit", 0.1))

    # ── step 3: HTTP probing ───────────────────────────────────────────────
    # runs after all port scans are done
    if all_host_ports:
        if config.get("verbose"):
            print("    probing HTTP services...")

        http_services = run_http_probe(all_host_ports, config)
        results["http_services"] = http_services

    return results
