<div align="center">

```text
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝

          Automated Reconnaissance Framework
              Tanya Singh · v1.0 · 2026
```

</div>

---

# Overview

ReconX is an automated reconnaissance framework that collects, validates, and correlates publicly accessible information about a target before manual security testing begins.

The project focuses on delivering accurate, evidence-based reconnaissance with minimal false positives, helping security professionals identify the most relevant areas for manual testing.

---

# Installation

```bash
git clone https://github.com/Tanya0xCyber/ReconX.git

cd ReconX

pip3 install -r requirements.txt
```

---

# Usage

```bash
# Default scan
python3 reconx.py -t target.com

# Increase threads
python3 reconx.py -t target.com --threads 30

# Skip port scanning
python3 reconx.py -t target.com --no-ports

# Save JSON report
python3 reconx.py -t target.com --output json
```

---

# Detection Capabilities

| Category       | Detection                                                   |
| -------------- | ----------------------------------------------------------- |
| Target         | IP, HTTPS, Server, CDN, WAF                                 |
| DNS            | WHOIS, Nameservers, SPF, DMARC                              |
| Attack Surface | Live Subdomains, Open Ports, APIs, Login Pages, Admin Pages |
| Discovery      | Sensitive Endpoints, Exposed Files, Email Addresses         |
| Fingerprinting | Web Server, Framework, CMS, Frontend, Hosting               |
| Security       | HTTP Security Headers, Verified Misconfigurations           |
| Analysis       | Risk Score, Confidence, Evidence, Testing Recommendations   |

---

# Report Structure

Every scan produces a structured report containing:

* Executive Summary
* Target Information
* Attack Surface
* Technology Fingerprinting
* Findings
* Recommended Next Tests

Reports are automatically saved inside:

```text
reports/
```

---

# Why ReconX?

ReconX does **not** attempt to exploit vulnerabilities.

Its objective is to answer questions such as:

* What is exposed?
* What technologies are running?
* Which findings are verified?
* What should a pentester test next?
* Where is the most promising attack surface?

---

# Future Improvements

* Better framework detection
* Better WAF fingerprinting
* More endpoint validation
* Improved technology confidence
* Better evidence collection
* Faster enumeration

---

# Legal

Use ReconX only against systems you own or have explicit authorization to test.

Unauthorized security testing may violate applicable laws and program policies.

---

*"Know your target before you test your target."*
