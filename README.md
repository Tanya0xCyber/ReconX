<div align="center">

```
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝

         automated recon pipeline · python · kali
             Tanya Singh · 2026
```

</div>

---

##  What is ReconX?

### ReconX is a 5-stage automated recon pipeline for pentesters and bug bounty hunters. One command — full recon from passive info gathering to a final report. 

---

##  Installation

```bash
git clone https://github.com/Tanya0xCyber/ReconX.git
cd reconx
pip3 install -r requirements.txt
```

---

##  Usage

```bash
python3 reconx.py -t target.com                   # full run
python3 reconx.py -t target.com --only passive    # passive only
python3 reconx.py -t target.com --no-ports        # skip ports
python3 reconx.py -t target.com --output all      # all formats
python3 reconx.py -t target.com --threads 30      # more threads
python3 reconx.py -t target.com --shodan API_KEY  # + CVE data
```

---

##  Pipeline

| Stage | What it does |
|---|---|
| 0 · Validation | domain check · IP resolve · reachability |
| 1 · Passive | WHOIS · DNS · crt.sh · Geo/ASN · Shodan |
| 2 · Active | subdomain BF · JS secrets · email harvest |
| 3 · Services | port scan · banner grab · HTTP probe |
| 4 · Analysis | WAF · tech stack · vuln hints · chains |

---

##  Chain Analyzer

Automatically detects dangerous finding combinations:

| Chain | Impact |
|---|---|
| JS Secret + API Endpoint | → Account Takeover |
| Subdomain Takeover + Cookies | → Session Hijack |
| No SPF + No DMARC | → Email Spoofing |
| Docker Port 2375 Open | → Full Server RCE |
| Database Port Exposed | → Direct Data Dump |
| WordPress + Admin Panel | → Site Takeover |

---

##  Reports

```bash
--output html   # dark dashboard — opens in browser
--output json   # raw data
--output md     # for HackerOne / Bugcrowd
--output all    # all three
```

Saved to `./reports/` after every scan.

---

##  Legal

Only use on targets you have written permission to test.
Unauthorized scanning is illegal. Use responsibly.

---

*Know your target before they know you.*
```
