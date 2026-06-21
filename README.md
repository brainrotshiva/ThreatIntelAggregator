# 🛡️ Threat Intel Aggregator v1.0

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/Made%20in-India-orange?style=flat-square"/>
  <img src="https://img.shields.io/badge/For-Ethical%20Use%20Only-red?style=flat-square"/>
</p>

> Instantly analyze IPs, domains, and file hashes for threats — geolocation, open ports, CVEs, TOR detection, DNS blacklists, and more. Works out of the box with zero API keys. Add optional keys for deeper intelligence.

---

## ⚡ Quick Start

```bash
git clone https://github.com/Brainrotshiva/threat-intel-aggregator
cd threat-intel-aggregator

# Install globally (run from anywhere)
sudo cp threatintel.py /usr/local/bin/threatintel
sudo chmod +x /usr/local/bin/threatintel
```

Now run from anywhere:

```bash
threatintel 8.8.8.8
threatintel google.com
threatintel --hash abc123def456abc123def456abc123def456abc123def456
```

---

## 🔍 What It Analyzes

### Without API Keys (Zero Setup)
| Source | Data |
|---|---|
| ip-api.com | Country, city, ISP, ASN, coordinates |
| Shodan InternetDB | Open ports, CVEs, hostnames, tags |
| TorProject | TOR exit node detection |
| DNS Blacklists | Spamhaus, SpamCop, SORBS, Barracuda |

### With Optional API Keys (Deeper Intel)
| Source | Data | Get Key |
|---|---|---|
| VirusTotal | Malware scan across 70+ engines | virustotal.com |
| AbuseIPDB | Abuse confidence score (0–100) | abuseipdb.com |
| AlienVault OTX | Threat pulse count | otx.alienvault.com |

All keys are **free tier** — no credit card needed.

### How to Get & Add API Keys (One Time Only)

Run the setup wizard once — keys are saved to `~/.threatintel.conf` and auto-loaded every scan:

```bash
threatintel --setup
```

It will ask you for each key one by one:

```
  VirusTotal  → virustotal.com → Profile → API Key
  VT Key: paste_here

  AbuseIPDB   → abuseipdb.com → Account → API
  AbuseIPDB Key: paste_here

  AlienVault OTX → otx.alienvault.com → Settings → API Key
  OTX Key: paste_here

  ✓ Keys saved to ~/.threatintel.conf
  Now just run: threatintel 8.8.8.8
```

From then on, just run `threatintel 8.8.8.8` — keys load automatically. No flags needed ever again.

---

## 🚀 Usage

```bash
# Scan an IP
threatintel 8.8.8.8

# Scan a domain
threatintel google.com

# Scan a file hash (MD5 / SHA1 / SHA256)
threatintel --hash abc123def456abc123def456abc123def456abc123def456

# With optional API keys
threatintel 1.2.3.4 --vt-key YOUR_KEY --abuse-key YOUR_KEY --otx-key YOUR_KEY

# Save HTML report
threatintel 1.2.3.4 --output report.html

# Export as JSON
threatintel 1.2.3.4 --json results.json

# Skip HTML report
threatintel 1.2.3.4 --no-report
```

---

## 📊 Sample Output

```
╔══════════════════════════════════════════════════════╗
║  🛡️  Threat Intel Aggregator v1.0                    ║
║  by Brainrotshiva — github.com/Brainrotshiva          ║
╚══════════════════════════════════════════════════════╝

  ✓ Geolocation
  ✓ Shodan InternetDB
  ✓ TOR check
  ✓ DNS blacklists

──────────── TARGET ────────────
  Target                 1.2.3.4
  Type                   IP
  Scan Time              2025-06-11 14:30:00

────────── THREAT ASSESSMENT ──────────
  Threat Score           75/100  ████████░░
  Threat Level           CRITICAL

────────── GEOLOCATION ──────────
  IP                     1.2.3.4
  Country                Russia (RU)
  City                   Moscow
  ISP                    AS12345 SomeISP
  ASN                    AS12345

────────── FLAGS ──────────
  ● TOR Exit Node
  ● Datacenter / Hosting

────────── OPEN PORTS ──────────
  22  80  443  3389  8080

────────── VULNERABILITIES ──────────
  ● CVE-2021-44228
  ● CVE-2022-26134

────────── REPUTATION ──────────
  VirusTotal             42/72 engines flagged
  AbuseIPDB Score        98/100
  OTX Pulses             14
  DNS Blacklists         zen.spamhaus.org, bl.spamcop.net
```

---

## 🏗️ Architecture

```
threatintel.py
├── Free Sources (no key)
│   ├── fetch_ipapi()          # Geolocation, proxy, datacenter detection
│   ├── fetch_shodan()         # Open ports, CVEs, hostnames
│   ├── fetch_tor()            # TOR exit node check
│   └── fetch_dns_blacklist()  # 4 major DNSBL checks
│
├── Optional Sources (with key)
│   ├── fetch_vt_ip/domain/hash()  # VirusTotal
│   ├── fetch_abuse()              # AbuseIPDB
│   └── fetch_otx()                # AlienVault OTX
│
├── threat_score               # Composite 0–100 score
├── print_report()             # Rich terminal output
└── generate_html()            # Dark-theme HTML report
```

---

## 📁 Output Files

| File | Description |
|---|---|
| `threat_report.html` | Visual HTML report (open in browser) |
| `results.json` | Machine-readable findings (optional) |

---

## 🗺️ Roadmap

- [ ] v1.1 — Bulk scan from file (list of IPs)
- [ ] v1.2 — Slack/webhook alerts
- [ ] v1.3 — Live dashboard (WebSocket)
- [ ] v2.0 — Full web UI

---

## 👤 Author

**Badam Shiva Sai**  
Cybersecurity Researcher | CEH (In Progress)  
📍 Hyderabad, India

- GitHub: [@Brainrotshiva](https://github.com/Brainrotshiva)
- LinkedIn: [Badam Shiva Sai](https://linkedin.com/in/shiva-sai-badam)

---

## 📜 License

MIT License — free to use, modify, and distribute.  
If you find it useful, drop a ⭐

---

*For ethical use only. Built to make threat intelligence accessible to everyone.*
