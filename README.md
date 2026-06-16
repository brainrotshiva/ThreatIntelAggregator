# 🔍 Threat Intel Aggregator

> Multi-source threat intelligence tool for SOC analysts and security researchers.  
> Queries **VirusTotal**, **AbuseIPDB**, **Shodan**, and **AlienVault OTX** to produce a unified threat report for any IP or domain.

**Author:** Badam Shiva Sai | [GitHub](https://github.com/Brainrotshiva) | [LinkedIn](https://linkedin.com/in/shiva-sai-badam)

---

## 📸 Demo

```
╭──────────────────────────────────────────────────╮
│ Threat Intel Aggregator v1.0                     │
│ VirusTotal • AbuseIPDB • Shodan • AlienVault OTX │
│ By Badam Shiva Sai | github.com/Brainrotshiva    │
╰──────────────────────────────────────────────────╯

Target: 45.33.32.156
Scan Time: 2026-06-15 10:22:04
Threat Score: 62/100 — MEDIUM THREAT

                  VirusTotal
  Metric              Value
 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Malicious Engines   8
  Suspicious          2
  Harmless            62
  Total Engines       72

                  AbuseIPDB
  Metric              Value
 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Abuse Confidence    61%
  Total Reports       142
  Country             US
  ISP                 Linode LLC
  Last Reported       2026-06-14T08:11:00+00:00
```

---

## ⚙️ Features

- **Multi-source correlation** — queries 4 threat intel platforms in one run
- **Composite threat score** — 0–100 score calculated from all sources combined
- **Color-coded terminal output** — green (clean), yellow (low), orange (medium), red (high)
- **Graceful degradation** — skips sources with no API key, runs on whatever keys you have
- **JSON report export** — saves full scan results per target for documentation
- **Supports IPs and domains** — auto-detects input type and queries the right endpoints

---

## 🧰 Tech Stack

- Python 3
- [Requests](https://pypi.org/project/requests/) — API calls
- [Rich](https://github.com/Textualize/rich) — terminal formatting
- VirusTotal API v3
- AbuseIPDB API v2
- Shodan REST API
- AlienVault OTX API v1

---

## 🚀 Installation

**Clone the repo:**
```bash
git clone https://github.com/Brainrotshiva/ThreatIntelAggregator
cd ThreatIntelAggregator
```

**Install dependencies (Kali Linux / Debian):**
```bash
sudo apt install python3-requests -y
pip install rich --break-system-packages
```

**Or via pip:**
```bash
pip install requests rich --break-system-packages
```

---

## 🔑 API Keys Setup

All four APIs are **free to sign up**. Get your keys here:

| Source | Sign Up | Free Tier |
|--------|---------|-----------|
| VirusTotal | [virustotal.com](https://www.virustotal.com/gui/sign-in) | 4 requests/min |
| AbuseIPDB | [abuseipdb.com](https://www.abuseipdb.com/register) | 1000 checks/day |
| Shodan | [account.shodan.io](https://account.shodan.io) | 1 query/sec |
| AlienVault OTX | [otx.alienvault.com](https://otx.alienvault.com) | Unlimited |

**Option 1 — Edit the script directly:**

Open `threat_intel.py` and replace the placeholders in the `API_KEYS` section:

```python
API_KEYS = {
    "virustotal": "YOUR_VT_KEY_HERE",
    "abuseipdb":  "YOUR_ABUSEIPDB_KEY_HERE",
    "shodan":     "YOUR_SHODAN_KEY_HERE",
    "otx":        "YOUR_OTX_KEY_HERE",
}
```

**Option 2 — Environment variables (recommended):**

```bash
export VT_API_KEY="your_key_here"
export ABUSE_API_KEY="your_key_here"
export SHODAN_API_KEY="your_key_here"
export OTX_API_KEY="your_key_here"
```

> The tool automatically skips any source with no key configured — you can start with just one key and add the rest later.

---

## 🖥️ Usage

**Interactive mode:**
```bash
python3 threat_intel.py
```

**Pass target directly:**
```bash
python3 threat_intel.py 8.8.8.8
python3 threat_intel.py malicious-domain.com
```

**Save JSON report:**

At the end of each scan, you'll be prompted:
```
Save report to JSON? (y/n): y
✔ Report saved: report_8_8_8_8_20260615_102204.json
```

---

## 📊 Threat Score Logic

The composite score (0–100) is calculated from all available sources:

| Source | Weight | Basis |
|--------|--------|-------|
| VirusTotal | 40 pts | % of engines flagging as malicious |
| AbuseIPDB | 40 pts | Abuse confidence score |
| AlienVault OTX | 20 pts | Number of threat pulses (capped at 10) |

| Score Range | Label |
|-------------|-------|
| 0 | Clean / Unknown |
| 1–39 | Low Threat |
| 40–69 | Medium Threat |
| 70–100 | High Threat |

---

## 📁 Output Example (JSON)

```json
{
  "target": "45.33.32.156",
  "scan_time": "2026-06-15T10:22:04",
  "threat_score": 62,
  "threat_label": "MEDIUM THREAT",
  "virustotal": {
    "status": "ok",
    "malicious": 8,
    "suspicious": 2,
    "harmless": 62,
    "total": 72
  },
  "abuseipdb": {
    "status": "ok",
    "abuse_score": 61,
    "country": "US",
    "isp": "Linode LLC",
    "total_reports": 142
  },
  "shodan": {
    "status": "ok",
    "open_ports": [22, 80, 443],
    "vulns": ["CVE-2021-44228"],
    "org": "Linode"
  },
  "otx": {
    "status": "ok",
    "pulse_count": 5,
    "reputation": -1
  }
}
```

---

## 🛡️ Use Cases

- **SOC Analysts** — quick IOC triage during incident investigation
- **Threat Hunters** — correlate IPs and domains across multiple intel feeds
- **Penetration Testers** — passive recon on target infrastructure
- **Security Students** — hands-on threat intelligence workflow practice

---

## ⚠️ Disclaimer

This tool is intended for **educational and authorized security research purposes only**.  
Do not use against systems or targets without explicit permission.  
The author is not responsible for any misuse of this tool.

---

## 📜 License

MIT License — free to use, modify, and distribute with attribution.

---

## 🔗 Related Projects

- [GitSecScan](https://github.com/Brainrotshiva/GitSecScan) — GitHub Secret Leakage Scanner
- [MNet v2.0](https://github.com/Brainrotshiva/Mnet) — Advanced Network Scanner
