#!/usr/bin/env python3
"""
Threat Intel Aggregator v1.0
Author: Badam Shiva Sai (Brainrotshiva)
GitHub: https://github.com/Brainrotshiva
"""

import re, sys, json, socket, argparse, urllib.request, urllib.error
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional

class C:
    RED="\033[91m";ORANGE="\033[93m";GREEN="\033[92m";BLUE="\033[94m"
    CYAN="\033[96m";MAGENTA="\033[95m";WHITE="\033[97m";MUTED="\033[90m"
    BOLD="\033[1m";RESET="\033[0m"

def red(t):     return f"{C.RED}{t}{C.RESET}"
def orange(t):  return f"{C.ORANGE}{t}{C.RESET}"
def green(t):   return f"{C.GREEN}{t}{C.RESET}"
def cyan(t):    return f"{C.CYAN}{t}{C.RESET}"
def white(t):   return f"{C.WHITE}{C.BOLD}{t}{C.RESET}"
def muted(t):   return f"{C.MUTED}{t}{C.RESET}"
def bold(t):    return f"{C.BOLD}{t}{C.RESET}"

@dataclass
class IntelResult:
    target: str
    target_type: str
    scan_time: str = ""
    ip: str = ""
    hostname: str = ""
    country: str = ""
    country_code: str = ""
    city: str = ""
    org: str = ""
    asn: str = ""
    isp: str = ""
    latitude: str = ""
    longitude: str = ""
    is_tor: bool = False
    is_proxy: bool = False
    is_datacenter: bool = False
    abuse_score: int = 0
    vt_malicious: int = 0
    vt_total: int = 0
    otx_pulses: int = 0
    shodan_ports: list = field(default_factory=list)
    shodan_vulns: list = field(default_factory=list)
    shodan_tags: list = field(default_factory=list)
    dns_blacklists: list = field(default_factory=list)
    hash_type: str = ""
    hash_malicious: int = 0
    hash_total: int = 0
    hash_name: str = ""
    hash_type_label: str = ""
    sources: dict = field(default_factory=dict)
    errors: list = field(default_factory=list)

    @property
    def threat_score(self):
        s = 0
        if self.is_tor: s += 30
        if self.is_proxy: s += 20
        if self.is_datacenter: s += 10
        s += min(self.abuse_score, 40)
        if self.vt_total > 0: s += int((self.vt_malicious/self.vt_total)*40)
        if self.otx_pulses > 0: s += min(self.otx_pulses*2, 20)
        if self.shodan_vulns: s += min(len(self.shodan_vulns)*5, 20)
        if self.dns_blacklists: s += min(len(self.dns_blacklists)*10, 30)
        if self.hash_total > 0: s += int((self.hash_malicious/self.hash_total)*100)
        return min(s, 100)

    @property
    def threat_level(self):
        s = self.threat_score
        if s >= 70: return "CRITICAL"
        if s >= 40: return "HIGH"
        if s >= 20: return "MEDIUM"
        if s > 0: return "LOW"
        return "CLEAN"

    @property
    def threat_color(self):
        return {
            "CRITICAL": red, "HIGH": orange,
            "MEDIUM": orange, "LOW": green, "CLEAN": green
        }.get(self.threat_level, white)

def http_get(url, headers={}, timeout=10):
    try:
        req = urllib.request.Request(url, headers={"User-Agent":"ThreatIntel/1.0",**headers})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except: return None

def is_ip(t):
    try: socket.inet_aton(t); return True
    except:
        try: socket.inet_pton(socket.AF_INET6,t); return True
        except: return False

def is_hash(t): return bool(re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}",t))
def detect_hash_type(h): return {32:"MD5",40:"SHA-1",64:"SHA-256"}.get(len(h),"Unknown")
def resolve_domain(d):
    try: return socket.gethostbyname(d)
    except: return ""

def fetch_ipapi(result):
    d = http_get(f"http://ip-api.com/json/{result.ip}?fields=status,country,countryCode,city,org,as,isp,lat,lon,proxy,hosting,query")
    if not d or d.get("status")!="success": result.errors.append("ip-api.com failed"); return
    result.country=d.get("country",""); result.country_code=d.get("countryCode","")
    result.city=d.get("city",""); result.org=d.get("org",""); result.asn=d.get("as","")
    result.isp=d.get("isp",""); result.latitude=str(d.get("lat","")); result.longitude=str(d.get("lon",""))
    result.is_proxy=d.get("proxy",False); result.is_datacenter=d.get("hosting",False)

def fetch_shodan(result):
    d = http_get(f"https://internetdb.shodan.io/{result.ip}")
    if not d: result.errors.append("Shodan failed"); return
    result.shodan_ports=d.get("ports",[]); result.shodan_vulns=d.get("vulns",[])
    result.shodan_tags=d.get("tags",[]); result.hostname=", ".join(d.get("hostnames",[]))

def fetch_tor(result):
    d = http_get(f"https://check.torproject.org/api/ip/{result.ip}")
    if d: result.is_tor=d.get("IsTor",False)

def fetch_dns_blacklist(result):
    if not result.ip: return
    rev = ".".join(reversed(result.ip.split(".")))
    for bl in ["zen.spamhaus.org","bl.spamcop.net","dnsbl.sorbs.net","b.barracudacentral.org"]:
        try: socket.gethostbyname(f"{rev}.{bl}"); result.dns_blacklists.append(bl)
        except: pass

def fetch_vt_ip(result, key):
    d = http_get(f"https://www.virustotal.com/api/v3/ip_addresses/{result.ip}",{"x-apikey":key})
    if not d: return
    s = d.get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
    result.vt_malicious=s.get("malicious",0); result.vt_total=sum(s.values())

def fetch_vt_domain(result, key):
    d = http_get(f"https://www.virustotal.com/api/v3/domains/{result.target}",{"x-apikey":key})
    if not d: return
    s = d.get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
    result.vt_malicious=s.get("malicious",0); result.vt_total=sum(s.values())

def fetch_vt_hash(result, key):
    d = http_get(f"https://www.virustotal.com/api/v3/files/{result.target}",{"x-apikey":key})
    if not d: return
    attrs=d.get("data",{}).get("attributes",{}); s=attrs.get("last_analysis_stats",{})
    result.hash_malicious=s.get("malicious",0); result.hash_total=sum(s.values())
    result.hash_name=attrs.get("meaningful_name",""); result.hash_type_label=attrs.get("type_description","")

def fetch_abuse(result, key):
    d = http_get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={result.ip}&maxAgeInDays=90",{"Key":key,"Accept":"application/json"})
    if d: result.abuse_score=d.get("data",{}).get("abuseConfidenceScore",0)

def fetch_otx(result, key):
    if result.target_type=="ip": url=f"https://otx.alienvault.com/api/v1/indicators/IPv4/{result.ip}/general"
    elif result.target_type=="hash": url=f"https://otx.alienvault.com/api/v1/indicators/file/{result.target}/general"
    else: url=f"https://otx.alienvault.com/api/v1/indicators/domain/{result.target}/general"
    d = http_get(url,{"X-OTX-API-KEY":key})
    if d: result.otx_pulses=d.get("pulse_info",{}).get("count",0)

def print_banner():
    print(f"""
{cyan('╔══════════════════════════════════════════════════════╗')}
{cyan('║')}  {white('🛡️  Threat Intel Aggregator v1.0')}                     {cyan('║')}
{cyan('║')}  {muted('by Brainrotshiva — github.com/Brainrotshiva')}          {cyan('║')}
{cyan('╚══════════════════════════════════════════════════════╝')}
""")

def row(label, value, color_fn=None):
    if not value and value!=0: return
    val = color_fn(str(value)) if color_fn else str(value)
    print(f"  {muted(label.ljust(22))} {val}")

def divider(title=""):
    w=56
    if title:
        pad=(w-len(title)-2)//2
        print(f"\n{cyan('─'*pad)} {white(title)} {cyan('─'*pad)}")
    else:
        print(cyan("─"*w))

def print_report(result):
    tc = result.threat_color
    divider("TARGET")
    row("Target", result.target, cyan)
    row("Type", result.target_type.upper(), white)
    row("Scan Time", result.scan_time, muted)

    divider("THREAT ASSESSMENT")
    bar = "█"*(result.threat_score//10) + "░"*(10-result.threat_score//10)
    print(f"  {muted('Threat Score'.ljust(22))} {tc(str(result.threat_score)+'/100')}  {tc(bar)}")
    print(f"  {muted('Threat Level'.ljust(22))} {tc(bold(result.threat_level))}")

    if result.target_type in ("ip","domain"):
        divider("GEOLOCATION")
        row("IP", result.ip, cyan)
        row("Hostname", result.hostname, white)
        row("Country", f"{result.country} ({result.country_code})" if result.country else "", white)
        row("City", result.city, white)
        row("ISP / Org", result.isp or result.org, white)
        row("ASN", result.asn, muted)
        if result.latitude: row("Coordinates", f"{result.latitude}, {result.longitude}", muted)

        divider("FLAGS")
        flags=[]
        if result.is_tor: flags.append(red("● TOR Exit Node"))
        if result.is_proxy: flags.append(orange("● Proxy / VPN"))
        if result.is_datacenter: flags.append(orange("● Datacenter / Hosting"))
        [print(f"  {f}") for f in flags] if flags else print(f"  {green('● No flags detected')}")

        if result.shodan_ports:
            divider("OPEN PORTS")
            print("  " + "  ".join([cyan(str(p)) for p in result.shodan_ports]))

        if result.shodan_vulns:
            divider("VULNERABILITIES")
            [print(f"  {red('●')} {red(v)}") for v in result.shodan_vulns]

        divider("REPUTATION")
        if result.vt_total>0:
            vc = red if result.vt_malicious>0 else green
            row("VirusTotal", f"{result.vt_malicious}/{result.vt_total} engines flagged", vc)
        else: row("VirusTotal", "No key — use --vt-key", muted)
        if result.abuse_score>0:
            row("AbuseIPDB Score", f"{result.abuse_score}/100", red if result.abuse_score>50 else orange)
        else: row("AbuseIPDB", "No key — use --abuse-key", muted)
        if result.otx_pulses>0: row("OTX Pulses", str(result.otx_pulses), red)
        else: row("OTX", "No key — use --otx-key", muted)
        if result.dns_blacklists: row("DNS Blacklists", ", ".join(result.dns_blacklists), red)
        else: row("DNS Blacklists", "Clean", green)

    elif result.target_type=="hash":
        divider("HASH INFO")
        row("Hash Type", result.hash_type, cyan)
        row("File Name", result.hash_name, white)
        row("File Type", result.hash_type_label, white)
        divider("REPUTATION")
        if result.hash_total>0:
            hc = red if result.hash_malicious>0 else green
            row("VirusTotal", f"{result.hash_malicious}/{result.hash_total} engines flagged", hc)
        else: row("VirusTotal", "No key — use --vt-key", muted)
        if result.otx_pulses>0: row("OTX Pulses", str(result.otx_pulses), red)

    if result.errors:
        divider("WARNINGS")
        [print(f"  {orange('⚠')}  {muted(e)}") for e in result.errors]
    divider(); print()

def generate_html(result):
    tc_hex = {"CRITICAL":"#ff2d55","HIGH":"#ff6b35","MEDIUM":"#ffd60a","LOW":"#30d158","CLEAN":"#30d158"}.get(result.threat_level,"#7c6aff")
    flags_html = ""
    if result.target_type in ("ip","domain"):
        if result.is_tor: flags_html += '<span class="flag critical">TOR Exit Node</span>'
        if result.is_proxy: flags_html += '<span class="flag high">Proxy / VPN</span>'
        if result.is_datacenter: flags_html += '<span class="flag medium">Datacenter</span>'
        if not flags_html: flags_html = '<span class="flag clean">No Flags</span>'
    ports_html = " ".join([f'<span class="port">{p}</span>' for p in result.shodan_ports]) or "<span class='muted'>None</span>"
    vulns_html = "".join([f'<div class="vuln">🔴 {v}</div>' for v in result.shodan_vulns]) or "<span class='muted'>None</span>"
    score_pct = result.threat_score

    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Threat Intel — {result.target}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@300;400;500;600;700&display=swap');
*{{box-sizing:border-box;margin:0;padding:0}}
:root{{--bg:#0a0a0f;--surface:#111118;--border:#1e1e2e;--text:#e2e2f0;--muted:#6e6e8a;--accent:#7c6aff;--critical:#ff2d55;--high:#ff6b35;--medium:#ffd60a;--low:#30d158}}
body{{background:var(--bg);color:var(--text);font-family:'Inter',sans-serif;font-size:14px}}
header{{border-bottom:1px solid var(--border);padding:20px 36px;display:flex;align-items:center;justify-content:space-between;background:var(--surface)}}
.logo{{display:flex;align-items:center;gap:12px}}.logo-icon{{width:34px;height:34px;background:var(--accent);border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:16px}}
.logo-text{{font-size:15px;font-weight:600}}.logo-sub{{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px}}
main{{padding:28px 36px;max-width:1200px;margin:0 auto}}
.risk-banner{{border:1px solid {tc_hex}33;background:{tc_hex}0d;border-radius:12px;padding:20px 28px;display:flex;align-items:center;gap:20px;margin-bottom:24px}}
.risk-dot{{width:12px;height:12px;border-radius:50%;background:{tc_hex};box-shadow:0 0 12px {tc_hex}}}
.risk-label{{font-size:10px;text-transform:uppercase;letter-spacing:1px;color:var(--muted)}}.risk-value{{font-size:24px;font-weight:700;color:{tc_hex}}}
.score-wrap{{margin-left:auto;text-align:right}}.score-num{{font-size:32px;font-weight:700;font-family:'JetBrains Mono',monospace;color:{tc_hex}}}
.score-bar{{height:4px;background:var(--border);border-radius:4px;margin-top:6px}}.score-fill{{height:100%;width:{score_pct}%;background:{tc_hex};border-radius:4px}}
.grid{{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px}}
.card{{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:20px;margin-bottom:16px}}
.card-title{{font-size:11px;text-transform:uppercase;letter-spacing:.8px;color:var(--muted);margin-bottom:14px}}
.row{{display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--border)}}.row:last-child{{border-bottom:none}}
.row-label{{color:var(--muted);font-size:12px}}.row-value{{font-family:'JetBrains Mono',monospace;font-size:12px}}
.flag{{display:inline-block;padding:3px 10px;border-radius:5px;font-size:11px;font-weight:700;margin:3px}}
.flag.critical{{background:var(--critical)22;color:var(--critical);border:1px solid var(--critical)44}}
.flag.high{{background:var(--high)22;color:var(--high);border:1px solid var(--high)44}}
.flag.medium{{background:var(--medium)22;color:var(--medium);border:1px solid var(--medium)44}}
.flag.clean{{background:var(--low)22;color:var(--low);border:1px solid var(--low)44}}
.port{{display:inline-block;background:var(--accent)22;color:var(--accent);border:1px solid var(--accent)33;padding:2px 8px;border-radius:4px;font-size:11px;font-family:'JetBrains Mono',monospace;margin:2px}}
.vuln{{color:var(--critical);font-family:'JetBrains Mono',monospace;font-size:12px;padding:4px 0}}
.muted{{color:var(--muted)}}
footer{{text-align:center;padding:24px;color:var(--muted);font-size:11px;border-top:1px solid var(--border);margin-top:40px}}
footer a{{color:var(--accent);text-decoration:none}}
</style></head><body>
<header>
  <div class="logo"><div class="logo-icon">🛡️</div>
  <div><div class="logo-text">Threat Intel Aggregator</div><div class="logo-sub">v1.0 by Brainrotshiva</div></div></div>
  <span style="color:var(--muted);font-size:12px">{result.scan_time}</span>
</header>
<main>
  <div class="risk-banner">
    <div class="risk-dot"></div>
    <div><div class="risk-label">Threat Level</div><div class="risk-value">{result.threat_level}</div></div>
    <div class="score-wrap">
      <div class="score-num">{result.threat_score}<span style="font-size:16px;color:var(--muted)">/100</span></div>
      <div style="font-size:11px;color:var(--muted)">Composite Threat Score</div>
      <div class="score-bar"><div class="score-fill"></div></div>
    </div>
  </div>
  <div class="grid">
    <div class="card">
      <div class="card-title">Target Info</div>
      <div class="row"><span class="row-label">Target</span><span class="row-value" style="color:#7c6aff">{result.target}</span></div>
      <div class="row"><span class="row-label">Type</span><span class="row-value">{result.target_type.upper()}</span></div>
      <div class="row"><span class="row-label">IP</span><span class="row-value">{result.ip or "—"}</span></div>
      <div class="row"><span class="row-label">Hostname</span><span class="row-value">{result.hostname or "—"}</span></div>
    </div>
    <div class="card">
      <div class="card-title">Geolocation</div>
      <div class="row"><span class="row-label">Country</span><span class="row-value">{result.country} {result.country_code}</span></div>
      <div class="row"><span class="row-label">City</span><span class="row-value">{result.city or "—"}</span></div>
      <div class="row"><span class="row-label">ISP</span><span class="row-value">{result.isp or result.org or "—"}</span></div>
      <div class="row"><span class="row-label">ASN</span><span class="row-value">{result.asn or "—"}</span></div>
    </div>
  </div>
  <div class="grid">
    <div class="card"><div class="card-title">Flags</div>{flags_html}</div>
    <div class="card"><div class="card-title">DNS Blacklists</div>{"".join([f'<span class="flag critical">{b}</span>' for b in result.dns_blacklists]) or '<span class="flag clean">Clean</span>'}</div>
  </div>
  <div class="card"><div class="card-title">Open Ports (Shodan)</div>{ports_html}</div>
  <div class="card"><div class="card-title">Vulnerabilities (Shodan)</div>{vulns_html}</div>
  <div class="card">
    <div class="card-title">Reputation Sources</div>
    <div class="row"><span class="row-label">VirusTotal</span><span class="row-value" style="color:{'#ff2d55' if result.vt_malicious>0 else '#30d158'}">{f"{result.vt_malicious}/{result.vt_total} flagged" if result.vt_total else "No key provided"}</span></div>
    <div class="row"><span class="row-label">AbuseIPDB</span><span class="row-value" style="color:{'#ff2d55' if result.abuse_score>50 else '#30d158'}">{f"{result.abuse_score}/100" if result.abuse_score else "No key provided"}</span></div>
    <div class="row"><span class="row-label">OTX Pulses</span><span class="row-value" style="color:{'#ff2d55' if result.otx_pulses>0 else '#30d158'}">{result.otx_pulses if result.otx_pulses else "No key provided"}</span></div>
  </div>
</main>
<footer><a href="https://github.com/Brainrotshiva/threat-intel-aggregator">Threat Intel Aggregator v1.0</a> by <a href="https://github.com/Brainrotshiva">Brainrotshiva</a></footer>
</body></html>"""

def main():
    parser = argparse.ArgumentParser(
        description="🛡️  Threat Intel Aggregator v1.0 — by Brainrotshiva",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ./threatintel.py 8.8.8.8
  ./threatintel.py google.com
  ./threatintel.py --hash abc123def456abc123def456abc123def456abc123def456
  ./threatintel.py 1.2.3.4 --vt-key YOUR_KEY --abuse-key YOUR_KEY --otx-key YOUR_KEY
  ./threatintel.py 1.2.3.4 --output report.html --json results.json

First time setup:
  chmod +x threatintel.py
        """
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("target", nargs="?", help="IP address or domain")
    group.add_argument("--hash", metavar="HASH", help="File hash (MD5/SHA1/SHA256)")
    parser.add_argument("--vt-key",    metavar="KEY", help="VirusTotal API key (optional)")
    parser.add_argument("--abuse-key", metavar="KEY", help="AbuseIPDB API key (optional)")
    parser.add_argument("--otx-key",   metavar="KEY", help="AlienVault OTX API key (optional)")
    parser.add_argument("--output",    metavar="FILE", default="threat_report.html")
    parser.add_argument("--json",      metavar="FILE", help="Export as JSON")
    parser.add_argument("--no-report", action="store_true", help="Skip HTML report")
    args = parser.parse_args()

    print_banner()

    result = IntelResult(
        target=args.hash or args.target,
        target_type="hash" if args.hash else ("ip" if is_ip(args.target) else "domain"),
        scan_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )
    if args.hash: result.hash_type = detect_hash_type(args.hash)

    if result.target_type == "domain":
        print(f"  {cyan('→')} {muted('Resolving domain...')}")
        result.ip = resolve_domain(result.target)
        if not result.ip: print(red(f"  ✗ Could not resolve {result.target}")); sys.exit(1)
        print(f"  {green('✓')} Resolved → {cyan(result.ip)}\n")
    elif result.target_type == "ip":
        result.ip = result.target

    if result.target_type in ("ip","domain"):
        fetch_ipapi(result);        print(f"  {green('✓')} Geolocation")
        fetch_shodan(result);       print(f"  {green('✓')} Shodan InternetDB")
        fetch_tor(result);          print(f"  {green('✓')} TOR check")
        fetch_dns_blacklist(result);print(f"  {green('✓')} DNS blacklists")

    if args.vt_key:
        if result.target_type=="ip": fetch_vt_ip(result, args.vt_key)
        elif result.target_type=="domain": fetch_vt_domain(result, args.vt_key)
        else: fetch_vt_hash(result, args.vt_key)
        print(f"  {green('✓')} VirusTotal")
    if args.abuse_key and result.ip: fetch_abuse(result, args.abuse_key); print(f"  {green('✓')} AbuseIPDB")
    if args.otx_key: fetch_otx(result, args.otx_key); print(f"  {green('✓')} OTX")

    print_report(result)

    if not args.no_report:
        with open(args.output,"w",encoding="utf-8") as f: f.write(generate_html(result))
        print(f"{green('📄')} Report saved → {cyan(args.output)}")

    if args.json:
        import dataclasses
        with open(args.json,"w",encoding="utf-8") as f: json.dump(dataclasses.asdict(result),f,indent=2)
        print(f"{green('📦')} JSON saved → {cyan(args.json)}")
    print()

if __name__ == "__main__":
    main()
