#!/usr/bin/env python3
"""
ioc-pivot v2 | IOC enrichment CLI tool
Author: 0xPersist
License: MIT
"""

import argparse
import json
import sys
import time
import os
import re
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    print("[!] Missing dependency: pip install requests")
    sys.exit(1)

try:
    from colorama import Fore, Back, Style, init as colorama_init
    colorama_init(autoreset=True)
    COLOR = True
except ImportError:
    COLOR = False

VERSION = "2.0.0"

BANNER = r"""
  ██╗ ██████╗  ██████╗    ██████╗ ██╗██╗   ██╗ ██████╗ ████████╗
  ██║██╔═══██╗██╔════╝    ██╔══██╗██║██║   ██║██╔═══██╗╚══██╔══╝
  ██║██║   ██║██║         ██████╔╝██║██║   ██║██║   ██║   ██║
  ██║██║   ██║██║         ██╔═══╝ ██║╚██╗ ██╔╝██║   ██║   ██║
  ██║╚██████╔╝╚██████╗    ██║     ██║ ╚████╔╝ ╚██████╔╝   ██║
  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝     ╚═╝  ╚═══╝   ╚═════╝    ╚═╝
"""

BANNER_SUB = "  v{version}  |  by 0xPersist  |  IOC enrichment: IPs, domains, hashes, URLs\n".format(version=VERSION)


# ── Color helpers ──────────────────────────────────────────────────────────────

def c(text, color):
    if not COLOR:
        return text
    colors = {
        "red":     Fore.RED,
        "green":   Fore.GREEN,
        "yellow":  Fore.YELLOW,
        "cyan":    Fore.CYAN,
        "white":   Fore.WHITE,
        "magenta": Fore.MAGENTA,
        "blue":    Fore.BLUE,
        "dim":     Style.DIM,
        "bold":    Style.BRIGHT,
    }
    return f"{colors.get(color, '')}{text}{Style.RESET_ALL}"


def tag(label, color="cyan"):
    return c(f"[{label}]", color)


def spinner_char(i):
    return ["⠋", "⠙", "⠸", "⠴", "⠦", "⠇"][i % 6]


# ── Verdict bar ────────────────────────────────────────────────────────────────

def threat_score(results: dict) -> int:
    """
    Compute a 0-100 composite threat score across all sources.
    """
    score = 0
    sources = 0

    vt = results.get("virustotal", {})
    if "error" not in vt and vt:
        mal = vt.get("malicious", 0)
        sus = vt.get("suspicious", 0)
        total = mal + sus + vt.get("harmless", 0) + vt.get("undetected", 0)
        if total > 0:
            score += int(((mal + sus * 0.5) / total) * 100)
            sources += 1

    ab = results.get("abuseipdb", {})
    if "error" not in ab and ab:
        score += ab.get("abuse_score", 0)
        sources += 1

    sh = results.get("shodan", {})
    if "error" not in sh and sh:
        vulns = len(sh.get("vulns", []))
        score += min(vulns * 15, 60)
        sources += 1

    otx = results.get("otx", {})
    if "error" not in otx and otx:
        pulses = otx.get("pulse_count", 0)
        score += min(pulses * 10, 80)
        sources += 1

    if sources == 0:
        return 0
    return min(int(score / sources), 100)


def verdict_bar(score: int) -> str:
    filled = int(score / 5)
    empty  = 20 - filled

    if score >= 70:
        bar_color = "red"
        label = "HIGH THREAT"
    elif score >= 35:
        bar_color = "yellow"
        label = "SUSPICIOUS"
    elif score > 0:
        bar_color = "green"
        label = "LOW RISK"
    else:
        bar_color = "green"
        label = "CLEAN"

    bar = c("█" * filled, bar_color) + c("░" * empty, "dim")
    score_str = c(f"{score:3d}/100", bar_color)
    label_str = c(f"[{label}]", bar_color)
    return f"  {bar}  {score_str}  {label_str}"


def verdict_color(malicious: int, score: int = 0) -> str:
    if malicious > 5 or score > 75:
        return "red"
    elif malicious > 0 or score > 25:
        return "yellow"
    return "green"


# ── IOC type detection ─────────────────────────────────────────────────────────

def detect_type(ioc: str) -> str:
    ioc = ioc.strip()
    if re.match(r'^[a-fA-F0-9]{32}$', ioc):
        return "hash_md5"
    if re.match(r'^[a-fA-F0-9]{40}$', ioc):
        return "hash_sha1"
    if re.match(r'^[a-fA-F0-9]{64}$', ioc):
        return "hash_sha256"
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ioc):
        return "ip"
    if re.match(r'^[a-fA-F0-9:]{2,39}$', ioc) and ':' in ioc:
        return "ip"
    if ioc.startswith("http://") or ioc.startswith("https://"):
        return "url"
    if re.match(r'^([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}$', ioc):
        return "domain"
    return "unknown"


def ioc_type_label(ioc_type: str) -> str:
    labels = {
        "ip":          "IPv4",
        "domain":      "Domain",
        "url":         "URL",
        "hash_md5":    "MD5",
        "hash_sha1":   "SHA1",
        "hash_sha256": "SHA256",
        "unknown":     "Unknown",
    }
    return labels.get(ioc_type, ioc_type)


# ── VirusTotal ─────────────────────────────────────────────────────────────────

def query_virustotal(ioc: str, ioc_type: str, api_key: str) -> dict:
    base    = "https://www.virustotal.com/api/v3"
    headers = {"x-apikey": api_key}

    if ioc_type == "url":
        # Submit URL for analysis then fetch report
        try:
            submit = requests.post(
                f"{base}/urls",
                headers=headers,
                data={"url": ioc},
                timeout=10,
            )
            if submit.status_code not in (200, 201):
                return {"error": f"URL submission failed: HTTP {submit.status_code}"}
            url_id = submit.json().get("data", {}).get("id", "")
            if not url_id:
                return {"error": "URL submission returned no ID"}
            time.sleep(2)
            r = requests.get(f"{base}/analyses/{url_id}", headers=headers, timeout=10)
            if r.status_code == 200:
                stats = r.json().get("data", {}).get("attributes", {}).get("stats", {})
                return {
                    "malicious":  stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless":   stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "reputation": "N/A",
                    "country":    "N/A",
                    "as_owner":   "N/A",
                }
            return {"error": f"HTTP {r.status_code}"}
        except requests.exceptions.Timeout:
            return {"error": "Timeout"}
        except Exception as e:
            return {"error": str(e)}

    endpoint_map = {
        "ip":          f"{base}/ip_addresses/{ioc}",
        "domain":      f"{base}/domains/{ioc}",
        "hash_md5":    f"{base}/files/{ioc}",
        "hash_sha1":   f"{base}/files/{ioc}",
        "hash_sha256": f"{base}/files/{ioc}",
    }

    url = endpoint_map.get(ioc_type)
    if not url:
        return {"error": "Unsupported IOC type for VirusTotal"}

    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            data  = r.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {
                "malicious":  stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless":   stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "reputation": data.get("reputation", "N/A"),
                "country":    data.get("country", "N/A"),
                "as_owner":   data.get("as_owner", "N/A"),
                "tags":       data.get("tags", []),
            }
        elif r.status_code == 404:
            return {"error": "Not found"}
        elif r.status_code == 401:
            return {"error": "Invalid API key"}
        elif r.status_code == 429:
            return {"error": "Rate limited"}
        else:
            return {"error": f"HTTP {r.status_code}"}
    except requests.exceptions.Timeout:
        return {"error": "Timeout"}
    except Exception as e:
        return {"error": str(e)}


# ── AbuseIPDB ──────────────────────────────────────────────────────────────────

def query_abuseipdb(ioc: str, ioc_type: str, api_key: str) -> dict:
    if ioc_type != "ip":
        return {"error": "AbuseIPDB supports IP addresses only"}

    headers = {"Key": api_key, "Accept": "application/json"}
    params  = {"ipAddress": ioc, "maxAgeInDays": 90, "verbose": False}

    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers,
            params=params,
            timeout=10,
        )
        if r.status_code == 200:
            d = r.json().get("data", {})
            return {
                "abuse_score":   d.get("abuseConfidenceScore", 0),
                "total_reports": d.get("totalReports", 0),
                "country":       d.get("countryCode", "N/A"),
                "isp":           d.get("isp", "N/A"),
                "domain":        d.get("domain", "N/A"),
                "is_tor":        d.get("isTor", False),
                "is_public":     d.get("isPublic", True),
                "usage_type":    d.get("usageType", "N/A"),
                "last_reported": d.get("lastReportedAt", "N/A"),
            }
        elif r.status_code == 401:
            return {"error": "Invalid API key"}
        elif r.status_code == 429:
            return {"error": "Rate limited"}
        else:
            return {"error": f"HTTP {r.status_code}"}
    except requests.exceptions.Timeout:
        return {"error": "Timeout"}
    except Exception as e:
        return {"error": str(e)}


# ── Shodan ─────────────────────────────────────────────────────────────────────

def query_shodan(ioc: str, ioc_type: str, api_key: str) -> dict:
    if ioc_type != "ip":
        return {"error": "Shodan host lookup supports IP addresses only"}

    try:
        r = requests.get(
            f"https://api.shodan.io/shodan/host/{ioc}",
            params={"key": api_key},
            timeout=10,
        )
        if r.status_code == 200:
            d = r.json()
            return {
                "org":       d.get("org", "N/A"),
                "country":   d.get("country_name", "N/A"),
                "city":      d.get("city", "N/A"),
                "os":        d.get("os", "N/A"),
                "ports":     sorted(set(d.get("ports", [])))[:20],
                "hostnames": d.get("hostnames", [])[:5],
                "domains":   d.get("domains", [])[:5],
                "tags":      d.get("tags", []),
                "vulns":     list(d.get("vulns", {}).keys())[:8],
                "last_update": d.get("last_update", "N/A"),
            }
        elif r.status_code == 404:
            return {"error": "No information available"}
        elif r.status_code == 401:
            return {"error": "Invalid API key"}
        elif r.status_code == 429:
            return {"error": "Rate limited"}
        else:
            return {"error": f"HTTP {r.status_code}"}
    except requests.exceptions.Timeout:
        return {"error": "Timeout"}
    except Exception as e:
        return {"error": str(e)}


# ── OTX (AlienVault) ───────────────────────────────────────────────────────────

def query_otx(ioc: str, ioc_type: str, api_key: str) -> dict:
    base    = "https://otx.alienvault.com/api/v1/indicators"
    headers = {"X-OTX-API-KEY": api_key}

    type_map = {
        "ip":          f"{base}/IPv4/{ioc}/general",
        "domain":      f"{base}/domain/{ioc}/general",
        "url":         f"{base}/url/{ioc}/general",
        "hash_md5":    f"{base}/file/{ioc}/general",
        "hash_sha1":   f"{base}/file/{ioc}/general",
        "hash_sha256": f"{base}/file/{ioc}/general",
    }

    url = type_map.get(ioc_type)
    if not url:
        return {"error": "Unsupported IOC type for OTX"}

    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            d = r.json()
            pulse_info  = d.get("pulse_info", {})
            pulse_count = pulse_info.get("count", 0)
            pulses      = pulse_info.get("pulses", [])
            tags        = []
            malware_fam = []
            for p in pulses[:5]:
                tags.extend(p.get("tags", []))
                malware_fam.extend(p.get("malware_families", []))
            return {
                "pulse_count":    pulse_count,
                "pulse_names":    [p.get("name", "") for p in pulses[:3]],
                "tags":           list(set(tags))[:8],
                "malware_family": list(set(malware_fam))[:5],
                "country":        d.get("country_name", "N/A"),
                "asn":            d.get("asn", "N/A"),
            }
        elif r.status_code == 400:
            return {"error": "Invalid IOC format"}
        elif r.status_code == 401:
            return {"error": "Invalid API key"}
        elif r.status_code == 404:
            return {"error": "Not found"}
        elif r.status_code == 429:
            return {"error": "Rate limited"}
        else:
            return {"error": f"HTTP {r.status_code}"}
    except requests.exceptions.Timeout:
        return {"error": "Timeout"}
    except Exception as e:
        return {"error": str(e)}


# ── Progress indicator ─────────────────────────────────────────────────────────

def query_with_progress(label: str, fn, *args) -> dict:
    """Run a query function with a live progress indicator."""
    if not sys.stdout.isatty():
        return fn(*args)

    frames  = ["⠋", "⠙", "⠸", "⠴", "⠦", "⠇"]
    result  = [None]
    done    = [False]

    import threading

    def worker():
        result[0] = fn(*args)
        done[0]   = True

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()

    i = 0
    while not done[0]:
        frame = c(frames[i % len(frames)], "cyan")
        sys.stdout.write(f"\r  {frame}  Querying {c(label, 'yellow')} ...")
        sys.stdout.flush()
        time.sleep(0.1)
        i += 1

    sys.stdout.write(f"\r  {c('✓', 'green')}  {c(label, 'yellow')} done          \n")
    sys.stdout.flush()

    return result[0]


# ── Output rendering ───────────────────────────────────────────────────────────

def render_result(ioc: str, ioc_type: str, results: dict, index: int, total: int):
    score = threat_score(results)

    print()
    print(c("╔" + "═" * 62 + "╗", "dim"))
    print(c("║", "dim") + f"  {c('IOC', 'bold')} {c(str(index) + '/' + str(total), 'dim')}  {c(ioc, 'cyan'):<45}" + c("║", "dim"))
    print(c("║", "dim") + f"  {c('Type:', 'dim')} {c(ioc_type_label(ioc_type), 'white'):<55}" + c("║", "dim"))
    print(c("╠" + "═" * 62 + "╣", "dim"))
    source_count = len([k for k in results if "error" not in results[k]])
    total_sources = len(results)
    source_note = c(f"  score based on {source_count}/{total_sources} source{'s' if total_sources != 1 else ''}", "dim")
    print(c("║", "dim") + f"  Threat Score {source_note:<50}" + c("║", "dim"))
    print(c("║", "dim") + verdict_bar(score) + "          " + c("║", "dim"))
    print(c("╚" + "═" * 62 + "╝", "dim"))

    # VirusTotal
    if "virustotal" in results:
        vt = results["virustotal"]
        print(f"\n  {tag('VirusTotal', 'yellow')}")
        if "error" in vt:
            print(f"    {c('Error: ' + vt['error'], 'red')}")
        else:
            mal   = vt.get("malicious", 0)
            sus   = vt.get("suspicious", 0)
            har   = vt.get("harmless", 0)
            und   = vt.get("undetected", 0)
            total_engines = mal + sus + har + und
            col   = verdict_color(mal)
            print(f"    Detections  : {c(str(mal) + ' malicious', col)} / {c(str(sus) + ' suspicious', 'yellow')} of {total_engines} engines")
            rep = vt.get("reputation", "N/A")
            if rep != "N/A":
                rep_col = "red" if int(rep) < 0 else "green"
                print(f"    Reputation  : {c(str(rep), rep_col)}")
            if vt.get("country") not in ("N/A", "", None):
                print(f"    Country     : {vt.get('country')}")
            if vt.get("as_owner") not in ("N/A", "", None):
                print(f"    ASN Owner   : {vt.get('as_owner')}")
            if vt.get("tags"):
                print(f"    Tags        : {c(', '.join(vt['tags']), 'magenta')}")

    # AbuseIPDB
    if "abuseipdb" in results:
        ab = results["abuseipdb"]
        print(f"\n  {tag('AbuseIPDB', 'yellow')}")
        if "error" in ab:
            print(f"    {c('Error: ' + ab['error'], 'red')}")
        else:
            score_ab = ab.get("abuse_score", 0)
            col      = verdict_color(0, score_ab)
            print(f"    Abuse Score  : {c(str(score_ab) + '%', col)}")
            print(f"    Reports      : {c(str(ab.get('total_reports', 0)), 'white')}")
            print(f"    Country      : {ab.get('country', 'N/A')}")
            print(f"    ISP          : {ab.get('isp', 'N/A')}")
            if ab.get("usage_type") not in ("N/A", "", None):
                print(f"    Usage Type   : {ab.get('usage_type')}")
            if ab.get("is_tor"):
                print(f"    TOR Exit     : {c('YES', 'red')}")
            if ab.get("last_reported") not in ("N/A", "", None):
                print(f"    Last Report  : {ab.get('last_reported')}")

    # Shodan
    if "shodan" in results:
        sh = results["shodan"]
        print(f"\n  {tag('Shodan', 'yellow')}")
        if "error" in sh:
            print(f"    {c('Error: ' + sh['error'], 'red')}")
        else:
            print(f"    Org          : {sh.get('org', 'N/A')}")
            loc_parts = [sh.get("city", ""), sh.get("country", "")]
            loc       = ", ".join(p for p in loc_parts if p and p != "N/A")
            if loc:
                print(f"    Location     : {loc}")
            if sh.get("os") not in ("N/A", "", None):
                print(f"    OS           : {sh.get('os')}")
            if sh.get("ports"):
                print(f"    Open Ports   : {c(', '.join(map(str, sh['ports'])), 'yellow')}")
            if sh.get("hostnames"):
                print(f"    Hostnames    : {', '.join(sh['hostnames'])}")
            if sh.get("domains"):
                print(f"    Domains      : {', '.join(sh['domains'])}")
            if sh.get("tags"):
                print(f"    Tags         : {c(', '.join(sh['tags']), 'magenta')}")
            if sh.get("vulns"):
                print(f"    CVEs         : {c(', '.join(sh['vulns']), 'red')}")
            if sh.get("last_update") not in ("N/A", "", None):
                print(f"    Last Updated : {sh.get('last_update')}")

    # OTX
    if "otx" in results:
        otx = results["otx"]
        print(f"\n  {tag('OTX', 'yellow')}")
        if "error" in otx:
            print(f"    {c('Error: ' + otx['error'], 'red')}")
        else:
            pc  = otx.get("pulse_count", 0)
            col = "red" if pc > 5 else "yellow" if pc > 0 else "green"
            print(f"    Pulse Count  : {c(str(pc), col)}")
            if otx.get("pulse_names"):
                for name in otx["pulse_names"]:
                    print(f"    {c('>', 'dim')} {name[:60]}")
            if otx.get("malware_family"):
                print(f"    Malware      : {c(', '.join(otx['malware_family']), 'red')}")
            if otx.get("tags"):
                print(f"    Tags         : {c(', '.join(otx['tags']), 'magenta')}")
            if otx.get("asn") not in ("N/A", "", None):
                print(f"    ASN          : {otx.get('asn')}")

    print()


# ── Summary table ──────────────────────────────────────────────────────────────

def render_summary(all_results: dict):
    print(c("\n  SUMMARY", "bold"))
    print(c("  " + "─" * 58, "dim"))
    print(f"  {'IOC':<38} {'TYPE':<10} {'SCORE':<8} VERDICT")
    print(c("  " + "─" * 58, "dim"))

    for ioc, data in all_results.items():
        score   = threat_score(data["results"])
        ioc_t   = ioc_type_label(data["type"])

        if score >= 70:
            verdict = c("HIGH THREAT", "red")
            s_str   = c(str(score), "red")
        elif score >= 35:
            verdict = c("SUSPICIOUS", "yellow")
            s_str   = c(str(score), "yellow")
        elif score > 0:
            verdict = c("LOW RISK", "green")
            s_str   = c(str(score), "green")
        else:
            verdict = c("CLEAN", "green")
            s_str   = c(str(score), "green")

        ioc_display = ioc[:36] + ".." if len(ioc) > 36 else ioc
        print(f"  {ioc_display:<38} {ioc_t:<10} {s_str:<8} {verdict}")

    print(c("  " + "─" * 58, "dim"))
    print()


# ── Load IOCs ──────────────────────────────────────────────────────────────────

def load_iocs(path: str) -> list:
    try:
        with open(path) as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        print(c(f"[!] File not found: {path}", "red"))
        sys.exit(1)


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="ioc-pivot",
        description="IOC enrichment tool: query IPs, domains, hashes, and URLs against threat intel APIs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  ioc-pivot -i 8.8.8.8 --vt --abuse
  ioc-pivot -i 44d88612fea8a8f36de82e1278abb02f --vt
  ioc-pivot -i https://malware.example.com/payload --vt --otx
  ioc-pivot -f iocs.txt --all --json
  ioc-pivot -i malware.example.com --all --out results.json

api keys (env vars):
  VTOTAL_API_KEY      VirusTotal API key
  ABUSEIPDB_API_KEY   AbuseIPDB API key
  SHODAN_API_KEY      Shodan API key
  OTX_API_KEY         AlienVault OTX API key
        """,
    )

    parser.add_argument("-i", "--ioc",     help="Single IOC to query (IP, domain, hash, or URL)")
    parser.add_argument("-f", "--file",    help="File containing one IOC per line")
    parser.add_argument("--vt",            action="store_true", help="Query VirusTotal")
    parser.add_argument("--abuse",         action="store_true", help="Query AbuseIPDB (IPs only)")
    parser.add_argument("--shodan",        action="store_true", help="Query Shodan (IPs only)")
    parser.add_argument("--otx",           action="store_true", help="Query AlienVault OTX")
    parser.add_argument("--all",           action="store_true", help="Query all available sources")
    parser.add_argument("--json",          action="store_true", help="Output results as JSON")
    parser.add_argument("--out",           help="Write JSON output to file")
    parser.add_argument("--no-summary",    action="store_true", help="Skip summary table at end")
    parser.add_argument("--delay",         type=float, default=1.0,
                        help="Delay between IOCs in seconds (default: 1.0)")
    parser.add_argument("--no-banner",     action="store_true", help="Suppress banner")
    parser.add_argument("--version",       action="version", version=f"ioc-pivot {VERSION}")

    args = parser.parse_args()

    if not args.no_banner and not args.json:
        print(c(BANNER, "cyan"))
        print(c(BANNER_SUB, "dim"))

    if not args.ioc and not args.file:
        parser.print_help()
        sys.exit(0)

    if args.all:
        args.vt = args.abuse = args.shodan = args.otx = True

    if not any([args.vt, args.abuse, args.shodan, args.otx]):
        print(c("[!] Specify at least one source: --vt, --abuse, --shodan, --otx, or --all", "red"))
        sys.exit(1)

    vt_key     = os.environ.get("VTOTAL_API_KEY", "")
    abuse_key  = os.environ.get("ABUSEIPDB_API_KEY", "")
    shodan_key = os.environ.get("SHODAN_API_KEY", "")
    otx_key    = os.environ.get("OTX_API_KEY", "")

    if args.vt     and not vt_key:     print(c("[!] VTOTAL_API_KEY not set", "red"))
    if args.abuse  and not abuse_key:  print(c("[!] ABUSEIPDB_API_KEY not set", "red"))
    if args.shodan and not shodan_key: print(c("[!] SHODAN_API_KEY not set", "red"))
    if args.otx    and not otx_key:    print(c("[!] OTX_API_KEY not set", "red"))

    iocs = []
    if args.ioc:
        iocs.append(args.ioc.strip())
    if args.file:
        iocs.extend(load_iocs(args.file))

    iocs = list(dict.fromkeys(iocs))

    all_results = {}
    total       = len(iocs)

    for idx, ioc in enumerate(iocs, 1):
        ioc_type = detect_type(ioc)
        results  = {}

        if not args.json:
            print(c(f"\n[*] IOC {idx}/{total}: {ioc}", "dim"))

        if args.vt and vt_key:
            results["virustotal"] = query_with_progress("VirusTotal", query_virustotal, ioc, ioc_type, vt_key) if not args.json else query_virustotal(ioc, ioc_type, vt_key)
            time.sleep(args.delay)

        if args.abuse and abuse_key:
            results["abuseipdb"] = query_with_progress("AbuseIPDB", query_abuseipdb, ioc, ioc_type, abuse_key) if not args.json else query_abuseipdb(ioc, ioc_type, abuse_key)
            time.sleep(args.delay)

        if args.shodan and shodan_key:
            results["shodan"] = query_with_progress("Shodan", query_shodan, ioc, ioc_type, shodan_key) if not args.json else query_shodan(ioc, ioc_type, shodan_key)
            time.sleep(args.delay)

        if args.otx and otx_key:
            results["otx"] = query_with_progress("OTX", query_otx, ioc, ioc_type, otx_key) if not args.json else query_otx(ioc, ioc_type, otx_key)
            time.sleep(args.delay)

        all_results[ioc] = {
            "type":    ioc_type,
            "results": results,
            "score":   threat_score(results),
            "ts":      datetime.now(timezone.utc).isoformat(),
        }

        if not args.json:
            render_result(ioc, ioc_type, results, idx, total)

    if not args.json and not args.no_summary and len(iocs) > 1:
        render_summary(all_results)

    if args.json or args.out:
        output = json.dumps(all_results, indent=2)
        if args.json:
            print(output)
        if args.out:
            with open(args.out, "w") as f:
                f.write(output)
            print(c(f"\n[+] Results written to {args.out}", "green"))


if __name__ == "__main__":
    main()
