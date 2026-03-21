#!/usr/bin/env python3
"""
ioc-pivot — IOC enrichment CLI tool
Author: 0xPersist
License: MIT
"""

import argparse
import json
import sys
import time
import os
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    print("[!] Missing dependency: pip install requests")
    sys.exit(1)

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    COLOR = True
except ImportError:
    COLOR = False

VERSION = "1.0.0"

BANNER = r"""
  _            _       _            _
 (_) ___   ___| |     (_)__   ___  | |_
 | |/ _ \ / __| |_____| |\ \ / / | | __|
 | | (_) | (__|  _____| | \ V /| |_| |_
 |_|\___/ \___|_|     |_|  \_/  \__|___|

  ioc-pivot v{version} — by 0xPersist
  IOC enrichment: IPs, domains, hashes
""".format(version=VERSION)


# ── Color helpers ─────────────────────────────────────────────────────────────

def c(text, color):
    if not COLOR:
        return text
    colors = {
        "red":    Fore.RED,
        "green":  Fore.GREEN,
        "yellow": Fore.YELLOW,
        "cyan":   Fore.CYAN,
        "white":  Fore.WHITE,
        "dim":    Style.DIM,
        "bold":   Style.BRIGHT,
    }
    return f"{colors.get(color, '')}{text}{Style.RESET_ALL}"


def tag(label, color="cyan"):
    return c(f"[{label}]", color)


# ── IOC type detection ─────────────────────────────────────────────────────────

def detect_type(ioc: str) -> str:
    import re
    ioc = ioc.strip()
    # MD5
    if re.match(r'^[a-fA-F0-9]{32}$', ioc):
        return "hash_md5"
    # SHA1
    if re.match(r'^[a-fA-F0-9]{40}$', ioc):
        return "hash_sha1"
    # SHA256
    if re.match(r'^[a-fA-F0-9]{64}$', ioc):
        return "hash_sha256"
    # IPv4
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ioc):
        return "ip"
    # IPv6
    if re.match(r'^[a-fA-F0-9:]{2,39}$', ioc) and ':' in ioc:
        return "ip"
    # Domain
    if re.match(r'^([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}$', ioc):
        return "domain"
    # URL
    if ioc.startswith("http://") or ioc.startswith("https://"):
        return "url"
    return "unknown"


# ── VirusTotal ─────────────────────────────────────────────────────────────────

def query_virustotal(ioc: str, ioc_type: str, api_key: str) -> dict:
    base = "https://www.virustotal.com/api/v3"
    headers = {"x-apikey": api_key}

    endpoint_map = {
        "ip":         f"{base}/ip_addresses/{ioc}",
        "domain":     f"{base}/domains/{ioc}",
        "url":        None,  # requires submission step
        "hash_md5":   f"{base}/files/{ioc}",
        "hash_sha1":  f"{base}/files/{ioc}",
        "hash_sha256": f"{base}/files/{ioc}",
    }

    url = endpoint_map.get(ioc_type)
    if not url:
        return {"error": "Unsupported IOC type for VirusTotal"}

    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {
                "malicious":   stats.get("malicious", 0),
                "suspicious":  stats.get("suspicious", 0),
                "harmless":    stats.get("harmless", 0),
                "undetected":  stats.get("undetected", 0),
                "reputation":  data.get("reputation", "N/A"),
                "country":     data.get("country", "N/A"),
                "as_owner":    data.get("as_owner", "N/A"),
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
        return {"error": "AbuseIPDB only supports IP addresses"}

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
                "abuse_score":     d.get("abuseConfidenceScore", 0),
                "total_reports":   d.get("totalReports", 0),
                "country":         d.get("countryCode", "N/A"),
                "isp":             d.get("isp", "N/A"),
                "domain":          d.get("domain", "N/A"),
                "is_tor":          d.get("isTor", False),
                "last_reported":   d.get("lastReportedAt", "N/A"),
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
        return {"error": "Shodan host lookup only supports IP addresses"}

    try:
        r = requests.get(
            f"https://api.shodan.io/shodan/host/{ioc}",
            params={"key": api_key},
            timeout=10,
        )
        if r.status_code == 200:
            d = r.json()
            ports = sorted(set(d.get("ports", [])))
            hostnames = d.get("hostnames", [])
            tags = d.get("tags", [])
            vulns = list(d.get("vulns", {}).keys())[:5]
            org = d.get("org", "N/A")
            country = d.get("country_name", "N/A")
            return {
                "org":       org,
                "country":   country,
                "ports":     ports[:20],
                "hostnames": hostnames[:5],
                "tags":      tags,
                "vulns":     vulns,
                "os":        d.get("os", "N/A"),
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


# ── Output rendering ───────────────────────────────────────────────────────────

def verdict_color(malicious: int, score: int = 0) -> str:
    if malicious > 5 or score > 75:
        return "red"
    elif malicious > 0 or score > 25:
        return "yellow"
    return "green"


def render_result(ioc: str, ioc_type: str, results: dict):
    print()
    print(c("─" * 60, "dim"))
    print(f"  {c('IOC', 'bold')}  : {c(ioc, 'cyan')}")
    print(f"  {c('Type', 'bold')} : {ioc_type}")
    print(c("─" * 60, "dim"))

    # VirusTotal
    if "virustotal" in results:
        vt = results["virustotal"]
        print(f"\n  {tag('VirusTotal', 'yellow')}")
        if "error" in vt:
            print(f"    {c('Error: ' + vt['error'], 'red')}")
        else:
            mal = vt.get("malicious", 0)
            sus = vt.get("suspicious", 0)
            total = mal + sus + vt.get("harmless", 0) + vt.get("undetected", 0)
            col = verdict_color(mal)
            print(f"    Detections : {c(str(mal) + ' malicious', col)} / {c(str(sus) + ' suspicious', 'yellow')} of {total} engines")
            print(f"    Reputation : {vt.get('reputation', 'N/A')}")
            if vt.get("country") != "N/A":
                print(f"    Country    : {vt.get('country')}")
            if vt.get("as_owner") != "N/A":
                print(f"    ASN Owner  : {vt.get('as_owner')}")

    # AbuseIPDB
    if "abuseipdb" in results:
        ab = results["abuseipdb"]
        print(f"\n  {tag('AbuseIPDB', 'yellow')}")
        if "error" in ab:
            print(f"    {c('Error: ' + ab['error'], 'red')}")
        else:
            score = ab.get("abuse_score", 0)
            col = verdict_color(0, score)
            print(f"    Abuse Score  : {c(str(score) + '%', col)}")
            print(f"    Reports      : {ab.get('total_reports', 0)}")
            print(f"    Country      : {ab.get('country', 'N/A')}")
            print(f"    ISP          : {ab.get('isp', 'N/A')}")
            if ab.get("is_tor"):
                print(f"    TOR Exit     : {c('YES', 'red')}")
            if ab.get("last_reported") != "N/A":
                print(f"    Last Report  : {ab.get('last_reported')}")

    # Shodan
    if "shodan" in results:
        sh = results["shodan"]
        print(f"\n  {tag('Shodan', 'yellow')}")
        if "error" in sh:
            print(f"    {c('Error: ' + sh['error'], 'red')}")
        else:
            print(f"    Org       : {sh.get('org', 'N/A')}")
            print(f"    Country   : {sh.get('country', 'N/A')}")
            if sh.get("os") and sh.get("os") != "N/A":
                print(f"    OS        : {sh.get('os')}")
            if sh.get("ports"):
                print(f"    Ports     : {', '.join(map(str, sh['ports']))}")
            if sh.get("hostnames"):
                print(f"    Hostnames : {', '.join(sh['hostnames'])}")
            if sh.get("tags"):
                print(f"    Tags      : {', '.join(sh['tags'])}")
            if sh.get("vulns"):
                print(f"    CVEs      : {c(', '.join(sh['vulns']), 'red')}")

    print()


# ── Load IOCs from file ────────────────────────────────────────────────────────

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
        description="IOC enrichment tool — query IPs, domains, and hashes against threat intel APIs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  ioc-pivot -i 8.8.8.8 --vt --abuse
  ioc-pivot -i 44d88612fea8a8f36de82e1278abb02f --vt
  ioc-pivot -f iocs.txt --vt --abuse --shodan --json
  ioc-pivot -i malware.example.com --vt --out results.json

api keys (env vars):
  VTOTAL_API_KEY      VirusTotal API key
  ABUSEIPDB_API_KEY   AbuseIPDB API key
  SHODAN_API_KEY      Shodan API key
        """,
    )

    parser.add_argument("-i", "--ioc",    help="Single IOC to query (IP, domain, or hash)")
    parser.add_argument("-f", "--file",   help="File containing one IOC per line")
    parser.add_argument("--vt",           action="store_true", help="Query VirusTotal")
    parser.add_argument("--abuse",        action="store_true", help="Query AbuseIPDB (IPs only)")
    parser.add_argument("--shodan",       action="store_true", help="Query Shodan (IPs only)")
    parser.add_argument("--all",          action="store_true", help="Query all available sources")
    parser.add_argument("--json",         action="store_true", help="Output results as JSON")
    parser.add_argument("--out",          help="Write JSON output to file")
    parser.add_argument("--delay",        type=float, default=1.0,
                        help="Delay between requests in seconds (default: 1.0)")
    parser.add_argument("--no-banner",    action="store_true", help="Suppress banner")
    parser.add_argument("--version",      action="version", version=f"ioc-pivot {VERSION}")

    args = parser.parse_args()

    if not args.no_banner:
        print(c(BANNER, "cyan"))

    if not args.ioc and not args.file:
        parser.print_help()
        sys.exit(0)

    if args.all:
        args.vt = args.abuse = args.shodan = True

    if not any([args.vt, args.abuse, args.shodan]):
        print(c("[!] Specify at least one source: --vt, --abuse, --shodan, or --all", "red"))
        sys.exit(1)

    # Load API keys
    vt_key     = os.environ.get("VTOTAL_API_KEY", "")
    abuse_key  = os.environ.get("ABUSEIPDB_API_KEY", "")
    shodan_key = os.environ.get("SHODAN_API_KEY", "")

    if args.vt and not vt_key:
        print(c("[!] VTOTAL_API_KEY not set", "red"))
    if args.abuse and not abuse_key:
        print(c("[!] ABUSEIPDB_API_KEY not set", "red"))
    if args.shodan and not shodan_key:
        print(c("[!] SHODAN_API_KEY not set", "red"))

    # Collect IOCs
    iocs = []
    if args.ioc:
        iocs.append(args.ioc.strip())
    if args.file:
        iocs.extend(load_iocs(args.file))

    iocs = list(dict.fromkeys(iocs))  # deduplicate, preserve order

    all_results = {}

    for idx, ioc in enumerate(iocs):
        ioc_type = detect_type(ioc)
        results  = {}

        if args.vt and vt_key:
            results["virustotal"] = query_virustotal(ioc, ioc_type, vt_key)
            if idx < len(iocs) - 1 or args.abuse or args.shodan:
                time.sleep(args.delay)

        if args.abuse and abuse_key:
            results["abuseipdb"] = query_abuseipdb(ioc, ioc_type, abuse_key)
            if idx < len(iocs) - 1 or args.shodan:
                time.sleep(args.delay)

        if args.shodan and shodan_key:
            results["shodan"] = query_shodan(ioc, ioc_type, shodan_key)
            if idx < len(iocs) - 1:
                time.sleep(args.delay)

        all_results[ioc] = {
            "type":    ioc_type,
            "results": results,
            "ts":      datetime.now(timezone.utc).isoformat(),
        }

        if not args.json:
            render_result(ioc, ioc_type, results)

    # JSON output
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
