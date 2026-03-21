# ioc-pivot

CLI tool for rapid IOC enrichment. Query IPs, domains, and file hashes against VirusTotal, AbuseIPDB, and Shodan from the terminal — no browser required.

Built for SOC analysts and threat hunters who need fast triage without leaving the command line.

---

## Features

- Supports IPs, domains, MD5/SHA1/SHA256 hashes
- Sources: VirusTotal, AbuseIPDB, Shodan
- Bulk input via file (one IOC per line)
- Color-coded terminal output with verdict scoring
- JSON output for pipeline integration or logging
- Rate-limit aware with configurable request delay
- Zero config — API keys via environment variables

---

## Install

```bash
git clone https://github.com/0xPersist/ioc-pivot.git
cd ioc-pivot
pip install -r requirements.txt
```

---

## API Keys

Set your keys as environment variables before running:

```bash
export VTOTAL_API_KEY="your_key_here"
export ABUSEIPDB_API_KEY="your_key_here"
export SHODAN_API_KEY="your_key_here"
```

Free tiers are available for all three services and are sufficient for most use cases.

- VirusTotal: https://www.virustotal.com/gui/join-us
- AbuseIPDB: https://www.abuseipdb.com/register
- Shodan: https://account.shodan.io/register

---

## Usage

```
usage: ioc-pivot [-h] [-i IOC] [-f FILE] [--vt] [--abuse] [--shodan] [--all]
                 [--json] [--out OUT] [--delay DELAY] [--no-banner]

options:
  -i, --ioc      Single IOC to query (IP, domain, or hash)
  -f, --file     File containing one IOC per line
  --vt           Query VirusTotal
  --abuse        Query AbuseIPDB (IPs only)
  --shodan       Query Shodan (IPs only)
  --all          Query all available sources
  --json         Output results as JSON
  --out OUT      Write JSON output to file
  --delay DELAY  Delay between requests in seconds (default: 1.0)
  --no-banner    Suppress banner
```

---

## Examples

**Single IP, all sources:**
```bash
ioc-pivot -i 198.51.100.23 --all
```

**Hash lookup on VirusTotal:**
```bash
ioc-pivot -i 44d88612fea8a8f36de82e1278abb02f --vt
```

**Bulk IOC file, JSON output:**
```bash
ioc-pivot -f iocs.txt --vt --abuse --json --out results.json
```

**Pipe-friendly with no banner:**
```bash
ioc-pivot -i malware.example.com --vt --json --no-banner | jq .
```

---

## Sample Output

```
  ────────────────────────────────────────────────────────────
  IOC  : 198.51.100.23
  Type : ip
  ────────────────────────────────────────────────────────────

  [VirusTotal]
    Detections : 12 malicious / 2 suspicious of 94 engines
    Reputation : -42
    Country    : RU
    ASN Owner  : AS12345 Some Hosting LLC

  [AbuseIPDB]
    Abuse Score  : 87%
    Reports      : 143
    Country      : RU
    ISP          : Some Hosting LLC
    TOR Exit     : NO
    Last Report  : 2024-11-01T14:22:00+00:00

  [Shodan]
    Org       : Some Hosting LLC
    Country   : Russia
    Ports     : 22, 80, 443, 8080
    Tags      : self-signed
    CVEs      : CVE-2021-44228, CVE-2022-26134
```

---

## IOC File Format

Plain text, one IOC per line. Lines starting with `#` are treated as comments.

```
# Suspicious IPs from honeypot
198.51.100.23
198.51.100.44

# Malware hashes
44d88612fea8a8f36de82e1278abb02f

# Suspicious domains
malware.example.com
```

---

## Requirements

- Python 3.8+
- `requests`
- `colorama` (optional, for colored output)

---

## License

MIT — see [LICENSE](LICENSE)

---

*by [0xPersist](https://github.com/0xPersist)*
