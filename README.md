# ioc-pivot

CLI tool for rapid IOC enrichment. Query IPs, domains, hashes, and URLs against VirusTotal, AbuseIPDB, Shodan, and AlienVault OTX from the terminal without touching a browser.

Built for SOC analysts and threat hunters who need fast triage at the command line.

---

## What's New in v2

- OTX (AlienVault) added as a 4th source
- URL support for VirusTotal
- Live progress indicator per query
- Composite threat score (0-100) with visual verdict bar per IOC
- Summary table at the end of bulk runs
- Usage type field from AbuseIPDB
- City-level location from Shodan
- Tags field from VirusTotal

---

## Features

- Supports IPs, domains, URLs, MD5/SHA1/SHA256 hashes
- Sources: VirusTotal, AbuseIPDB, Shodan, AlienVault OTX
- Composite threat score with color-coded verdict bar
- Bulk input via file (one IOC per line)
- Live spinner per query so you know it's working
- Summary table across all IOCs at the end of a run
- JSON output for pipeline integration or logging
- Rate-limit aware with configurable request delay
- API keys via environment variables

---

## Install

```bash
git clone https://github.com/0xPersist/ioc-pivot.git
cd ioc-pivot
pip install -r requirements.txt
```

---

## API Keys

```bash
export VTOTAL_API_KEY="your_key_here"
export ABUSEIPDB_API_KEY="your_key_here"
export SHODAN_API_KEY="your_key_here"
export OTX_API_KEY="your_key_here"
```

Free tiers available for all four services:

- VirusTotal: https://www.virustotal.com/gui/join-us
- AbuseIPDB: https://www.abuseipdb.com/register
- Shodan: https://account.shodan.io/register
- OTX: https://otx.alienvault.com

---

## Usage

```
usage: ioc-pivot [-h] [-i IOC] [-f FILE] [--vt] [--abuse] [--shodan] [--otx]
                 [--all] [--json] [--out OUT] [--no-summary] [--delay DELAY]
                 [--no-banner]

options:
  -i, --ioc        Single IOC to query (IP, domain, hash, or URL)
  -f, --file       File containing one IOC per line
  --vt             Query VirusTotal
  --abuse          Query AbuseIPDB (IPs only)
  --shodan         Query Shodan (IPs only)
  --otx            Query AlienVault OTX
  --all            Query all available sources
  --json           Output results as JSON
  --out OUT        Write JSON output to file
  --no-summary     Skip summary table at end of bulk runs
  --delay DELAY    Delay between requests in seconds (default: 1.0)
  --no-banner      Suppress banner
```

---

## Examples

**Single IP, all sources:**
```bash
ioc-pivot -i 198.51.100.23 --all
```

**Hash lookup:**
```bash
ioc-pivot -i 44d88612fea8a8f36de82e1278abb02f --vt --otx
```

**URL scan:**
```bash
ioc-pivot -i https://malware.example.com/payload --vt
```

**Bulk file run with JSON output:**
```bash
ioc-pivot -f iocs.txt --all --out results.json
```

**Pipe-friendly:**
```bash
ioc-pivot -i 198.51.100.23 --vt --json --no-banner | jq .
```

Missing-key warnings are written to stderr, so `--json` stdout stays parseable even when a
requested source has no key configured.

---

## IOC File Format

Plain text, one IOC per line. Lines starting with `#` are treated as comments.

```
# Suspicious IPs from alert triage
198.51.100.23
198.51.100.44

# Malware hashes
44d88612fea8a8f36de82e1278abb02f

# Suspicious domains
malware.example.com
```

---

## Threat Scoring

Each IOC gets a threat score calculated across all queried sources:

- VirusTotal detection ratio weighted by engine count (contributes 0-100)
- AbuseIPDB confidence score (0-100)
- Shodan CVE count contribution (0-60)
- OTX pulse count contribution (0-80)

Scores are color-coded: green (clean), yellow (suspicious), red (high threat).

**How the sources combine, and its limits.** The score is the **arithmetic mean** of the
sub-scores of the sources you actually queried, so the attainable range depends on which
flags you pass. Because the Shodan and OTX sub-scores are capped below 100, the maximum
score under `--all` is **85**, not 100. `--shodan` alone tops out at 60 and `--otx` alone
at 80.

Averaging also means the score does not rise with corroboration: an IOC that VirusTotal
rates maximally malicious scores 100 under `--vt` alone, and 80 once a maximally
malicious Shodan result is added. Compare scores only between runs that used the same
set of sources, and read the per-source detail rather than the number alone.

---

## Requirements

- Python 3.8+
- `requests`
- `colorama` (optional, for colored output)

---

## License

MIT. See [LICENSE](LICENSE).

---

*by [0xPersist](https://github.com/0xPersist)*
