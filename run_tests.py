#!/usr/bin/env python3
"""
ioc-pivot regression tests.

The composite threat score used to be the arithmetic mean of the sub-scores of
whichever sources were queried. Because Shodan and OTX are capped below 100,
adding a corroborating source could pull the average *down*: an IOC that
VirusTotal rated maximally malicious scored 100 alone and 80 once a maximally
malicious Shodan result was added. That inverts what corroboration means.

These pin the replacement model. Every case calls threat_score() directly with
synthetic source dicts, so the suite makes no network calls and needs no keys.
"""
from __future__ import annotations

import itertools
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ioc_pivot import threat_score  # noqa: E402

_passed = 0
_failed = 0


def check(label: str, cond: bool) -> None:
    global _passed, _failed
    if cond:
        _passed += 1
        print(f"  [PASS] {label}")
    else:
        _failed += 1
        print(f"  [FAIL] {label}")


def vt(malicious: int, harmless: int = 0) -> dict:
    return {"malicious": malicious, "suspicious": 0,
            "harmless": harmless, "undetected": 0}


# Maximal per-source signals: each of these alone pins its sub-score to its cap.
VT_MAX  = vt(90)
AB_MAX  = {"abuse_score": 100}
SH_MAX  = {"vulns": ["CVE-2021-1", "CVE-2021-2", "CVE-2021-3", "CVE-2021-4"]}
OTX_MAX = {"pulse_count": 8}

# Sources that returned data and found nothing.
VT_CLEAN  = vt(0, harmless=90)
AB_CLEAN  = {"abuse_score": 0}
SH_CLEAN  = {"vulns": []}
OTX_CLEAN = {"pulse_count": 0}


def main() -> int:
    print("T1: adding a source never lowers the score")
    # Every ordered accumulation of the four maximal sources, checked stepwise.
    sources = [("virustotal", VT_MAX), ("abuseipdb", AB_MAX),
               ("shodan", SH_MAX), ("otx", OTX_MAX)]
    monotonic = True
    for order in itertools.permutations(sources):
        acc: dict = {}
        prev = threat_score(acc)
        for name, payload in order:
            acc[name] = payload
            cur = threat_score(acc)
            if cur < prev:
                monotonic = False
                print(f"    dropped {prev} -> {cur} after adding {name}")
            prev = cur
    check("malicious sources, every arrival order: never decreases", monotonic)

    # Mixed strengths, including weak and clean sources arriving late.
    mixed = [("virustotal", vt(30, harmless=60)), ("abuseipdb", {"abuse_score": 45}),
             ("shodan", {"vulns": ["CVE-2021-1"]}), ("otx", OTX_CLEAN)]
    monotonic = True
    for order in itertools.permutations(mixed):
        acc = {}
        prev = threat_score(acc)
        for name, payload in order:
            acc[name] = payload
            cur = threat_score(acc)
            if cur < prev:
                monotonic = False
            prev = cur
    check("mixed-strength sources, every arrival order: never decreases", monotonic)

    print("T2: one maximal source reaches 100")
    check("VirusTotal alone, every engine malicious", threat_score({"virustotal": VT_MAX}) == 100)
    check("AbuseIPDB alone, full confidence", threat_score({"abuseipdb": AB_MAX}) == 100)

    print("T3: four corroborating sources reach 100")
    all_four = {"virustotal": VT_MAX, "abuseipdb": AB_MAX,
                "shodan": SH_MAX, "otx": OTX_MAX}
    check("all four maximal", threat_score(all_four) == 100)
    # Capped sources cannot reach 100 alone, but together they must.
    capped = {"shodan": SH_MAX, "otx": OTX_MAX, "abuseipdb": {"abuse_score": 95},
              "virustotal": vt(80, harmless=10)}
    check("no single source at 100, corroboration carries it", threat_score(capped) == 100)

    print("T4: sources that all report clean score 0")
    clean = {"virustotal": VT_CLEAN, "abuseipdb": AB_CLEAN,
             "shodan": SH_CLEAN, "otx": OTX_CLEAN}
    check("four clean sources", threat_score(clean) == 0)
    check("no sources queried at all", threat_score({}) == 0)
    check("every source errored", threat_score({
        "virustotal": {"error": "rate limited"},
        "abuseipdb": {"error": "no key"},
    }) == 0)

    print("T5: one malicious source among clean ones lands between 0 and 100")
    lone = {"virustotal": vt(45, harmless=45), "abuseipdb": AB_CLEAN,
            "shodan": SH_CLEAN, "otx": OTX_CLEAN}
    score = threat_score(lone)
    check(f"one malicious + three clean scores {score}: above zero", score > 0)
    check(f"one malicious + three clean scores {score}: below full", score < 100)
    check("clean sources add no corroboration bonus",
          score == threat_score({"virustotal": vt(45, harmless=45)}))

    print("T6: the regression that prompted the model change")
    vt_only    = threat_score({"virustotal": VT_MAX})
    vt_shodan  = threat_score({"virustotal": VT_MAX, "shodan": SH_MAX})
    check("maximal VT plus maximal Shodan is not below VT alone", vt_shodan >= vt_only)

    print("T7: corroboration bonus is bounded and diminishing")
    # A weak-but-real signal from every source must not manufacture a top score.
    weak = {"virustotal": vt(5, harmless=85), "abuseipdb": {"abuse_score": 5},
            "shodan": {"vulns": ["CVE-2021-1"]}, "otx": {"pulse_count": 1}}
    score = threat_score(weak)
    check(f"four weak signals score {score}: stays well below a strong verdict", score < 50)
    # Sub-scores here are VT 5, AbuseIPDB 5, Shodan 15, OTX 10: the strongest
    # is 15, and three corroborating sources add the full 10 + 6 + 3 bonus.
    check("score is the strongest sub-score plus the full 19-point bonus",
          score == 15 + 10 + 6 + 3)

    print(f"\nRESULTS: {_passed} passed, {_failed} failed")
    return 1 if _failed else 0


if __name__ == "__main__":
    sys.exit(main())
