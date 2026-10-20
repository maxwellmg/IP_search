from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from concurrent.futures import ThreadPoolExecutor

from . import dns_checks, geo, heuristics, lists, local, registry
from .compare import Claims, evaluate
from .model import Section
from .report import render_text


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="ip-intel",
        description="Everything knowable from an IP address, with the source of every value labeled.")
    p.add_argument("ips", nargs="+", help="one or more IPv4/IPv6 addresses")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("--offline", action="store_true",
                   help="only compute from the address bits (no DNS, no third parties)")
    p.add_argument("--no-third-party", action="store_true",
                   help="skip commercial geolocation APIs (keeps DNS, RDAP, RIPEstat, published lists)")
    p.add_argument("--skip-icloud", action="store_true", help="skip the ~10MB iCloud Private Relay list")
    p.add_argument("--mmdb", help="path to a MaxMind GeoLite2-City.mmdb (needs `pip install maxminddb`)")
    p.add_argument("--no-sources", action="store_true", help="omit the source legend from text output")
    g = p.add_argument_group("claimed details to check for incongruities")
    g.add_argument("--claimed-country", help="ISO 3166-1 alpha-2 code, e.g. US")
    g.add_argument("--claimed-region", help="state/province name")
    g.add_argument("--claimed-city")
    g.add_argument("--claimed-timezone", help="IANA tz from the device/browser, e.g. America/Chicago")
    g.add_argument("--claimed-isp", help="e.g. 'Comcast'")
    g.add_argument("--claimed-latlon", help="'lat,lon' from billing/shipping geocode or device GPS")
    a = p.parse_args(argv)

    lat = lon = None
    if a.claimed_latlon:
        lat, lon = (float(x) for x in a.claimed_latlon.split(","))
    claims = Claims(a.claimed_country, a.claimed_region, a.claimed_city, a.claimed_timezone,
                    a.claimed_isp, lat, lon)

    results = []
    for raw_ip in a.ips:
        try:
            ip = ipaddress.ip_address(raw_ip.strip().strip("[]"))
        except ValueError:
            print(f"error: '{raw_ip}' is not a valid IP address", file=sys.stderr)
            continue
        results.append(investigate(ip, claims, a))

    if a.json:
        print(json.dumps(results if len(results) > 1 else results[0], indent=2, default=str))
    else:
        for r in results:
            print(render_text(r, show_sources=not a.no_sources))


def investigate(ip, claims: Claims, a) -> dict:
    sections: dict[str, Section] = {}
    loc = local.analyze(ip)
    sections[loc.title] = loc

    if not a.offline and loc.raw["scope"].startswith("global"):
        tasks = {
            "Reverse DNS": lambda: dns_checks.reverse_dns(ip),
            "DNS blocklists": lambda: dns_checks.dnsbl(ip),
            "Registration (RDAP)": lambda: registry.rdap(ip),
            "Routing (BGP)": lambda: registry.bgp(ip),
            "Published IP lists": lambda: lists.check(ip, a.skip_icloud),
        }
        if not a.no_third_party:
            tasks |= {
                "Geolocation: ip-api.com": lambda: geo.ipapi(ip),
                "Geolocation: ipinfo.io": lambda: geo.ipinfo(ip),
                "Geolocation: ipwho.is": lambda: geo.ipwhois(ip),
            }
        if a.mmdb:
            tasks["Geolocation: MaxMind (local)"] = lambda: geo.maxmind(ip, a.mmdb)

        with ThreadPoolExecutor(max_workers=len(tasks)) as pool:
            futures = {title: pool.submit(fn) for title, fn in tasks.items()}
            for title, fut in futures.items():
                try:
                    sections[title] = fut.result(timeout=60)
                except Exception as e:
                    sec = Section(title)
                    sec.errors.append(f"{type(e).__name__}: {e}")
                    sections[title] = sec

        org_texts = [s.raw.get("org_text", "") for s in sections.values()]
        org_texts += sections["Routing (BGP)"].raw.get("as_holders", [])
        org_texts.append(sections["Registration (RDAP)"].raw.get("network_name", ""))
        h = heuristics.classify(sections["Reverse DNS"].raw.get("ptr"), org_texts)
        sections[h.title] = h

    signals = evaluate(sections, claims)
    return {
        "ip": str(ip),
        "claims": {k: v for k, v in vars(claims).items() if v is not None},
        "signals": [vars(s) for s in signals],
        "sections": [s.to_dict() for s in sections.values()],
    }


if __name__ == "__main__":
    main()
