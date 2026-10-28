#!/usr/bin/env python3
"""Standalone offline IP intelligence script.

Usage:
  python offline_ipintel.py --ips 203.0.113.7 198.51.100.4
  python offline_ipintel.py --file ips.txt
  python offline_ipintel.py --csv ips.csv --ip-column ip --csv-output results.csv
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import sys
from typing import Iterable


def analyze_ip(ip_text: str) -> dict:
    ip = ipaddress.ip_address(ip_text.strip().strip("[]"))
    raw = {
        "ip": str(ip),
        "version": f"IPv{ip.version}",
        "canonical": ip.compressed,
        "reverse_dns_name": ip.reverse_pointer,
        "scope": classify_scope(ip),
    }

    if ip.version == 6:
        raw["exploded"] = ip.exploded
        raw["subscriber_prefix"] = str(ipaddress.ip_network(f"{ip}/64", strict=False))
        raw["interface_id"] = ip.exploded[20:]
        embedded = embedded_ipv4(ip)
        if embedded is not None:
            raw["embedded_ipv4"] = str(embedded)
    else:
        raw["containing_prefix"] = str(ipaddress.ip_network(f"{ip}/24", strict=False))

    signals = []
    scope = raw["scope"]
    if scope != "global":
        signals.append({
            "severity": "high",
            "message": f"Address is {scope}; it cannot be a real public client IP.",
            "evidence": ["iana-special"],
        })

    if "embedded_ipv4" in raw:
        signals.append({
            "severity": "info",
            "message": f"IP embeds IPv4 {raw['embedded_ipv4']}; analyze that address too.",
            "evidence": ["rfc-format"],
        })

    return {
        "ip": raw["ip"],
        "signals": signals,
        "sections": [{
            "title": "Address structure (offline)",
            "raw": raw,
        }],
    }


def classify_scope(ip: ipaddress._BaseAddress) -> str:
    if ip.is_unspecified:
        return "unspecified"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.is_multicast:
        return "multicast"
    if ip.version == 6 and ip.teredo:
        return "global (Teredo tunnel)"
    if ip.version == 6 and ip.sixtofour:
        return "global (6to4 tunnel)"
    if ip.version == 4 and ip in ipaddress.ip_network("100.64.0.0/10"):
        return "shared (carrier-grade NAT, RFC 6598)"
    if ip.is_private:
        return "private (RFC 1918 / ULA / documentation / reserved)"
    if ip.is_reserved:
        return "reserved"
    if ip.is_global:
        return "global"
    return "non-global special-purpose"


def embedded_ipv4(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    if ip.ipv4_mapped:
        return ip.ipv4_mapped
    if ip.sixtofour:
        return ip.sixtofour
    if ip.teredo:
        _, client = ip.teredo
        return client
    if ip in ipaddress.ip_network("64:ff9b::/96"):
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return None


def parse_ips(values: Iterable[str]) -> list[str]:
    ips = []
    for raw in values:
        for item in str(raw).split(","):
            item = item.strip()
            if not item:
                continue
            ips.append(item)
    return ips


def csv_ip_column(fieldnames: list[str] | None, override: str | None) -> str | None:
    if override:
        return override
    if not fieldnames:
        return None
    lowered = {name.strip().lower(): name for name in fieldnames}
    for candidate in ("ip", "ip_address", "ipaddr", "address"):
        if candidate in lowered:
            return lowered[candidate]
    return fieldnames[0]


def process_csv_file(csv_path: str, ip_column: str | None, output_path: str | None) -> int:
    with open(csv_path, "r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = reader.fieldnames or []
        chosen = csv_ip_column(fieldnames, ip_column)
        if chosen is None:
            print("error: no IP column found in CSV header; use --ip-column or include ip/ip_address/address", file=sys.stderr)
            return 2

        rows = []
        for row in reader:
            ip_text = (row.get(chosen) or "").strip()
            if not ip_text:
                continue
            try:
                result = analyze_ip(ip_text)
            except ValueError:
                print(f"error: '{ip_text}' is not a valid IP address", file=sys.stderr)
                continue

            merged = dict(row)
            merged["scope"] = result["sections"][0]["raw"]["scope"]
            merged["version"] = result["sections"][0]["raw"].get("version", "")
            merged["signals"] = "; ".join(f"{sig['severity']}:{sig['message']}" for sig in result["signals"])
            rows.append(merged)

        out_fieldnames = list(fieldnames)
        for extra in ("scope", "version", "signals"):
            if extra not in out_fieldnames:
                out_fieldnames.append(extra)

        if output_path:
            with open(output_path, "w", encoding="utf-8", newline="") as out_handle:
                writer = csv.DictWriter(out_handle, fieldnames=out_fieldnames)
                writer.writeheader()
                writer.writerows(rows)
            print(f"wrote {len(rows)} rows to {output_path}")
        else:
            writer = csv.DictWriter(sys.stdout, fieldnames=out_fieldnames)
            writer.writeheader()
            writer.writerows(rows)

        return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Standalone offline IP analysis")
    parser.add_argument("--ips", nargs="*", help="IP addresses to analyze")
    parser.add_argument("--file", help="Path to a text file with one IP address per line")
    parser.add_argument("--csv", help="Path to a CSV file containing an IP column")
    parser.add_argument("--ip-column", help="CSV column name holding the IP address (default: ip or ip_address)")
    parser.add_argument("--csv-output", help="Optional output CSV file for CSV mode")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    if args.csv:
        return process_csv_file(args.csv, args.ip_column, args.csv_output)

    if not args.ips and not args.file:
        parser.error("provide --ips, --file, or --csv")

    ip_values = []
    if args.ips:
        ip_values.extend(parse_ips(args.ips))
    if args.file:
        with open(args.file, "r", encoding="utf-8") as handle:
            ip_values.extend(parse_ips(handle.readlines()))

    results = []
    for ip_text in ip_values:
        try:
            results.append(analyze_ip(ip_text))
        except ValueError:
            print(f"error: '{ip_text}' is not a valid IP address", file=sys.stderr)

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for item in results:
            print(f"IP: {item['ip']}")
            print(f"Scope: {item['sections'][0]['raw']['scope']}")
            for sig in item['signals']:
                print(f"- [{sig['severity']}] {sig['message']}")
            print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
