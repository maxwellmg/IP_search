"""Membership in authoritative published IP lists: Tor exits, cloud providers, iCloud Private Relay."""
from __future__ import annotations

import csv
import io
import ipaddress
import json

from .model import Section
from .net import get_cached

DAY = 86400


def _aws(body):
    d = json.loads(body)
    for p in d["prefixes"]:
        yield p["ip_prefix"], f"{p['service']} {p['region']}"
    for p in d["ipv6_prefixes"]:
        yield p["ipv6_prefix"], f"{p['service']} {p['region']}"


def _gcp(body):
    for p in json.loads(body)["prefixes"]:
        yield p.get("ipv4Prefix") or p.get("ipv6Prefix"), p.get("scope", "")


def _oracle(body):
    for r in json.loads(body)["regions"]:
        for c in r["cidrs"]:
            yield c["cidr"], r["region"]


def _csv_first_col(body):
    for row in csv.reader(io.StringIO(body.decode())):
        if row and not row[0].startswith("#"):
            yield row[0], " ".join(x for x in row[1:4] if x)


def _lines(body):
    for line in body.decode().split():
        yield line, ""


def _fastly(body):
    d = json.loads(body)
    for p in d.get("addresses", []) + d.get("ipv6_addresses", []):
        yield p, ""


CLOUD_LISTS = {
    "AWS": ("https://ip-ranges.amazonaws.com/ip-ranges.json", _aws),
    "Google Cloud": ("https://www.gstatic.com/ipranges/cloud.json", _gcp),
    "Oracle Cloud": ("https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json", _oracle),
    "DigitalOcean": ("https://digitalocean.com/geo/google.csv", _csv_first_col),
    "Cloudflare": ("https://www.cloudflare.com/ips-v4", _lines),
    "Cloudflare v6": ("https://www.cloudflare.com/ips-v6", _lines),
    "Fastly": ("https://api.fastly.com/public-ip-list", _fastly),
}

ICLOUD_RELAY = "https://mask-api.icloud.com/egress-ip-ranges.csv"
TOR_EXITS = "https://check.torproject.org/torbulkexitlist"


def _match(ip, entries):
    for cidr, label in entries:
        try:
            if ip in ipaddress.ip_network(cidr.strip(), strict=False):
                return cidr, label
        except ValueError:
            continue
    return None


def check(ip, skip_icloud=False) -> Section:
    s = Section("Published IP lists")
    try:
        exits = set(get_cached(TOR_EXITS, DAY // 4).decode().split())
        is_tor = str(ip) in exits
        s.add("tor_exit", "YES" if is_tor else "no", "tor-exits")
        s.raw["tor"] = is_tor
    except Exception as e:
        s.errors.append(f"Tor list: {e}")

    s.raw["cloud"] = []
    for provider, (url, parser) in CLOUD_LISTS.items():
        try:
            hit = _match(ip, parser(get_cached(url, DAY)))
        except Exception as e:
            s.errors.append(f"{provider}: {e}")
            continue
        if hit:
            s.add(f"cloud_{provider}", f"{hit[0]} {hit[1]}".strip(), "cloud-ranges")
            s.raw["cloud"].append(provider)
    if not s.raw["cloud"]:
        s.add("cloud_provider", "not in any published list checked", "cloud-ranges")

    if not skip_icloud:
        try:
            hit = _match(ip, _csv_first_col(get_cached(ICLOUD_RELAY, DAY)))
            s.add("icloud_private_relay", f"YES {hit[0]} ({hit[1]})" if hit else "no", "icloud-relay")
            s.raw["icloud"] = hit
        except Exception as e:
            s.errors.append(f"iCloud relay list: {e}")
    return s
