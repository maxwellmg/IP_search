from __future__ import annotations

import ipaddress
import socket

from .model import Section

DNSBLS = {
    "zen.spamhaus.org": {"v6": True},
    "bl.spamcop.net": {"v6": False},
    "dnsbl.dronebl.org": {"v6": True},
}

SPAMHAUS_CODES = {
    "127.0.0.2": "SBL (spam source)",
    "127.0.0.3": "SBL CSS (snowshoe spam)",
    "127.0.0.4": "XBL (exploited/botnet/open proxy)",
    "127.0.0.9": "SBL DROP (hijacked netblock)",
    "127.0.0.10": "PBL (ISP says: end-user IP, shouldn't send mail directly)",
    "127.0.0.11": "PBL (Spamhaus-maintained end-user range)",
}

DRONEBL_CODES = {
    "127.0.0.3": "IRC drone", "127.0.0.5": "bottler", "127.0.0.6": "unknown spambot/drone",
    "127.0.0.7": "DDoS drone", "127.0.0.8": "SOCKS proxy", "127.0.0.9": "HTTP proxy",
    "127.0.0.10": "proxychain", "127.0.0.11": "web page proxy", "127.0.0.13": "brute force",
    "127.0.0.14": "open wingate", "127.0.0.15": "compromised router", "127.0.0.17": "auto-rooting worm",
    "127.0.0.19": "abused VPN service",
}


def reverse_dns(ip) -> Section:
    s = Section("Reverse DNS")
    try:
        host, aliases, _ = socket.gethostbyaddr(str(ip))
    except (socket.herror, socket.gaierror):
        s.add("ptr", "(none)", "dns-ptr", "No PTR record. Common for hosting, VPN, and some mobile IPs.")
        return s
    s.add("ptr", host, "dns-ptr")
    s.raw["ptr"] = host
    try:
        forward = {ai[4][0] for ai in socket.getaddrinfo(host, None)}
        confirmed = str(ip) in forward
    except socket.gaierror:
        forward, confirmed = set(), False
    s.add("fcrdns", "confirmed" if confirmed else "NOT confirmed", "dns-fcrdns",
          "" if confirmed else f"The PTR name resolves to {sorted(forward) or 'nothing'}.")
    s.raw["fcrdns"] = confirmed
    return s


def dnsbl(ip) -> Section:
    s = Section("DNS blocklists")
    if ip.version == 4:
        rev = ".".join(reversed(str(ip).split(".")))
    else:
        rev = ".".join(reversed(ip.exploded.replace(":", "")))
    listed = []
    for zone, opts in DNSBLS.items():
        if ip.version == 6 and not opts["v6"]:
            continue
        try:
            codes = sorted({ai[4][0] for ai in socket.getaddrinfo(f"{rev}.{zone}", None, socket.AF_INET)})
        except socket.gaierror:
            s.add(zone, "not listed", "dnsbl")
            continue
        if any(c.startswith("127.255.255.") for c in codes):
            s.add(zone, "query refused", "dnsbl",
                  "Spamhaus blocks public/open resolvers. Run this from a network with its own resolver.")
            continue
        table = SPAMHAUS_CODES if "spamhaus" in zone else DRONEBL_CODES if "dronebl" in zone else {}
        meaning = ", ".join(table.get(c, c) for c in codes)
        s.add(zone, f"LISTED: {meaning}", "dnsbl")
        listed.append((zone, codes, meaning))
    s.raw["listed"] = listed
    return s
