"""Facts derivable from the address bits alone, with no network access."""
from __future__ import annotations

import ipaddress

from .model import Section

CGNAT = ipaddress.ip_network("100.64.0.0/10")  # RFC 6598 shared address space
NAT64_WKP = ipaddress.ip_network("64:ff9b::/96")  # RFC 6052


def analyze(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> Section:
    s = Section("Address structure (offline)")
    s.add("version", f"IPv{ip.version}", "iana-special")
    s.add("canonical", ip.compressed, "iana-special")
    if ip.version == 6:
        s.add("exploded", ip.exploded, "iana-special")
    s.add("integer", int(ip), "iana-special")
    s.add("reverse_dns_name", ip.reverse_pointer, "iana-special")

    scope = classify_scope(ip)
    s.add("scope", scope, "iana-special",
          "" if scope == "global" else "Not a public internet address. Should never appear as a "
                                       "real client IP; a logging or proxy issue, or spoofed input.")
    s.raw["scope"] = scope

    # The conventional block a single subscriber typically gets.
    if ip.version == 4:
        s.add("containing_/24", str(ipaddress.ip_network(f"{ip}/24", strict=False)), "rfc-format",
              "Convention only; the routed prefix is in the BGP section.")
    else:
        s.add("subscriber_/64", str(ipaddress.ip_network(f"{ip}/64", strict=False)), "rfc-format",
              "A single household or device usually gets a whole /64. Compare IPv6 users at "
              "/64, not by full address.")
        s.add("interface_id", ip.exploded[20:], "rfc-format")
        _ipv6_embedded(ip, s)
    return s


def classify_scope(ip) -> str:
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
    if ip.version == 4 and ip in CGNAT:
        return "shared (carrier-grade NAT, RFC 6598)"
    if ip.is_private:
        return "private (RFC 1918 / ULA / documentation / reserved)"
    if ip.is_reserved:
        return "reserved"
    if ip.is_global:
        return "global"
    return "non-global special-purpose"


def _ipv6_embedded(ip: ipaddress.IPv6Address, s: Section):
    if ip.ipv4_mapped:
        s.add("embedded_ipv4 (mapped)", str(ip.ipv4_mapped), "rfc-format",
              "Really an IPv4 client. Analyze the IPv4 address instead.")
        s.raw["embedded_ipv4"] = ip.ipv4_mapped
    if ip.sixtofour:
        s.add("embedded_ipv4 (6to4, RFC 3056)", str(ip.sixtofour), "rfc-format",
              "Legacy tunnel; the embedded address is the client's public IPv4.")
        s.raw["embedded_ipv4"] = ip.sixtofour
    if ip.teredo:
        server, client = ip.teredo
        s.add("teredo_server", str(server), "rfc-format")
        s.add("embedded_ipv4 (Teredo client, RFC 4380)", str(client), "rfc-format",
              "The client's real public IPv4 behind NAT.")
        port = ~(int(ip) >> 32) & 0xFFFF
        s.add("teredo_client_port", port, "rfc-format")
        s.raw["embedded_ipv4"] = client
    if ip in NAT64_WKP:
        v4 = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
        s.add("embedded_ipv4 (NAT64, RFC 6052)", str(v4), "rfc-format")
        s.raw["embedded_ipv4"] = v4

    iid = ip.packed[8:]
    if iid[3] == 0xFF and iid[4] == 0xFE:
        mac = bytearray(iid[:3] + iid[5:])
        mac[0] ^= 0x02  # flip universal/local bit back
        mac_str = ":".join(f"{b:02x}" for b in mac)
        s.add("eui64_mac", mac_str, "rfc-format",
              "The interface ID encodes a hardware MAC address. The address is stable across "
              "networks, so the same device can be tracked. Look up the vendor from the first "
              "3 bytes (OUI) at https://regauth.standards.ieee.org/standards-ra-web/pub/view.html")
        s.add("eui64_oui", mac_str[:8], "rfc-format")
    elif not (ip.ipv4_mapped or ip.teredo or ip.sixtofour):
        s.add("interface_id_type", "random/privacy or manually assigned (not EUI-64)", "rfc-format")
