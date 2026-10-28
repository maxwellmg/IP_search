"""Turn collected facts into fraud signals: intrinsic red flags, cross-source disagreement,
and mismatches against details the user claimed."""
from __future__ import annotations

import math
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .model import Section, Signal

GEO_SOURCES = {"Geolocation: ip-api.com": "geo-ipapi", "Geolocation: ipinfo.io": "geo-ipinfo",
               "Geolocation: ipwho.is": "geo-ipwhois", "Geolocation: MaxMind (local)": "geo-maxmind"}


@dataclass
class Claims:
    country: str | None = None
    region: str | None = None
    city: str | None = None
    timezone: str | None = None
    isp: str | None = None
    lat: float | None = None
    lon: float | None = None

    def any(self):
        return any(v is not None for v in vars(self).values())


def evaluate(sections: dict[str, Section], claims: Claims) -> list[Signal]:
    sig: list[Signal] = []
    raw = {t: s.raw for t, s in sections.items()}
    local = raw.get("Address structure (offline)", {})
    lists = raw.get("Published IP lists", {})
    heur = raw.get("Connection-type heuristics", {})
    rdns = raw.get("Reverse DNS", {})
    bl = raw.get("DNS blocklists", {})
    bgp = raw.get("Routing (BGP)", {})
    rdap = raw.get("Registration (RDAP)", {})
    geos = {GEO_SOURCES[t]: r for t, r in raw.items() if t in GEO_SOURCES and r.get("country")}
    ipapi = raw.get("Geolocation: ip-api.com", {})

    # --- intrinsic -----------------------------------------------------------
    scope = local.get("scope")
    if scope and not scope.startswith("global"):
        sig.append(Signal("high", f"Address is {scope}; it cannot be a real public client IP.", ["iana-special"]))
    if local.get("embedded_ipv4"):
        sig.append(Signal("info", f"IPv6 embeds IPv4 {local['embedded_ipv4']}; analyze that too.", ["rfc-format"]))
    if lists.get("tor"):
        sig.append(Signal("high", "Tor exit node.", ["tor-exits"]))
    if lists.get("cloud"):
        sig.append(Signal("high", f"Inside published cloud/CDN ranges: {', '.join(lists['cloud'])}. "
                                  "Consumers don't normally browse from these.", ["cloud-ranges"]))
    if lists.get("icloud"):
        sig.append(Signal("info", "iCloud Private Relay. The real IP is hidden but this is usually "
                                  "a legitimate Apple user, and the region is roughly right.", ["icloud-relay"]))
    if ipapi.get("proxy"):
        sig.append(Signal("medium", "ip-api.com flags this IP as proxy/VPN.", ["geo-ipapi"]))
    if ipapi.get("hosting"):
        sig.append(Signal("medium", "ip-api.com flags this IP as hosting/datacenter.", ["geo-ipapi"]))
    if heur.get("vpn"):
        sig.append(Signal("medium", "VPN/proxy keywords in network names.", ["heuristic"]))
    if heur.get("hosting") and not lists.get("cloud"):
        sig.append(Signal("low", "Hosting-provider keywords in AS/org/PTR names.", ["heuristic"]))
    for zone, _, meaning in bl.get("listed", []):
        pbl_only = "PBL" in meaning and "SBL" not in meaning and "XBL" not in meaning
        sev = "info" if pbl_only else "medium"
        note = " (PBL means an ordinary end-user IP, which mildly supports 'residential')" if pbl_only else ""
        sig.append(Signal(sev, f"Listed on {zone}: {meaning}{note}", ["dnsbl"]))
    if bgp and not bgp.get("asns"):
        sig.append(Signal("high", "IP is not announced in BGP: unroutable on the public internet.", ["ripestat-bgp"]))
    if rdns.get("ptr") and rdns.get("fcrdns") is False:
        sig.append(Signal("low", "PTR hostname does not forward-confirm.", ["dns-fcrdns"]))
    if rdap.get("registered"):
        try:
            age = (datetime.now(timezone.utc) - datetime.fromisoformat(rdap["registered"].replace("Z", "+00:00"))).days
            if age < 180:
                sig.append(Signal("low", f"Address block registered only {age} days ago; geo databases "
                                         "may not have caught up yet.", ["rdap"]))
        except ValueError:
            pass

    # --- cross-source disagreement ---------------------------------------------
    countries = {src: g["country"] for src, g in geos.items()}
    if len(set(countries.values())) > 1:
        sig.append(Signal("medium", f"Geolocation providers disagree on country: {_fmt(countries)}. "
                                    "Typical of VPN egress, mobile carriers, or recently moved ranges.",
                          list(countries)))
    pts = [(src, g["lat"], g["lon"]) for src, g in geos.items() if g.get("lat") is not None]
    spread = max((_km(a[1], a[2], b[1], b[2]), a[0], b[0]) for a in pts for b in pts) if len(pts) > 1 else None
    if spread and spread[0] > 500:
        sig.append(Signal("low", f"Geolocation estimates are {spread[0]:.0f} km apart ({spread[1]} vs {spread[2]}).",
                          [spread[1], spread[2]]))
    geo_majority = _majority(countries.values())
    for label, val, src in (("RDAP registration", rdap.get("country"), "rdap"),
                            ("RIR delegation", bgp.get("rir_country"), "ripestat-rir")):
        if val and geo_majority and val.upper() != geo_majority:
            sig.append(Signal("info", f"{label} country {val} differs from geolocated country {geo_majority}. "
                                      "This is common for multinational ISPs and hosting, and is often seen on VPN egress.",
                              [src] + list(countries)))

    # --- versus claims --------------------------------------------------------------
    if claims.country:
        c = claims.country.upper()
        hits = {s: v for s, v in countries.items() if v == c}
        if countries and not hits:
            sig.append(Signal("high", f"Claimed country {c} matches no geolocation provider: {_fmt(countries)}.",
                              list(countries)))
        elif countries and len(hits) < len(countries):
            sig.append(Signal("low", f"Claimed country {c} matches only some providers: {_fmt(countries)}.",
                              list(countries)))
        if rdap.get("country") and rdap["country"].upper() != c and not hits:
            sig.append(Signal("low", f"Claimed country {c} also differs from RDAP registration {rdap['country']}.", ["rdap"]))

    if claims.region:
        _text_claim(sig, "region", claims.region, {s: g.get("region") for s, g in geos.items()})
    if claims.city:
        _text_claim(sig, "city", claims.city, {s: g.get("city") for s, g in geos.items()}, severity="low",
                    extra=" (city-level geo is unreliable; weigh lightly)")

    if claims.timezone:
        try:
            claimed_off = _utc_offset(claims.timezone)
        except ZoneInfoNotFoundError:
            sig.append(Signal("info", f"Unknown IANA timezone '{claims.timezone}'.", []))
            claimed_off = None
        if claimed_off is not None:
            geo_offs = {}
            for s, g in geos.items():
                try:
                    geo_offs[s] = (g["timezone"], _utc_offset(g["timezone"]))
                except (ZoneInfoNotFoundError, KeyError, TypeError, ValueError):
                    pass
            if geo_offs and all(off != claimed_off for _, off in geo_offs.values()):
                desc = ", ".join(f"{s}={tz} (UTC{off:+.1f})" for s, (tz, off) in geo_offs.items())
                sig.append(Signal("high", f"Claimed/device timezone {claims.timezone} (UTC{claimed_off:+.1f}) "
                                          f"does not match the IP's timezone: {desc}. A classic VPN/proxy tell.",
                                  list(geo_offs)))

    if claims.lat is not None and claims.lon is not None and pts:
        dists = {s: _km(claims.lat, claims.lon, la, lo) for s, la, lo in pts}
        nearest = min(dists.values())
        if nearest > 300:
            sev = "high" if nearest > 1500 else "medium"
            sig.append(Signal(sev, f"Claimed coordinates are {nearest:.0f} km or more from every IP geolocation estimate.",
                              list(dists)))

    if claims.isp:
        org_texts = [t for t in (raw.get(k, {}).get("org_text") for k in GEO_SOURCES) if t]
        org_texts += bgp.get("as_holders", []) + [rdap.get("registrant", ""), rdap.get("network_name", "")]
        blob = " ".join(org_texts).lower()
        tokens = [t for t in re.split(r"\W+", claims.isp.lower()) if len(t) >= 2]
        if blob and tokens and not any(re.search(rf"\b{re.escape(t)}\b", blob) for t in tokens):
            sig.append(Signal("medium", f"Claimed ISP '{claims.isp}' does not appear in any AS/org/registrant name.",
                              ["ripestat-bgp", "rdap"] + list(geos)))

    if claims.any() and not geos:
        sig.append(Signal("info", "No geolocation data available to check the claims against.", []))
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    return sorted(sig, key=lambda x: order[x.severity])


def _text_claim(sig, label, claimed, values, severity="medium", extra=""):
    values = {s: v for s, v in values.items() if v}
    if not values:
        return
    cl = claimed.strip().lower()
    if not any(cl in v.lower() or v.lower() in cl for v in values.values()):
        sig.append(Signal(severity, f"Claimed {label} '{claimed}' matches no provider: {_fmt(values)}{extra}.",
                          list(values)))


def _utc_offset(tz: str) -> float:
    return datetime.now(ZoneInfo(tz)).utcoffset().total_seconds() / 3600


def _km(lat1, lon1, lat2, lon2):
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 6371 * 2 * math.asin(math.sqrt(a))


def _majority(vals):
    vals = list(vals)
    return max(set(vals), key=vals.count) if vals else None


def _fmt(d):
    return ", ".join(f"{k}={v}" for k, v in d.items())
