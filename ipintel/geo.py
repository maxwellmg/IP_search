"""Third-party geolocation estimates. Each provider is kept separate so they can be compared."""
from __future__ import annotations

import os

from .model import Section
from .net import get_json


def ipapi(ip) -> Section:
    s = Section("Geolocation: ip-api.com")
    fields = ("status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,"
              "isp,org,as,asname,mobile,proxy,hosting")
    d, _ = get_json(f"http://ip-api.com/json/{ip}?fields={fields}")
    if d.get("status") != "success":
        s.errors.append(d.get("message", "lookup failed"))
        return s
    _common(s, "geo-ipapi", d.get("countryCode"), d.get("regionName"), d.get("city"),
            d.get("zip"), d.get("lat"), d.get("lon"), d.get("timezone"))
    s.add("isp", d.get("isp"), "geo-ipapi")
    s.add("org", d.get("org"), "geo-ipapi")
    s.add("as", d.get("as"), "geo-ipapi")
    for flag in ("proxy", "hosting", "mobile"):
        s.add(f"flag_{flag}", str(d.get(flag)).lower(), "geo-ipapi")
        s.raw[flag] = d.get(flag)
    s.raw["org_text"] = " ".join(filter(None, [d.get("isp"), d.get("org"), d.get("asname")]))
    return s


def ipinfo(ip) -> Section:
    s = Section("Geolocation: ipinfo.io")
    token = os.environ.get("IPINFO_TOKEN")
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    d, _ = get_json(f"https://ipinfo.io/{ip}/json", headers)
    if d.get("bogon"):
        s.errors.append("bogon address")
        return s
    lat, lon = (d.get("loc") or ",").split(",")
    _common(s, "geo-ipinfo", d.get("country"), d.get("region"), d.get("city"),
            d.get("postal"), _f(lat), _f(lon), d.get("timezone"))
    s.add("org", d.get("org"), "geo-ipinfo")
    if "privacy" in d:  # paid tier only
        for k, v in d["privacy"].items():
            s.add(f"privacy_{k}", v, "geo-ipinfo")
    s.raw["org_text"] = d.get("org") or ""
    return s


def ipwhois(ip) -> Section:
    s = Section("Geolocation: ipwho.is")
    d, _ = get_json(f"https://ipwho.is/{ip}")
    if not d.get("success"):
        s.errors.append(d.get("message", "lookup failed"))
        return s
    _common(s, "geo-ipwhois", d.get("country_code"), d.get("region"), d.get("city"),
            d.get("postal"), d.get("latitude"), d.get("longitude"),
            (d.get("timezone") or {}).get("id"))
    conn = d.get("connection") or {}
    s.add("isp", conn.get("isp"), "geo-ipwhois")
    s.add("org", conn.get("org"), "geo-ipwhois")
    s.add("asn", conn.get("asn"), "geo-ipwhois")
    s.raw["org_text"] = " ".join(filter(None, [conn.get("isp"), conn.get("org")]))
    return s


def maxmind(ip, mmdb_path: str) -> Section:
    s = Section("Geolocation: MaxMind (local)")
    import maxminddb  # optional dependency

    with maxminddb.open_database(mmdb_path) as db:
        d = db.get(str(ip)) or {}
    loc = d.get("location", {})
    _common(s, "geo-maxmind", d.get("country", {}).get("iso_code"),
            ((d.get("subdivisions") or [{}])[0].get("names") or {}).get("en"),
            (d.get("city", {}).get("names") or {}).get("en"),
            d.get("postal", {}).get("code"), loc.get("latitude"), loc.get("longitude"),
            loc.get("time_zone"))
    s.add("accuracy_radius_km", loc.get("accuracy_radius"), "geo-maxmind")
    s.add("registered_country", d.get("registered_country", {}).get("iso_code"), "geo-maxmind")
    return s


def _common(s, src, country, region, city, postal, lat, lon, tz):
    s.add("country", country, src)
    s.add("region", region, src)
    s.add("city", city, src, "City-level IP geolocation is frequently off by 50km or more.")
    s.add("postal", postal, src)
    if lat is not None and lon is not None:
        s.add("lat_lon", f"{lat}, {lon}", src)
    s.add("timezone", tz, src)
    s.raw.update(country=(country or "").upper() or None, region=region, city=city,
                 lat=lat, lon=lon, timezone=tz)


def _f(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return None
