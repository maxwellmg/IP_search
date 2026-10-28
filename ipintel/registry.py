"""Registration (RDAP) and routing (BGP via RIPEstat) data."""
from __future__ import annotations

from urllib.parse import urlparse

from .model import Section
from .net import get_json

RIPESTAT = "https://stat.ripe.net/data/{}/data.json?resource={}&sourceapp=ip-intel"


def rdap(ip) -> Section:
    s = Section("Registration (RDAP)")
    data, final_url = get_json(f"https://rdap.org/ip/{ip}")
    registry = urlparse(final_url).hostname
    s.add("served_by", registry, "rdap", "The RIR that answered after the rdap.org redirect.")
    s.add("handle", data.get("handle"), "rdap")
    s.add("network_name", data.get("name"), "rdap")
    s.add("block", f"{data.get('startAddress')} - {data.get('endAddress')}", "rdap")
    s.add("type", data.get("type"), "rdap")
    s.add("registration_country", data.get("country"), "rdap",
          "Where the block holder registered. This is NOT the user's location.")
    s.add("parent_handle", data.get("parentHandle"), "rdap")
    for ev in data.get("events", []):
        if ev.get("eventAction") in ("registration", "last changed"):
            s.add(ev["eventAction"].replace(" ", "_"), ev.get("eventDate", "")[:10], "rdap")

    orgs, abuse = [], []
    for ent in _walk_entities(data.get("entities", [])):
        name, emails = _vcard(ent)
        roles = ent.get("roles", [])
        if "abuse" in roles:
            abuse += emails
        if {"registrant", "administrative"} & set(roles) and name:
            orgs.append(name)
    s.add("registrant", "; ".join(dict.fromkeys(orgs)), "rdap")
    s.add("abuse_contact", ", ".join(dict.fromkeys(abuse)), "rdap")
    for r in data.get("remarks", []):
        txt = " ".join(r.get("description", []))
        if txt and len(txt) < 300:
            s.add("remark", txt, "rdap")

    s.raw.update(country=data.get("country"), registrant=" ".join(orgs),
                 network_name=data.get("name") or "",
                 registered=next((e.get("eventDate") for e in data.get("events", [])
                                  if e.get("eventAction") == "registration"), None))
    return s


def _walk_entities(ents):
    for e in ents:
        yield e
        yield from _walk_entities(e.get("entities", []))


def _vcard(ent):
    name, emails = None, []
    for item in (ent.get("vcardArray") or [None, []])[1]:
        if item[0] == "fn":
            name = item[3]
        elif item[0] == "email":
            emails.append(item[3])
    return name, emails


def bgp(ip) -> Section:
    s = Section("Routing (BGP)")
    info = get_json(RIPESTAT.format("network-info", ip))[0]["data"]
    asns = info.get("asns", [])
    s.add("announced_prefix", info.get("prefix"), "ripestat-bgp",
          "The routed block this IP belongs to, as seen in global BGP tables.")
    s.raw["prefix"] = info.get("prefix")
    s.raw["asns"] = asns
    if not asns:
        s.add("origin_asn", "(not announced)", "ripestat-bgp",
              "No route on the public internet. Unusual for a real client IP.")
    holders = []
    for asn in asns:
        ov = get_json(RIPESTAT.format("as-overview", f"AS{asn}"))[0]["data"]
        holders.append(ov.get("holder", ""))
        s.add(f"origin_AS{asn}", ov.get("holder"), "ripestat-bgp")
    s.raw["as_holders"] = holders

    rir = get_json(RIPESTAT.format("rir-stats-country", ip))[0]["data"]
    locs = {r.get("location") for r in rir.get("located_resources", []) if r.get("location")}
    s.add("rir_delegation_country", ", ".join(sorted(locs)), "ripestat-rir")
    s.raw["rir_country"] = next(iter(locs), None) if len(locs) == 1 else None
    return s
