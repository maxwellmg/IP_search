"""Keyword guesses at connection type. This is the weakest evidence in the report; it is labeled as such."""
from __future__ import annotations

import re

from .model import Section

HOSTING = r"hosting|host|cloud|server|datacenter|data center|colo|vps|dedicated|amazon|aws|google|" \
          r"microsoft|azure|ovh|hetzner|digitalocean|linode|akamai|vultr|choopa|leaseweb|contabo|" \
          r"m247|scaleway|online s\.a\.s|hostinger|ionos|psychz|quadranet|cogent|zenlayer|alibaba|" \
          r"tencent|oracle|datacamp|cdn77|g-core|gcore|constant company|servers\.com|frantech|" \
          r"buyvm|kamatera|hostwinds|ucloud|worldstream|serverius|nforce|combahton"
VPN = r"vpn|nord|expressvpn|mullvad|proton|private internet access|surfshark|cyberghost|" \
      r"windscribe|ipvanish|hide\.?me|torguard|purevpn|hotspot shield|astrill|packethub|" \
      r"tunnelbear|privado|anonymous|proxy"
RESIDENTIAL_PTR = r"\b(dsl|adsl|vdsl|cable|dyn|dynamic|pool|dhcp|ppp|pppoe|fiber|fibre|ftth|fttx|" \
                  r"broadband|cpe|res|resi|residential|customer|cust|home|user|client|bb|catv|" \
                  r"ip-?\d+)\b"
MOBILE = r"mobile|lte|4g|5g|wireless|cellular|gprs|umts|mobil|tmobile|t-mobile|verizon wireless|" \
         r"vodafone|telefonica|orange|airtel|jio|cricket|metropcs"


def classify(ptr: str | None, org_texts: list[str]) -> Section:
    s = Section("Connection-type heuristics")
    ptr_l = (ptr or "").lower()
    orgs = " | ".join(t for t in org_texts if t).lower()
    s.raw["hosting"] = s.raw["vpn"] = s.raw["residential"] = s.raw["mobile"] = False

    for label, rx, haystack, where in (
        ("vpn", VPN, orgs + " " + ptr_l, "org/PTR"),
        ("hosting", HOSTING, orgs, "AS/org name"),
        ("hosting", r"\b(vps|server|srv|host|cloud|dedi|static\.\d+)", ptr_l, "PTR"),
        ("mobile", MOBILE, orgs + " " + ptr_l, "org/PTR"),
        ("residential", RESIDENTIAL_PTR, re.sub(r"[.\-_]", " ", ptr_l), "PTR"),
    ):
        m = re.search(rx, haystack)
        if m:
            s.raw[label] = True
            s.add(f"looks_{label}", f"keyword '{m.group(0)}' in {where}", "heuristic")

    if ptr_l and re.search(r"\d+[-.]\d+[-.]\d+[-.]\d+", ptr_l):
        s.add("ptr_embeds_ip", "yes", "heuristic",
              "Typical of ISP-generated PTRs for dynamic, mass-assigned subscriber IPs.")
    if not s.facts:
        s.add("guess", "no keyword matches", "heuristic")
    return s
