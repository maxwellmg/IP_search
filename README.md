# ip-intel

A one-off CLI that pulls together everything knowable from a single IP address. Every value it
outputs is labeled with the source it came from, so you can judge how much to trust it. It then
flags **incongruities**: between data sources, and between the IP and details a user claimed
(country, timezone, ISP, location). This is useful for fraud review.

Requires Python 3.10+, with no required dependencies.

```sh
python3.12 -m ipintel 203.0.113.7
python3.12 -m ipintel 203.0.113.7 \
    --claimed-country US --claimed-region Texas --claimed-city Austin \
    --claimed-timezone America/Chicago --claimed-isp "AT&T" \
    --claimed-latlon 30.27,-97.74
python3.12 -m ipintel 2001:db8::1 --offline        # address bits only, no network
python3.12 -m ipintel 198.51.100.4 --json           # machine-readable output
```

`--claimed-timezone` is the most useful claim to pass. Use the browser's
`Intl.DateTimeFormat().resolvedOptions().timeZone`. A device timezone that doesn't match the IP's
timezone is a classic VPN/proxy tell.

## Running the offline version in a Jupyter notebook

If you want to analyze a Python list of IP addresses with no API calls at all, call the library
from a notebook and set `offline=True`. This is equivalent to running the CLI with `--offline`.

```python
import ipaddress
from types import SimpleNamespace

from ipintel.cli import investigate
from ipintel.compare import Claims

ips = [
    "203.0.113.7",
    "198.51.100.4",
    "2001:db8::1",
]

opts = SimpleNamespace(
    offline=True,
    no_third_party=False,
    skip_icloud=False,
    mmdb=None,
    no_sources=False,
)

results = []
for raw_ip in ips:
    ip = ipaddress.ip_address(raw_ip.strip().strip("[]"))
    results.append(investigate(ip, Claims(), opts))

# Example: inspect the first result
print(results[0]["ip"])
print(results[0]["signals"])
print(results[0]["sections"][0]["title"])
```

This keeps the analysis limited to local address-structure checks (scope, embedded IPv4, reserved
space, etc.) and does not contact RDAP, RIPEstat, DNS, or third-party geo APIs. If you want to
compare the same list against claimed user details, pass a `Claims(...)` object with fields like
`country`, `region`, `city`, `timezone`, `isp`, `lat`, and `lon`.

## Output

1. **Signals**: potential fraud indicators ranked `high / medium / low / info`. Each one names
   the source ids it is based on.
2. **Sections**: the raw facts, each tagged `[source-id]`.
3. **Sources legend**: for every source used, how it was obtained, what it actually means, and
   its caveats.

## Data sources: what each component tells you

There are three very different kinds of "location" for an IP, and they routinely disagree for
legitimate reasons:

| Kind | Sources | Answers |
|---|---|---|
| **Registration** | RDAP, RIR delegation stats | Who owns the block, and where the owner registered it (administrative) |
| **Routing** | BGP via RIPEstat | Which network actually carries traffic for it today |
| **Geolocation** | ip-api, ipinfo, ipwho.is, MaxMind | A proprietary *estimate* of where the device physically is |

| Source id | What it is | How obtained | Trust |
|---|---|---|---|
| `iana-special` | IANA special-purpose registries (private, CGNAT, reserved…) | Computed locally | Definitional |
| `rfc-format` | Structure inside the address: Teredo/6to4/NAT64 embedded IPv4, EUI-64 MAC, /64 | Computed locally | Definitional |
| `dns-ptr` | Reverse DNS hostname | DNS | Set by the block owner; can be stale |
| `dns-fcrdns` | Whether the PTR hostname resolves back to the IP | DNS | Strong if confirmed |
| `dnsbl` | Spamhaus ZEN, SpamCop, DroneBL listings | DNS | Authoritative for their lists |
| `rdap` | Registered org, block, country, abuse contact, dates | HTTPS via rdap.org → the relevant RIR | Authoritative for *registration* |
| `ripestat-bgp` | Announced prefix, origin ASN, AS name | HTTPS, RIPEstat API | Authoritative for *routing* |
| `ripestat-rir` | Country in the RIR delegation file | HTTPS, RIPEstat API | Administrative only |
| `tor-exits` | Tor exit relay list | HTTPS, Tor Project (cached 6h) | Authoritative |
| `cloud-ranges` | AWS, GCP, Oracle, DigitalOcean, Cloudflare, Fastly ranges | HTTPS, published by the providers (cached 24h) | Authoritative |
| `icloud-relay` | Apple iCloud Private Relay egress ranges | HTTPS, published by Apple (cached 24h) | Authoritative |
| `geo-ipapi` | Geo estimate + proxy/hosting/mobile flags | **HTTP** (free tier is plaintext) | Estimate; black-box flags |
| `geo-ipinfo` | Geo estimate, org, timezone | HTTPS (`IPINFO_TOKEN` optional) | Estimate |
| `geo-ipwhois` | Geo estimate, ISP, timezone | HTTPS | Estimate |
| `geo-maxmind` | Geo estimate + accuracy radius | Local `.mmdb` (`--mmdb`, `pip install maxminddb`) | Estimate |
| `heuristic` | Hosting/VPN/residential/mobile keyword guesses | Regex on PTR and org names | Weakest evidence |
| `comparison` | Cross-source and claimed-vs-observed checks | This tool | Only as good as its inputs |

The full text of each source's meaning and caveats is in
[`ipintel/sources.py`](ipintel/sources.py) and appears in every report.

## Privacy and terms

- Default runs send the IP to rdap.org/RIRs, RIPEstat, ip-api.com, ipinfo.io and ipwho.is.
  `--no-third-party` skips the commercial geo APIs. `--offline` sends nothing.
- The free tiers of ip-api.com and ipwho.is are licensed for **non-commercial use**. For
  production fraud work, use paid keys or a local MaxMind database.
- Spamhaus refuses queries from public resolvers (8.8.8.8, 1.1.1.1…). Those show up as
  `query refused`, not as clean.
- Bulk lists are cached in `~/.cache/ip-intel` (override with `IPINTEL_CACHE`).

## What an IP can't tell you

It can't identify a person, prove a VPN isn't in use, or see behind a residential proxy (these
look like ordinary home connections). Mobile carrier IPs often geolocate to a regional gateway
hundreds of km from the user. Treat every signal as one input alongside device, account, and
payment data.

## Tests

```sh
python3.12 -m unittest discover tests   # offline only
```
