"""Registry of every data source the tool can draw on.

Each Fact in a report points at one of these ids, so the reader can see
exactly where a value came from and what that source actually measures.
"""

SOURCES = {
    # --- Computed locally, no network ---------------------------------------
    "iana-special": {
        "name": "IANA special-purpose address registries",
        "url": "https://www.iana.org/assignments/iana-ipv4-special-registry/ "
               "https://www.iana.org/assignments/iana-ipv6-special-registry/",
        "method": "computed locally (Python stdlib `ipaddress`, plus RFC 6598 CGNAT range)",
        "meaning": "Whether the address is private, loopback, reserved, shared (CGNAT), etc. "
                   "Deterministic: it follows from the address bits alone.",
        "caveat": "None. This is definitional, not observational.",
    },
    "rfc-format": {
        "name": "Address format RFCs (RFC 4291, 3056, 4380, 6052)",
        "url": "https://www.rfc-editor.org/rfc/rfc4291",
        "method": "computed locally from the address bits",
        "meaning": "Structure inside the address: IPv4 embedded in IPv6 (6to4, Teredo, NAT64, "
                   "mapped), or an EUI-64 interface ID that encodes a hardware MAC.",
        "caveat": "EUI-64 detection is a pattern match (ff:fe in the middle of the interface ID); "
                  "a random interface ID could match it by chance, though that is unlikely.",
    },
    # --- DNS ----------------------------------------------------------------
    "dns-ptr": {
        "name": "Reverse DNS (PTR record)",
        "url": "in-addr.arpa / ip6.arpa via this machine's resolver",
        "method": "DNS query",
        "meaning": "The hostname the owner of the IP block chose to publish. Often reveals the ISP "
                   "and the connection type (dsl, cable, mobile, static, vps...).",
        "caveat": "Set by whoever controls the reverse zone. It can be stale, generic, or "
                  "deliberately misleading. Check it against forward DNS (FCrDNS).",
    },
    "dns-fcrdns": {
        "name": "Forward-confirmed reverse DNS",
        "url": "A/AAAA lookup of the PTR hostname",
        "method": "DNS query",
        "meaning": "Whether the PTR hostname resolves back to the same IP. A match means the "
                   "hostname's owner also controls the forward zone.",
        "caveat": "Many legitimate residential ISPs do not set up FCrDNS.",
    },
    "dnsbl": {
        "name": "DNS blocklists (Spamhaus ZEN, SpamCop, DroneBL)",
        "url": "https://www.spamhaus.org/zen/ https://www.spamcop.net/ https://dronebl.org/",
        "method": "DNS query",
        "meaning": "Whether the IP is currently listed for spam, botnet, open proxy, or exploit "
                   "activity.",
        "caveat": "Spamhaus refuses queries sent through large public resolvers (8.8.8.8, 1.1.1.1). "
                  "These show up as 'query refused', not 'clean'. Listings change hourly.",
    },
    # --- Registry / routing ---------------------------------------------------
    "rdap": {
        "name": "RDAP (Regional Internet Registry registration data)",
        "url": "https://rdap.org/ (bootstrap that redirects to ARIN/RIPE/APNIC/LACNIC/AFRINIC)",
        "method": "HTTPS API",
        "meaning": "Who the address block is REGISTERED to: organization, network name, block "
                   "range, registration country, abuse contact, registration dates.",
        "caveat": "Registration country is where the holding organization registered, NOT where "
                  "the user is. A US company can hold blocks used in Germany.",
    },
    "ripestat-bgp": {
        "name": "RIPEstat network-info / as-overview (BGP routing data)",
        "url": "https://stat.ripe.net/docs/data_api",
        "method": "HTTPS API",
        "meaning": "Which Autonomous System (network) is actually ANNOUNCING the route for this IP "
                   "on the global internet right now, and that AS's registered name.",
        "caveat": "This is the network operator, which is not always the end ISP. Resellers and "
                  "VPN providers often run on rented space inside someone else's AS.",
    },
    "ripestat-rir": {
        "name": "RIPEstat rir-stats-country (RIR delegation statistics)",
        "url": "https://stat.ripe.net/docs/data_api#rir-stats-country",
        "method": "HTTPS API",
        "meaning": "The country the RIR recorded in its delegation file when it allocated the block.",
        "caveat": "Same as RDAP: an administrative country, not a physical location.",
    },
    # --- Commercial / community geolocation ----------------------------------
    "geo-ipapi": {
        "name": "ip-api.com (free tier)",
        "url": "http://ip-api.com/docs/api:json",
        "method": "HTTP API (the free tier is plaintext HTTP only)",
        "meaning": "An estimated geolocation, plus proprietary flags: proxy/VPN, hosting, mobile.",
        "caveat": "A proprietary estimate. City-level accuracy is often wrong by tens to hundreds "
                  "of km. The flags come from a black-box model. Free use is non-commercial only.",
    },
    "geo-ipinfo": {
        "name": "ipinfo.io",
        "url": "https://ipinfo.io/developers",
        "method": "HTTPS API (uses IPINFO_TOKEN env var if set)",
        "meaning": "An estimated geolocation, organization/ASN, and timezone.",
        "caveat": "A proprietary estimate. Without a token it is heavily rate-limited.",
    },
    "geo-ipwhois": {
        "name": "ipwho.is",
        "url": "https://ipwhois.io/documentation",
        "method": "HTTPS API",
        "meaning": "An estimated geolocation, ISP/org, and timezone.",
        "caveat": "A proprietary estimate. Free use is non-commercial and rate-limited.",
    },
    "geo-maxmind": {
        "name": "MaxMind GeoLite2 / GeoIP2 (local .mmdb file)",
        "url": "https://dev.maxmind.com/geoip/geolite2-free-geolocation-data",
        "method": "local database lookup (only with --mmdb and `pip install maxminddb`)",
        "meaning": "An estimated geolocation with an accuracy radius.",
        "caveat": "A proprietary estimate, only as fresh as your downloaded file.",
    },
    # --- Published lists ------------------------------------------------------
    "tor-exits": {
        "name": "Tor Project bulk exit list",
        "url": "https://check.torproject.org/torbulkexitlist",
        "method": "HTTPS download (cached 6h)",
        "meaning": "IPs currently operating as Tor exit relays. Authoritative and published by the "
                   "Tor Project.",
        "caveat": "Covers exits only, not relays or bridges. A recently retired exit drops off the list.",
    },
    "cloud-ranges": {
        "name": "Cloud/CDN provider self-published IP ranges",
        "url": "AWS ip-ranges.json, Google Cloud cloud.json, Oracle public_ip_ranges.json, "
               "DigitalOcean geo csv, Cloudflare ips-v4/v6, Fastly public-ip-list",
        "method": "HTTPS download (cached 24h)",
        "meaning": "The provider itself says this IP is part of its infrastructure. A consumer "
                   "browsing from it is almost always using a server, VPN, or proxy.",
        "caveat": "Covers only providers that publish lists. Azure, Hetzner, OVH and others are "
                  "not covered here; look for them in the ASN heuristics instead.",
    },
    "icloud-relay": {
        "name": "Apple iCloud Private Relay egress ranges",
        "url": "https://mask-api.icloud.com/egress-ip-ranges.csv",
        "method": "HTTPS download (cached 24h, ~10MB)",
        "meaning": "The IP is an Apple Private Relay egress. The user is a real Apple customer whose "
                   "true IP is hidden. Apple publishes the approximate region each range represents.",
        "caveat": "Proxy-like, but usually benign. Do not treat it the same as a VPN.",
    },
    # --- Derived --------------------------------------------------------------
    "heuristic": {
        "name": "ip-intel keyword heuristics",
        "url": "ipintel/heuristics.py in this repo",
        "method": "keyword matching on PTR hostname and AS/org names",
        "meaning": "A best guess at connection type (hosting, VPN, residential, mobile).",
        "caveat": "A guess, and the weakest evidence in the report. Corroborate it with "
                  "authoritative sources.",
    },
    "comparison": {
        "name": "ip-intel cross-source comparison",
        "url": "ipintel/compare.py in this repo",
        "method": "compares the facts above with each other and with --claimed-* inputs",
        "meaning": "Incongruities between sources, or between the IP and what the user claimed.",
        "caveat": "Only as reliable as the weakest input it compares.",
    },
}
